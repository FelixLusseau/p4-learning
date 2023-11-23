from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw
import time
from cmd import Cmd
from threading import Thread

MAX_WEIGHT  = 10000
DEBUFF      = 10000

DIGEST_VALUE_IN_INDEX   = 0
DIGEST_VALUE_OUT_INDEX  = 1
DIGEST_PORT_INDEX       = 2


class Controller():
    #### BEGIN START FUNCTIONS ####

    # Create the structures for the Controller
    def __init__(self):
        self.topo = load_topo("topology.json")

        # Dctionnary that links edges to their relability (true or false)
        self.edge_2_reliability = {}
        self.edge_2_digest_count = {}

        # Edges start with a reliability set to "true"
        # Note : a link (u,v) is here seen as two edges (u,v) and (v,u) with seperate
        # reliability
        for u, v in self.topo.edges():
            edge_id = "{}-{}".format(u, v)
            self.edge_2_reliability[edge_id] = True
            self.edge_2_digest_count[edge_id] = 0
            edge_id = "{}-{}".format(v, u)
            self.edge_2_reliability[edge_id] = True
            self.edge_2_digest_count[edge_id] = 0


        # There is one subcontroller per switch, that is in charge of
        # actually modifying tables etc.
        # These subcontroller are orchestrated by the main Controller()
        self.subcontrollers = {}
        self.init()

    # Connect to the switches and initialize the tables
    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()
        self.update_path(first_call=True)
        for sw_name in self.subcontrollers.keys():
            print("Starting subcontroller of {}".format(sw_name))
            self.fill_check_port_table(sw_name)
            self.loop(sw_name)

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            print("Creating subcontroller for {}".format(p4switch))
            self.subcontrollers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def reset_states(self):
        for subcontroller in self.subcontrollers.values():
            subcontroller.reset_state()
            subcontroller.table_clear("ipv4_lpm")
            subcontroller.table_clear("ecmp_group_to_nhop")
            subcontroller.table_clear("check_port")

    def set_table_defaults(self):
        for subcontroller in self.subcontrollers.values():
            subcontroller.table_set_default("ipv4_lpm", "drop", [])
            subcontroller.table_set_default("ecmp_group_to_nhop", "drop", [])
            subcontroller.table_set_default("check_port", "NoAction", [])

    def fill_check_port_table(self, sw_name):
        subcontroller = self.subcontrollers[sw_name]
        for u, v in self.topo.edges(sw_name):
            v_node = self.topo.nodes[v]
            if v_node.get("isHost", False):
                continue
            port = str(self.topo.get_edge_data(u, v)["port1"])
            self.table_update(sw_name, "check_port", "check_if_count", [port], ["100"], force_add=True)

    #### END START FUNCTION ####

    #### BEGIN UTILS ####

    # Adds an entry to a table if it does not exist. Otherwise, modifies the existing entry
    # sw_name : Name of the switch onto which pushing the change
    # table_name : Name of the table to modify
    # action_name : Action to call if entry matches
    # key : Match key for the table entry
    # params : Parameters for the action
    def table_update(
        self, sw_name: str, table_name: str, action_name: str, key: list, params: list, force_add=False
    ):
        subcontroller = self.subcontrollers[sw_name]
        if force_add:
            subcontroller.table_add(table_name, action_name, key, params)
            return
        handle = subcontroller.get_handle_from_match(table_name, key)
        if handle is not None:
            subcontroller.table_modify(table_name, action_name, handle, params)
        else:
            subcontroller.table_add(table_name, action_name, key, params)

    # Get the edge id used to reference the edge in the edge2reliability dictionnary
    def get_edge_id(self, u, v):
        return "{}-{}".format(u, v)

    #### END UTILS ####

    #### BEGIN MANAGE DIGEST ####

    # Unpack the receive digest to extract the desired
    # information
    def unpack_digest(self, msg, num_samples):
        digests = []
        value1 = None
        value2 = None
        port = None
        starting_index = 32  # ignore header
        i=0
        for sample in range(num_samples):
            # get and convert first 8 bits/1byte (value1)
            print("Sample {} is {}".format(i,sample))
            value1 = struct.unpack(">c", msg[starting_index : starting_index + 1])
            #print("raw value in {}".format(value1))
            starting_index += 1  # move on to next byte
            value1 = int.from_bytes(value1[0], "big")

            # get and convert second 8 bits/1byte (value1)
            value2 = struct.unpack(">c", msg[starting_index : starting_index + 1])
            #print("raw value in {}".format(value2))
            starting_index += 1  # move on to next byte
            value2 = int.from_bytes(value2[0], "big")

            port = struct.unpack(">h", msg[starting_index : starting_index + 2])
            port = port[0]
            digests.append((value1, value2, port))

            starting_index += 2

        # return lists with separated digest types
        return digests

    # Recv a digest message and set the new reliability for the link
    def recv_msg_digest(self, msg, sw_name):
        _, _, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:32])
        digests = self.unpack_digest(msg, num)

        subcontroller = self.subcontrollers[sw_name]
        subcontroller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

        for digest in digests:
            value_in_d  = digest[DIGEST_VALUE_IN_INDEX]
            value_out_d = digest[DIGEST_VALUE_OUT_INDEX]
            port_d      = digest[DIGEST_PORT_INDEX]
            # print(
            #     "\033[2;31;43m[INFO_CTRL]\033[0;0m Received Digest on {} : {},{},{}".format(
            #         sw_name, value_in_d, value_out_d, port_d
            #     )
            # )
            print("\nSwitch {}, Port {} Compteur in : {}, compteur out : {} ".format(sw_name, port_d,value_in_d,value_out_d))
            

            reliability = value_in_d / value_out_d
            info = self.topo.get_intfs(fields=["port"])[sw_name]
            

            for neighbor, port in info.items():
                if port == port_d:
                    edge_id = self.get_edge_id(neighbor, sw_name)
                    other_edge_id = self.get_edge_id(sw_name, neighbor)
                    self.edge_2_reliability[edge_id] = (
                        reliability == 1
                    )
                    print(self.edge_2_digest_count[edge_id], edge_id)
                    self.edge_2_digest_count[edge_id] = self.edge_2_digest_count[edge_id] + 1
                    break


            full_link_reliability = (
                self.edge_2_reliability[edge_id] and self.edge_2_reliability[other_edge_id]
            )
            print("Full link reliability : {}".format(full_link_reliability))
            
            if not full_link_reliability :
                
                if self.topo[sw_name][neighbor]["weight"] < MAX_WEIGHT:
                    self.topo[sw_name][neighbor]["weight"] = self.topo[sw_name][neighbor]["weight"] + DEBUFF
                    
                    print(
                        "\033[2;31;43m[INFO_CTRL]\033[0;0m {}-{} is not reliable and must be debuffed : {}".format(
                            neighbor, sw_name, self.topo[sw_name][neighbor]["weight"]
                        )
                    )
                    self.update_path()
            # else : 
            #     print("\033[2;31;43m[INFO_CTRL]\033[0;0m {}-{} is reliable".format(sw_name,neighbor))

    # Waits to receive a digest message from the
    # switch called sw_name (e.g., from "s1")
    def run_digest_loop(self, sw_name):
        subcontroller = self.subcontrollers[sw_name]
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        sub.connect(subcontroller.client.bm_mgmt_get_info().notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, "")
        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg, sw_name)

    # Launch the run_digest_loop in a Process to prevent blocking
    def loop(self, sw_name):
        thread = Thread(
            target=self.run_digest_loop, args=(sw_name,)
        )
        thread.daemon = True
        thread.start()

    #### END MANAGE DIGEST ####

    #### BEGIN PATH COMPUTATION ####

    # Compute shortest path according to the "weight" attribute
    # and push the Next-Hop in the data-plane tables
    def update_path(self, first_call=False):
        switch_ecmp_groups = {
            sw_name: {} for sw_name in self.topo.get_p4switches().keys()
        }

        for sw_name, subcontroller in self.subcontrollers.items():
            for sw_dst in self.topo.get_p4switches():
                # if its ourselves we create direct connections
                if sw_name == sw_dst:
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.topo.get_host_ip(host) + "/32"
                        host_mac = self.topo.get_host_mac(host)

                        # add rule
                        self.table_update(
                            sw_name,
                            "ipv4_lpm",
                            "set_nhop",
                            [str(host_ip)],
                            [str(host_mac), str(sw_port)],force_add=first_call
                        )

                # check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        paths = self.topo.get_shortest_paths_between_nodes(
                            sw_name, sw_dst
                        )
                        for host in self.topo.get_hosts_connected_to(sw_dst):
                            if len(paths) == 1:
                                next_hop = paths[0][1]

                                host_ip = self.topo.get_host_ip(host) + "/24"
                                sw_port = self.topo.node_to_node_port_num(
                                    sw_name, next_hop
                                )
                                dst_sw_mac = self.topo.node_to_node_mac(
                                    next_hop, sw_name
                                )

                                # add rule
                                self.table_update(
                                    sw_name,
                                    "ipv4_lpm",
                                    "set_nhop",
                                    [str(host_ip)],
                                    [str(dst_sw_mac), str(sw_port)], force_add=first_call
                                )

                            elif len(paths) > 1:
                                next_hops = [x[1] for x in paths]
                                dst_macs_ports = [
                                    (
                                        self.topo.node_to_node_mac(next_hop, sw_name),
                                        self.topo.node_to_node_port_num(
                                            sw_name, next_hop
                                        ),
                                    )
                                    for next_hop in next_hops
                                ]
                                host_ip = self.topo.get_host_ip(host) + "/24"

                                # check if the ecmp group already exists. The ecmp group is defined by the number of next
                                # ports used, thus we can use dst_macs_ports as key
                                if switch_ecmp_groups[sw_name].get(
                                    tuple(dst_macs_ports), None
                                ):
                                    ecmp_group_id = switch_ecmp_groups[sw_name].get(
                                        tuple(dst_macs_ports), None
                                    )
                                    print("table_add at {}:".format(sw_name))
                                    self.table_update(
                                        sw_name,
                                        "ipv4_lpm",
                                        "ecmp_group",
                                        [str(host_ip)],
                                        [str(ecmp_group_id), str(len(dst_macs_ports))],force_add=first_call
                                    )

                                # new ecmp group for this switch
                                else:
                                    new_ecmp_group_id = (
                                        len(switch_ecmp_groups[sw_name]) + 1
                                    )
                                    switch_ecmp_groups[sw_name][
                                        tuple(dst_macs_ports)
                                    ] = new_ecmp_group_id

                                    # add group
                                    for i, (mac, port) in enumerate(dst_macs_ports):
                                        print("table_add at {}:".format(sw_name))
                                        self.table_update(
                                            sw_name,
                                            "ecmp_group_to_nhop",
                                            "set_nhop",
                                            [str(new_ecmp_group_id), str(i)],
                                            [str(mac), str(port)], force_add=first_call
                                        )

                                    # add forwarding rule
                                    self.table_update(
                                        sw_name,
                                        "ipv4_lpm",
                                        "ecmp_group",
                                        [str(host_ip)],
                                        [
                                            str(new_ecmp_group_id),
                                            str(len(dst_macs_ports))
                                        ],force_add=first_call
                                    )

    #### END PATH COMPUTATION ####



class NorthboundAPI(Cmd):
    intro = "Welcome to the NBI. Type help or ? to list commands.\n"
    prompt = "NBI > "
    

    def do_exit(self, inp):
        "Stop the controller : exit"
        print("\033[2;31;43m[INFO_NBI]\033[0;0m Exiting")
        exit(0)

    # For all links, show if they seem reliable based on counter
    # (either true or false)
    def do_show_links_state(self, inp):
        "Display reliability and weight of switch to switch links : show_links_state"
        output = ""
        for u, v in controller.topo.edges():
            v_node = controller.topo.nodes[v]
            u_node = controller.topo.nodes[u]
            # Skipping host link since they are not monitored
            if v_node.get("isHost", False) or u_node.get("isHost", False):
                continue

            uv_id = controller.get_edge_id(u, v)
            vu_id = controller.get_edge_id(v, u)
            # checking if link can be used (ie both directions are reliable)
            reliability = (controller.edge_2_reliability[uv_id]) and (
                controller.edge_2_reliability[vu_id]
            )
            output += "\033[2;31;43m[INFO_NBI]\033[0;0m {} <-> {} : Reliability : {} / Weight : {} / Digest Count : {} ({}->{}) + {} ({}->{})\n".format(u, v, reliability, controller.topo[u][v]["weight"], controller.edge_2_digest_count[uv_id], u, v, controller.edge_2_digest_count[vu_id], v, u)
        print(output)

    # indicate that a link has been repaired, e.g.,
    # > repair s1-s2
    def do_repair(self, inp):
        "State that a link was repaired and is reliable again : repair s1-s2\nIts weight is brought back down to its original value"
        try:
            u, v = inp.split("-")
            weight = controller.topo[u][v]["weight"]
        except Exception as e: 
            print("\033[2;31;43m[INFO_NBI]\033[0;0m Error. Syntax : > repair s1-s2")


        if weight > MAX_WEIGHT:
            controller.topo[u][v]["weight"] -= DEBUFF
            controller.update_path()
            print(
                "\033[2;31;43m[INFO_NBI]\033[0;0m {}-{} is considering reliable again : {}".format(
                    u, v, controller.topo[u][v]["weight"]
                )
            )

    def do_change_weight(self, inp):
        "Change the weight of a link : change_weight u-v 100"
        try:
            uv, weight = inp.split()
            u, v = uv.split("-")
            controller.topo[u][v]["weight"] = int(weight)
        except Exception as e: 
            print("\033[2;31;43m[INFO_NBI]\033[0;0m Error. Syntax : change_weight s1-s2 100")

    def do_update_paths(self, inp):
        "Update the path according to the current weights : update_path"
        controller.update_path()


controller = Controller()
NorthboundAPI().cmdloop()
