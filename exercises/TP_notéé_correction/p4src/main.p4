/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"


const bit<8> THRESHOLD = 25;

// Structure of the digest sent to the controller
struct digest_t {
    count_t value_in;
    count_t value_out;
    bit<16> port;
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    //Counter of incoming packets that contain the counter
    register<count_t>(64) count_in;
  
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},
	    num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

        //set the destination mac address that we got from the match in the table
        //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;
        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id: exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 1){            
            // TODO : Implement the Ingress logic:
            // - If the packet received contains a counter, send a digest to the controller
            //      containing both counter values (before resetting it)
            //      and forward packet as normal IPv4 packet
            // - If packet is tagged, increase counter value before 
            //      forwarding it as normal IPv4 packet 
            // - Otherwise, forward normally
            count_t current_count_in;
            count_in.read(current_count_in, (bit<32>)standard_metadata.ingress_port);
            current_count_in = current_count_in+1;

            if (hdr.cnt.isValid()) {
                digest_t d;
                d.value_in = current_count_in;
                d.value_out = hdr.cnt.value;
                d.port = (bit<16>)standard_metadata.ingress_port;
                digest<digest_t>(1, d);               
                hdr.cnt.setInvalid(); 
                hdr.ethernet.etherType = TYPE_IPV4;
                count_in.write((bit<32>)standard_metadata.ingress_port, 0);
            } else {
                if (hdr.ipv4.flags == TAG) {
                    count_in.write((bit<32>)standard_metadata.ingress_port, current_count_in);
                    hdr.ipv4.flags = 0;
                }
            }

            switch (ipv4_lpm.apply().action_run){
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    register<count_t>(64) count_out;
    count_t current_count_out = 0;
    bool count_packet = false;

    action check_if_count(bit<7> probability) {
        bit<7> random_value;
        random(random_value, 0, 100);
        count_packet = (random_value < probability);
    }

    table check_port {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            check_if_count;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    } 

    apply {
        // TODO : implement Egress Logic
        //  - Check if the packet will be sent to an host. If not, check_if_count 
        //      should contain whether the packet should be counted or not 
        //  -  If the packet should be counted, increase the counter accordingly 
        //      -  If THRESHOLD is reached, add a counter header with the local 
        //          count for the outgoing port and reset counter 
        //      - Else, Tag the packet to signel it must be counted
        switch (check_port.apply().action_run) {
            check_if_count : {
                if (count_packet) {
                    count_out.read(current_count_out, (bit<32>)standard_metadata.egress_port);
                    count_out.write((bit<32>)standard_metadata.egress_port, current_count_out + 1);
                    current_count_out = current_count_out + 1;

                    if (current_count_out >= THRESHOLD) {
                        hdr.cnt.setValid();
                        hdr.ethernet.etherType = TYPE_COUNTER;
                        hdr.cnt.value = current_count_out; // or threshold
                        count_out.write((bit<32>)standard_metadata.egress_port, 0);
                    }  else {
                        hdr.ipv4.flags = TAG;
                    }
                }
            }
        }    
    }

    
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;