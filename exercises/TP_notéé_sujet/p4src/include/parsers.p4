/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

// The parser must be able to parse a ethernet header, 
// and then either an IPv4 one or a cnt one (and then the IP one), depending 
// On the EtherType. The upper levels are unused and do not require parsing.


parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    //TODO1 : Parse either the IPv4 header or the counter header
    state parse_ethernet {
        packet.extract(hdr.ethernet);
       
    }

    state parse_counter {
    }

    state parse_ipv4 {
    }

    state parse_tcp {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        // TODO1 : Add the headers into the packet
    }
}