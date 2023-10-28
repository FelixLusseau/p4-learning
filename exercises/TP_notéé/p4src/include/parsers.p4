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
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_COUNTER: parse_counter;
            default: accept;
        }
    }

    state parse_counter {
        packet.extract(hdr.cnt);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        // TODO1 : Add the headers into the packet
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cnt);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}