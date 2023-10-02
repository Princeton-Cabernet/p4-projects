#include <core.p4>
#include <tna.p4>

#define NUM_BANNED_DST_IP 100
#define NUM_ALLOWABLE_DST_IP 100
#define NUM_KNOWN_DOMAINS 2048
#define NUM_KNOWN_DOMAINS_BITS 10
#define TABLE_SIZE 65536
#define TIMEOUT 100000000 // 100 seconds

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<32> known_domain_id;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType; 
}
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    IPv4Address src;
    IPv4Address dst; 
}
header ipv6_h {
    bit<4> version;
    bit<8> tc;
    bit<20> fl;
    bit<16> plen;
    bit<8> nh;
    bit<8> hl;
    IPv6Address src;
    IPv6Address dst; 
}
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}

header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

header dns_q_label {
    bit<8> label;
}

header dns_q_part_1 {
    bit<8> part;
}

header dns_q_part_2 {
    bit<16> part;
}

header dns_q_part_4 {
    bit<32> part;
}

struct dns_qtype_class {
    bit<16> type;
    bit<16> class;
}

header dns_query_tc{
    dns_qtype_class tc_query;
}

header dns_a {
    bit<16> qname_pointer;
    dns_qtype_class tc_ans;
    bit<32> ttl;
    bit<8> rd_length_1;
    bit<8> rd_length_2;
}

header dns_a_ip {
    bit<32> rdata; //IPV4 is always 32 bit.
}

header resubmit_data_t {
    bit<1> stage_indicator; // 0 or 1 for stage 1 or 2 in the sip/cip table
    bit<7> _padding0;
    bit<8> _padding1;
    bit<16> _padding2;
    bit<32> _padding3;
}

header resubmit_data_skimmed_t {
    bit<1> stage_indicator; // 0 or 1 for stage 1 or 2 in the sip/cip table
}

header report_h {
    IPv4Address client_ip;
    bit<16> server_port;
    bit<32> domain_id;
}

// List of all recognized headers
struct Parsed_packet { 
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    tcp_h tcp;
    dns_h dns_header;

    dns_q_label label1;
    dns_q_part_1 q1_part1;
    dns_q_part_2 q1_part2;
    dns_q_part_4 q1_part4;
    dns_q_part_4 q1_part8_1;
    dns_q_part_4 q1_part8_2;

    dns_q_label label2;
    dns_q_part_1 q2_part1;
    dns_q_part_2 q2_part2;
    dns_q_part_4 q2_part4;
    dns_q_part_4 q2_part8_1;
    dns_q_part_4 q2_part8_2;

    dns_q_label label3;
    dns_q_part_1 q3_part1;
    dns_q_part_2 q3_part2;
    dns_q_part_4 q3_part4;
    dns_q_part_4 q3_part8_1;
    dns_q_part_4 q3_part8_2;

    dns_q_label label4;
    dns_q_part_1 q4_part1;
    dns_q_part_2 q4_part2;
    dns_q_part_4 q4_part4;
    dns_q_part_4 q4_part8_1;
    dns_q_part_4 q4_part8_2;

    dns_q_label label5;

    dns_query_tc query_tc;

    dns_a dns_answer;
    dns_a_ip dns_ip;

    report_h report;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct ig_metadata_t {
    resubmit_data_t resubmit_data_read;
    resubmit_data_skimmed_t resubmit_data_write;

    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
    bit<1> is_tcp;
    bit<1> is_udp;
    bit<3>  unused;

    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
    bit<1> matched_domain;
    bit<32> domain_id_dns;
    bit<32> domain_id;
    bit<32> index_1_dns;
    bit<32> index_2_dns;
    bit<32> index_1;
    bit<32> index_2;
    bit<48> temp_timestamp;
    bit<32> temp_cip;
    bit<32> temp_sip;
    bit<1> already_matched;
    bit<64> min_counter;
    bit<2> min_table;
    bit<64> temp_packet_counter;
    bit<64> temp_byte_counter;

    bit<64> temp_total_dns;
    bit<64> temp_total_missed;
    bit<1> parsed_answer;
}

struct sip_cip_t { 
    bit<32> sip;
    bit<32> cip;
}

//struct domainid_timestamp_t { 
//    bit<32> domain_id;
//    bit<32> timestamp;
//}
//
struct domainid_t { 
    bit<32> domain_id;
}
struct timestamp_t { 
    bit<32> timestamp;
}




struct eg_metadata_t {
    bit<16> pkt_length_wo_fcs;
    bit<32> bit_marker;
    bit<1> matched_rule;
}

parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        //pkt.advance(64);
        pkt.extract(ig_md.resubmit_data_read);
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition accept;
    }
}

// parsers
parser SwitchIngressParser(packet_in pkt,
           out Parsed_packet p,
           out ig_metadata_t ig_md,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    ParserCounter() counter;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
        ig_md.do_dns = 0;
        ig_md.recur_desired = 0;
        ig_md.response_set = 0;
		ig_md.is_dns = 0;
		ig_md.is_tcp = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

        ig_md.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
            6: parse_tcp;
			default: accept;
		}
	}

    state parse_tcp {
        pkt.extract(p.tcp);
        ig_md.is_tcp = 1;
        transition accept;
    }

    state parse_udp {
        pkt.extract(p.udp);
        ig_md.is_udp = 1;

		transition select(p.udp.dport) {
			53: parse_dns_header;
			default: parse_udp_2;
		}
	}

	state parse_udp_2 {

		transition select(p.udp.sport) {
			53: parse_dns_header;
			default: accept;
        }
    }

	state parse_dns_header {
        pkt.extract(p.dns_header);
		ig_md.is_dns = 1;

        ig_md.last_label = 0;


		transition select(p.dns_header.is_response) {
			1: parse_dns_query1;
			default: accept;
		}
	}

    // Parsel DNS Query Label 1
    state parse_dns_query1 {
        pkt.extract(p.label1);
        ig_md.last_label = 1;

        transition select(p.label1.label) {
            0: parse_query_tc;
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            8: parse_dns_q1_len8;
            9: parse_dns_q1_len9;
            10: parse_dns_q1_len10;
            11: parse_dns_q1_len11;
            12: parse_dns_q1_len12;
            13: parse_dns_q1_len13;
            14: parse_dns_q1_len14;
            15: parse_dns_q1_len15;
            default: accept;
        }
    }

    state parse_dns_q1_len1 {
        pkt.extract(p.q1_part1);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len2 {
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len3 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len4 {
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len5 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len6 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len8 {
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len9 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len10 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len11 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len12 {
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len13 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len14 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len15 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    // Parsel DNS Query Label 2
    state parse_dns_query2 {
        pkt.extract(p.label2);
        ig_md.last_label = 2;

        transition select(p.label2.label) {
            0: parse_query_tc;
            1: parse_dns_q2_len1;
            2: parse_dns_q2_len2;
            3: parse_dns_q2_len3;
            4: parse_dns_q2_len4;
            5: parse_dns_q2_len5;
            6: parse_dns_q2_len6;
            7: parse_dns_q2_len7;
            8: parse_dns_q2_len8;
            9: parse_dns_q2_len9;
            10: parse_dns_q2_len10;
            11: parse_dns_q2_len11;
            12: parse_dns_q2_len12;
            13: parse_dns_q2_len13;
            14: parse_dns_q2_len14;
            15: parse_dns_q2_len15;
            default: accept;
        }
    }

    state parse_dns_q2_len1 {
        pkt.extract(p.q2_part1);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len2 {
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len3 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len4 {
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len5 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len6 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len7 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len8 {
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len9 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len10 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len11 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len12 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len13 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len14 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len15 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    
    // Parsel DNS Query Label 3
    state parse_dns_query3 {
        pkt.extract(p.label3);
        ig_md.last_label = 3;

        transition select(p.label3.label) {
            0: parse_query_tc;
            1: parse_dns_q3_len1;
            2: parse_dns_q3_len2;
            3: parse_dns_q3_len3;
            4: parse_dns_q3_len4;
            5: parse_dns_q3_len5;
            6: parse_dns_q3_len6;
            7: parse_dns_q3_len7;
            8: parse_dns_q3_len8;
            9: parse_dns_q3_len9;
            10: parse_dns_q3_len10;
            11: parse_dns_q3_len11;
            12: parse_dns_q3_len12;
            13: parse_dns_q3_len13;
            14: parse_dns_q3_len14;
            15: parse_dns_q3_len15;
            default: accept;
        }
    }

    state parse_dns_q3_len1 {
        pkt.extract(p.q3_part1);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len2 {
        pkt.extract(p.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len3 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len4 {
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len5 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len6 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len7 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len8 {
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len9 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len10 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len11 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len12 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len13 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len14 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len15 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    
    // Parsel DNS Query Label 4
    state parse_dns_query4 {
        pkt.extract(p.label4);
        ig_md.last_label = 4;

        transition select(p.label4.label) {
            0: parse_query_tc;
            1: parse_dns_q4_len1;
            2: parse_dns_q4_len2;
            3: parse_dns_q4_len3;
            4: parse_dns_q4_len4;
            5: parse_dns_q4_len5;
            6: parse_dns_q4_len6;
            7: parse_dns_q4_len7;
            8: parse_dns_q4_len8;
            9: parse_dns_q4_len9;
            10: parse_dns_q4_len10;
            11: parse_dns_q4_len11;
            12: parse_dns_q4_len12;
            13: parse_dns_q4_len13;
            14: parse_dns_q4_len14;
            15: parse_dns_q4_len15;
            default: accept;
        }
    }

    state parse_dns_q4_len1 {
        pkt.extract(p.q4_part1);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len2 {
        pkt.extract(p.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len3 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len4 {
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len5 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len6 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len7 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len8 {
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len9 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len10 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len11 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len12 {
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len13 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len14 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len15 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }


    // Parsel DNS Query Label 5
    state parse_dns_query5 {
        pkt.extract(p.label5);
        ig_md.last_label = 5;

        transition select(p.label5.label) {
            0: parse_query_tc;
            default: accept;
        }
    }

    state parse_query_tc {
        pkt.extract(p.query_tc);
        ig_md.parsed_answer = 0;
        transition parse_dns_answer;
    }

    state parse_dns_answer {
        pkt.extract(p.dns_answer);

        transition select(p.dns_answer.tc_ans.type) {
            1: parse_a_ip;
            5: parse_cname_arbiter;
            default: accept;
        }
    }

    state parse_cname {
        counter.set(p.dns_answer.rd_length_2);
        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    // Parse normally up to CNAME length: 50 bytes
    // For 51 or more, parse with parse_cname_over50
    state parse_cname_arbiter {
        transition select(p.dns_answer.rd_length_2) {
            1: parse_cname;
            2: parse_cname; 
            3: parse_cname;
            4: parse_cname;
            5: parse_cname;
            6: parse_cname;
            7: parse_cname;
            8: parse_cname;
            9: parse_cname;
            10: parse_cname;
            11: parse_cname;
            12: parse_cname;
            13: parse_cname;
            14: parse_cname;
            15: parse_cname;
            16: parse_cname;
            17: parse_cname;
            18: parse_cname;
            19: parse_cname;
            20: parse_cname;
            21: parse_cname;
            22: parse_cname;
            23: parse_cname;
            24: parse_cname;
            25: parse_cname;
            26: parse_cname;
            27: parse_cname;
            28: parse_cname;
            29: parse_cname;
            30: parse_cname;
            31: parse_cname;
            32: parse_cname;
            33: parse_cname;
            34: parse_cname;
            35: parse_cname;
            36: parse_cname;
            37: parse_cname;
            38: parse_cname;
            39: parse_cname;
            40: parse_cname;
            41: parse_cname;
            42: parse_cname;
            43: parse_cname;
            44: parse_cname;
            45: parse_cname;
            46: parse_cname;
            47: parse_cname;
            48: parse_cname;
            49: parse_cname;
            50: parse_cname;
            default: parse_cname_over50;
        }
    }

    // A state just for hopping to parse_cname_cut50
    // Might not even need, but whatever.
    state parse_cname_over50 {
        counter.set(p.dns_answer.rd_length_2);

        transition parse_cname_cut50;
    }

    // Advance 50 bytes (400 bits) and decrement 50 from ParserCounter.
    // After that, perform same parsing procedure as parse_cname
    state parse_cname_cut50 {
        pkt.advance(400);
        counter.decrement(8w50);

        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    state parse_cname_byte{
        pkt.advance(8);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    state parse_a_ip {
        pkt.extract(p.dns_ip);
        ig_md.parsed_answer = 1;

        transition accept;
    }
}
/**************************END OF PARSER**************************/

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout Parsed_packet hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
         
    Resubmit() resubmit;
    
    apply {        

        if (ig_intr_dprsr_md.resubmit_type == 1) {
            resubmit.emit(ig_md.resubmit_data_write);
            //resubmit.emit();
        }
 

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
//        pkt.emit(hdr.tcp);
        pkt.emit(hdr.report);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out Parsed_packet p,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout Parsed_packet hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}

// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(inout Parsed_packet headers,
                inout ig_metadata_t ig_md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    // PRECISION STYLE TABLES

    Register<sip_cip_t,_>(TABLE_SIZE) sip_cip_reg_1; 
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_1) sip_cip_reg_1_check_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            if (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<sip_cip_t,_,void> (sip_cip_reg_1) sip_cip_reg_1_update_action = {
        void apply(inout sip_cip_t value) {
            value.sip = headers.dns_ip.rdata;
            value.cip = headers.ipv4.dst;
        }
    };


    Register<domainid_t,_>(TABLE_SIZE) domain_reg_1;
    RegisterAction<domainid_t,_,bit<32>> (domain_reg_1) domain_reg_1_get_domain_action = {
        void apply(inout domainid_t value, out bit<32> domain_id) {
            domain_id = value.domain_id;
        }
    };
    RegisterAction<domainid_t,_,void> (domain_reg_1) domain_reg_1_update_domain_action = {
        void apply(inout domainid_t value) {
            value.domain_id = ig_md.domain_id_dns;
        }
    };

    Register<timestamp_t,_>(TABLE_SIZE) tstamp_reg_1;
    RegisterAction<timestamp_t,_,bit<1>> (tstamp_reg_1) tstamp_reg_1_check_tstamp_action = {
        void apply(inout timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<timestamp_t,_,void> (tstamp_reg_1) tstamp_reg_1_update_tstamp_action = {
        void apply(inout timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
        }
    };
    RegisterAction<timestamp_t,_,void> (tstamp_reg_1) tstamp_reg_1_void_tstamp_action = {
        void apply(inout timestamp_t value) {
            value.timestamp = 32w0;
        }
    };


    // Register 2
    Register<sip_cip_t,_>(TABLE_SIZE) sip_cip_reg_2; 
    RegisterAction<sip_cip_t,_,bit<1>> (sip_cip_reg_2) sip_cip_reg_2_check_action = {
        void apply(inout sip_cip_t value, out bit<1> is_match) {
            if (value.sip == headers.dns_ip.rdata && value.cip == headers.ipv4.dst) {
                is_match = 1;
            }
            else {
                is_match = 0;
            }
        }
    };
    RegisterAction<sip_cip_t,_,void> (sip_cip_reg_2) sip_cip_reg_2_update_action = {
        void apply(inout sip_cip_t value) {
            value.sip = headers.dns_ip.rdata;
            value.cip = headers.ipv4.dst;
        }
    };

    Register<domainid_t,_>(TABLE_SIZE) domain_reg_2;
    RegisterAction<domainid_t,_,bit<32>> (domain_reg_2) domain_reg_2_get_domain_action = {
        void apply(inout domainid_t value, out bit<32> domain_id) {
            domain_id = value.domain_id;
        }
    };
    RegisterAction<domainid_t,_,void> (domain_reg_2) domain_reg_2_update_domain_action = {
        void apply(inout domainid_t value) {
            value.domain_id = ig_md.domain_id_dns;
        }
    };

    Register<timestamp_t,_>(TABLE_SIZE) tstamp_reg_2;
    RegisterAction<timestamp_t,_,bit<1>> (tstamp_reg_2) tstamp_reg_2_check_tstamp_action = {
        void apply(inout timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<timestamp_t,_,void> (tstamp_reg_2) tstamp_reg_2_update_tstamp_action = {
        void apply(inout timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
        }
    };
    RegisterAction<timestamp_t,_,void> (tstamp_reg_2) tstamp_reg_2_void_tstamp_action = {
        void apply(inout timestamp_t value) {
            value.timestamp = 32w0;
        }
    };



/*
    Register<domainid_timestamp_t,_>(TABLE_SIZE) domain_tstamp_reg_2;
    RegisterAction<domainid_timestamp_t,_,bit<1>> (domain_tstamp_reg_2) domain_tstamp_reg_2_check_tstamp_action = {
        void apply(inout domainid_timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)ig_intr_prsr_md.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<domainid_timestamp_t,_,bit<32>> (domain_tstamp_reg_2) domain_tstamp_reg_2_get_domain_and_update_ts_action = {
        void apply(inout domainid_timestamp_t value, out bit<32> domain_id) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            domain_id = value.domain_id;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_2) domain_tstamp_reg_2_update_tstamp_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
        }
    };
    RegisterAction<domainid_timestamp_t,_,void> (domain_tstamp_reg_2) domain_tstamp_reg_2_update_tstamp_domain_action = {
        void apply(inout domainid_timestamp_t value) {
            value.timestamp = (bit<32>)ig_intr_prsr_md.global_tstamp;
            value.domain_id = ig_md.domain_id_dns;
        }
    };
*/
 
    // REGISTER ARRAY FOR KEEPING TRACK OF OVERFLOW DNS RESPONSES
    Register<bit<32>,_>(NUM_KNOWN_DOMAINS) dns_total_queried;
    RegisterAction<bit<32>,_, void> (dns_total_queried) dns_total_queried_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };
 
    Register<bit<32>,_>(NUM_KNOWN_DOMAINS) dns_total_missed;
    RegisterAction<bit<32>,_, void> (dns_total_missed) dns_total_missed_reg_inc_action = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };

    // Define Hash
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1_dns;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_2_dns;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_2;

    action match_domain(known_domain_id id) {
        ig_md.domain_id_dns = id;
        ig_md.matched_domain = 1;
    }

    table known_domain_list {
        key = {

            headers.q1_part1.isValid(): ternary;
            headers.q1_part1.part: ternary;
            headers.q1_part2.isValid(): ternary;
            headers.q1_part2.part: ternary;
            headers.q1_part4.isValid(): ternary;
            headers.q1_part4.part: ternary;
            headers.q1_part8_1.isValid(): ternary;
            headers.q1_part8_1.part: ternary;
            headers.q1_part8_2.isValid(): ternary;
            headers.q1_part8_2.part: ternary;

            headers.q2_part1.isValid(): ternary;
            headers.q2_part1.part: ternary;
            headers.q2_part2.isValid(): ternary;
            headers.q2_part2.part: ternary;
            headers.q2_part4.isValid(): ternary;
            headers.q2_part4.part: ternary;
            headers.q2_part8_1.isValid(): ternary;
            headers.q2_part8_1.part: ternary;
            headers.q2_part8_2.isValid(): ternary;
            headers.q2_part8_2.part: ternary;

            headers.q3_part1.isValid(): ternary;
            headers.q3_part1.part: ternary;
            headers.q3_part2.isValid(): ternary;
            headers.q3_part2.part: ternary;
            headers.q3_part4.isValid(): ternary;
            headers.q3_part4.part: ternary;
            headers.q3_part8_1.isValid(): ternary;
            headers.q3_part8_1.part: ternary;
            headers.q3_part8_2.isValid(): ternary;
            headers.q3_part8_2.part: ternary;


            headers.q4_part1.isValid(): ternary;
            headers.q4_part1.part: ternary;
            headers.q4_part2.isValid(): ternary;
            headers.q4_part2.part: ternary;
            headers.q4_part4.isValid(): ternary;
            headers.q4_part4.part: ternary;
            headers.q4_part8_1.isValid(): ternary;
            headers.q4_part8_1.part: ternary;
            headers.q4_part8_2.isValid(): ternary;
            headers.q4_part8_2.part: ternary;
        }

        actions = {
            match_domain;
            NoAction;
        }

        /*const entries = {
            // Matches key: "login.live.com" in domain name in DNS response A record.
            
             *
             *
             *
             *
             true, false, true, false, false,
             //true, true, true, true, true,
             //true, true, true, true, true,
             //true, true, true, true, true,
             false, false, true, false, false,
             true, true, false, false, false,
             false, false, false, false, false,
             0x6c, 0x0, 0x6f_67_69_6e, 0x0, 0x0,
             _,_,0x6C_69_76_65,_,_,
             0x63,0x6F_6D,_,_,_,
             _,_,_,_,_
            ) : match_domain(1);
            
            
            (
             true, 0x6c, false, _, true, 0x6f_67_69_6e, false, _, false, _,
             false, _, false, _, true, 0x6C_69_76_65, false, _, false, _,
             true, 0x63, true, 0x6F_6D, false, _, false, _, false, _,
             false , _, false, _, false, _, false,_, false,_
            ) : match_domain(1);
 
        }*/

        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    action match_banned_dns_dst() {
        ig_md.matched_domain = 0;
    }

    // Incorporate both banned and allowable dns in this single table
    table banned_dns_dst {
        key = {
            headers.ipv4.dst: lpm;
        }

        actions = {
            match_banned_dns_dst;
            NoAction;
        }
        size = NUM_BANNED_DST_IP;
        default_action = NoAction();
    }

    apply {

        if(ig_md.parsed_answer == 1) {
            ig_md.domain_id_dns = 0;
            ig_md.matched_domain = 0;

            known_domain_list.apply();
            banned_dns_dst.apply();

            if (ig_md.matched_domain == 1) {
                
                ig_md.index_1_dns = (bit<32>) hash_1_dns.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w134140211);
                ig_md.index_2_dns = (bit<32>) hash_2_dns.get(headers.dns_ip.rdata + headers.ipv4.dst + 32w187182238);

                ig_md.already_matched = 0;

                bool is_resubmitted=(bool) ig_intr_md.resubmit_flag;
                bool resubmit_stage = (bool) ig_md.resubmit_data_read.stage_indicator;

                if (!is_resubmitted) {
                    // Increment total DNS queries for this domain name
                    dns_total_queried_reg_inc_action.execute(ig_md.domain_id_dns);

                    // access table 1
                    // Read sip_cip table
                    bit<1> is_match_1 = 0;

                    is_match_1 = sip_cip_reg_1_check_action.execute(ig_md.index_1_dns);
                    
                    // If sip and cip matches, just update timestamp
                    if (is_match_1 == 1) {
                        tstamp_reg_1_update_tstamp_action.execute(ig_md.index_1_dns);
                        ig_md.already_matched = 1;
                    }
                    else { 
                        // Check timestamp
                        bit<1> timed_out = 0;

                        timed_out = tstamp_reg_1_check_tstamp_action.execute(ig_md.index_1_dns);

                        // If entry timed out, replace entry. For this, resubmit packet.
                        if (timed_out == 1) {
                            // Set resubmit
                            ig_intr_dprsr_md.resubmit_type = 1;
                            ig_md.resubmit_data_write.stage_indicator = 0;
                            ig_md.already_matched = 1;
                        }

                        // Else, we have a collision that we cannot replace reg_1. 
                        // Continue to reg_2.
                    }
                    if (ig_md.already_matched == 0) {
                        // access table 2
                        // Read sip_cip table
                        bit<1> is_match_2 = 0;

                        is_match_2 = sip_cip_reg_2_check_action.execute(ig_md.index_2_dns);

                        // If sip and cip matches, just update timestamp
                        if (is_match_2 == 1) {
                            tstamp_reg_2_update_tstamp_action.execute(ig_md.index_2_dns);
                            ig_md.already_matched = 1;
                        }
                        else { 
                            // Check timestamp
                            bit<1> timed_out = 0;

                            timed_out = tstamp_reg_2_check_tstamp_action.execute(ig_md.index_2_dns);

                            // If entry timed out, replace entry. For this, resubmit packet.
                            if (timed_out == 1) {
                                // Set resubmit
                                ig_intr_dprsr_md.resubmit_type = 1;
                                ig_md.resubmit_data_write.stage_indicator = 1;
                                ig_md.already_matched = 1;
                            }
                            else {
                                // Increment total DNS queries missed for this domain name
                                dns_total_missed_reg_inc_action.execute(ig_md.domain_id_dns);
                            }
                        }
                    }
                }
                // Resubmitted packet. That means this is for updating entry in reg_1.
                else if (!resubmit_stage) {
                    sip_cip_reg_1_update_action.execute(ig_md.index_1_dns);
                    domain_reg_1_update_domain_action.execute(ig_md.index_1_dns);
                    tstamp_reg_1_update_tstamp_action.execute(ig_md.index_1_dns);
                    
                }
                // Resubmitted packet. That means this is for updating entry in reg_2.
                else {
                    sip_cip_reg_2_update_action.execute(ig_md.index_2_dns);
                    domain_reg_2_update_domain_action.execute(ig_md.index_2_dns);
                    tstamp_reg_2_update_tstamp_action.execute(ig_md.index_2_dns);
                    
                }
            }
        }
        // HANDLE TCP SYN-ACK packets
        else if ((ig_md.is_tcp == 1 && headers.tcp.flags == 18) || ig_md.is_udp == 1) {
            bit<32> index_1 = (bit<32>) hash_1.get(headers.ipv4.src + headers.ipv4.dst + 32w134140211);

            bit<1> sip_cip_matched = 0;
            bit<1> entry_matched = 0;
            bit<32> domain_id = 0;

            headers.dns_ip.rdata = headers.ipv4.src;

            // register_1
            sip_cip_matched = sip_cip_reg_1_check_action.execute(index_1);
            
            if (sip_cip_matched == 1) {
                    // Get domain_id and udpate timestamp
                    //domain_id = domain_tstamp_reg_1_get_domain_and_update_ts_action.execute(index_1);
                headers.report.setValid();
                headers.report.client_ip = headers.ipv4.dst;
                if (ig_md.is_tcp == 1) {
                    headers.report.server_port = headers.tcp.sport;
                }
                else {
                    headers.report.server_port = headers.udp.sport;
                }
                headers.report.domain_id = domain_reg_1_get_domain_action.execute(index_1);
                tstamp_reg_1_void_tstamp_action.execute(index_1);
                
                // Update packet_count, update byte_count
                entry_matched = 1;
                //ig_intr_tm_md.ucast_egress_port=156;
            }

            bit<32> index_2 = (bit<32>) hash_2.get(headers.ipv4.src + headers.ipv4.dst + 32w187182238);
            // register_2
            if (entry_matched == 0) {
                sip_cip_matched = sip_cip_reg_2_check_action.execute(index_2);
                
                if (sip_cip_matched == 1) {
                        // Get domain_id and udpate timestamp
                    headers.report.setValid();
                    headers.report.client_ip = headers.ipv4.dst;
                    if (ig_md.is_tcp == 1) {
                        headers.report.server_port = headers.tcp.sport;
                    }
                    else {
                        headers.report.server_port = headers.udp.sport;
                    }
                    headers.report.domain_id = domain_reg_2_get_domain_action.execute(index_2);
                    tstamp_reg_2_void_tstamp_action.execute(index_2);

                    // Update packet_count, update byte_count
                    entry_matched = 1;
                    //ig_intr_tm_md.ucast_egress_port=164;
                }              
            }
            //ig_intr_tm_md.ucast_egress_port=180;
            //ig_intr_tm_md.ucast_egress_port=156;
            if (entry_matched==1) {
                //headers.report.setValid();
                //headers.report.domain_id = 1;
                //headers.ethernet.etherType = 0x9000;
                //headers.tcp.dport = 65535;
                //headers.ipv4.dst = 16843009;
                ig_intr_tm_md.ucast_egress_port=156;
            }

            /*
            if (entry_matched == 1) {
                packet_counts_table_reg_inc_action.execute(domain_id);
                byte_counts_table_reg_inc_action.execute(domain_id);
            }
            */
            //headers.ipv4.src = (bit<32>)entry_matched;
            //headers.ipv4.dst = domain_id;
        }
	}
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout Parsed_packet hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;
