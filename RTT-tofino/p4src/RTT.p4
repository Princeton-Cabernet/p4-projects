/*
    RTT measurement based on TCP SEQ/ACK number
    Copyright (C) 2019 Xiaoqi Chen, Princeton University
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <core.p4>
#include <tna.p4>


//== Constants

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

typedef bit<8> tcp_flags_t;
const tcp_flags_t TCP_FLAGS_F = 1;
const tcp_flags_t TCP_FLAGS_S = 2;
const tcp_flags_t TCP_FLAGS_R = 4;
const tcp_flags_t TCP_FLAGS_P = 8;
const tcp_flags_t TCP_FLAGS_A = 16;


//== Headers

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header report_h {
    //measurement report, including IP+UDP header
    //IP
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    //UDP
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
    //Payload
    bit<32> payload_1;
    bit<32> payload_2;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    report_h report;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

#define PKT_TYPE_SEQ true
#define PKT_TYPE_ACK false

struct ig_metadata_t {
    bool pkt_type;
    
    bit<32> tmp_1;
    bit<32> tmp_2;
    bit<32> tmp_3;
    bit<32> total_hdr_len_bytes; 
    bit<32> total_body_len_bytes; 
    
    bit<32> expected_ack;
    bit<32> pkt_signature;
    
    bit<16> hashed_location_1;
    bit<16> hashed_location_2;
    
    bit<32> table_1_read;
}
struct eg_metadata_t {
}

//== Parsers and Deparsers

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
        pkt.advance(64); 
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition accept;
    }
}
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            0x0000: parse_report;//shadow state
            default : reject;
        }
    }
    
    state parse_report {
        pkt.extract(hdr.report);
        transition parse_ipv4;
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            default : accept;
        }
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
         
    // Checksum is not computed yet.
    
    apply {        
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.report);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}


//== Pipeline logic

control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
         
        action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
        }
        action nop() {
        }
       
        action route_to_64(){
            //route to CPU NIC. on tofino model, it is veth250
            ig_intr_tm_md.ucast_egress_port=64;
        }
        
        action mark_SEQ(){
            ig_md.pkt_type=PKT_TYPE_SEQ;
        }
        action mark_ACK(){
            ig_md.pkt_type=PKT_TYPE_ACK;
        }
        action drop_and_exit(){
            drop();exit;
        }
        
        // Decide packet is a data packet or an ACK
        
        table tb_decide_packet_type {
            key = {
                hdr.tcp.flags: ternary;
                hdr.ipv4.total_len: range;
                //hdr.ipv4.dst_addr: lpm; //use IP address to decide inside/outside
            }
            actions = {
                mark_SEQ;
                mark_ACK;
                drop_and_exit;
            }
            default_action = mark_SEQ();
            size = 512;
            const entries = {
                (TCP_FLAGS_S,_): mark_SEQ();
                (TCP_FLAGS_S+TCP_FLAGS_A,_): mark_ACK();
                (TCP_FLAGS_A, 0..80 ): mark_ACK();
                (TCP_FLAGS_A+TCP_FLAGS_P, 0..80 ): mark_ACK();
                (_,80..1600): mark_SEQ();
                (TCP_FLAGS_R,_): drop_and_exit();
                (TCP_FLAGS_F,_): drop_and_exit();
            }
        }
        
        // Calculate the expected ACK number for a data packet.
        // Formula: expected ACK=SEQ+(ipv4.total_len - 4*ipv4.ihl - 4*tcp.data_offset)
        // For SYN/SYNACK packets, add 1 to e_ack
        
        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;
        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_2;
        action compute_eack_1_(){
            ig_md.tmp_1=copy32_1.get({26w0 ++ hdr.ipv4.ihl ++ 2w0});
        }
        action compute_eack_2_(){
            ig_md.tmp_2=copy32_2.get({26w0 ++ hdr.tcp.data_offset ++ 2w0});
        }
        action compute_eack_3_(){
            ig_md.tmp_3=16w0 ++ hdr.ipv4.total_len;
        }
        action compute_eack_4_(){
            ig_md.total_hdr_len_bytes=(ig_md.tmp_1+ig_md.tmp_2);
        }
        action compute_eack_5_(){
            ig_md.total_body_len_bytes=ig_md.tmp_3 - ig_md.total_hdr_len_bytes;
        }
        action compute_eack_6_(){
            ig_md.expected_ack=hdr.tcp.seq_no + ig_md.total_body_len_bytes;
        }
        
        action compute_eack_last_if_syn(){
            ig_md.expected_ack=ig_md.expected_ack + 1;
            // could save 1 stage here by folding this into "++ 2w0" as "++ 2w1"
        }
        
        // Calculate 32-bit packet signature, to be stored into hash tables
        
        Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32_1;
        Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32_2;
        action get_pkt_signature_SEQ(){
            ig_md.pkt_signature=crc32_1.get({
                hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                hdr.tcp.src_port, hdr.tcp.dst_port,
                ig_md.expected_ack
            });
        }
        action get_pkt_signature_ACK(){
            ig_md.pkt_signature=crc32_2.get({
                hdr.ipv4.dst_addr,hdr.ipv4.src_addr, 
                hdr.tcp.dst_port,hdr.tcp.src_port, 
                hdr.tcp.ack_no
            });
        }
        
        // Calculate 16-bit hash table index
                
        Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_1;
        Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_2;
        action get_location_SEQ(){
            ig_md.hashed_location_1=crc16_1.get({
                4w0,
                hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                hdr.tcp.src_port, hdr.tcp.dst_port,
                ig_md.expected_ack,
                4w0
            });
        }
        action get_location_ACK(){
            ig_md.hashed_location_1=crc16_2.get({
                4w0,
                hdr.ipv4.dst_addr,hdr.ipv4.src_addr, 
                hdr.tcp.dst_port,hdr.tcp.src_port, 
                hdr.tcp.ack_no,
                4w0
            });
        }
        
        // Self-expiry hash table, each entry stores a signature and a timestamp
        
        #define TIMESTAMP ig_intr_md.ingress_mac_tstamp[31:0]
        #define TS_EXPIRE_THRESHOLD (50*1000*1000)
        //50ms
        #define TS_LEGITIMATE_THRESHOLD (2000*1000*1000)
        
        
        Register<paired_32bit,_>(32w65536) reg_table_1;
        //lo:signature, hi:timestamp
        
        RegisterAction<paired_32bit, _, bit<32>>(reg_table_1) table_1_insert= {  
            void apply(inout paired_32bit value, out bit<32> rv) {          
                rv = 0;                                                    
                paired_32bit in_value;                                          
                in_value = value;                 
                
                bool existing_timestamp_is_old = (TIMESTAMP-in_value.hi)>TS_EXPIRE_THRESHOLD;
                bool current_entry_empty = in_value.lo==0;
                
                if(existing_timestamp_is_old || current_entry_empty)
                {
                    value.lo=ig_md.pkt_signature;
                    value.hi=TIMESTAMP;
                    rv=1;
                }
            }                                                              
        };
        
        action exec_table_1_insert(){
            ig_md.table_1_read=table_1_insert.execute(ig_md.hashed_location_1);
        }
        
        RegisterAction<paired_32bit, _, bit<32>>(reg_table_1) table_1_tryRead= {  
            void apply(inout paired_32bit value, out bit<32> rv) {    
                rv=0;
                paired_32bit in_value;                                          
                in_value = value;     
                
                #define current_entry_matched (in_value.lo==ig_md.pkt_signature)
                #define timestamp_legitimate  ((TIMESTAMP-in_value.hi)<TS_LEGITIMATE_THRESHOLD)
                
                if(current_entry_matched && timestamp_legitimate)
                {
                    value.lo=0;
                    value.hi=0;
                    rv=in_value.hi;
                }
            }                                                              
        };
        
        action exec_table_1_tryRead(){
            ig_md.table_1_read=table_1_tryRead.execute(ig_md.hashed_location_1);
        }
        
        // Send output report as a UDP packet
        
        action prepare_report(){
            hdr.report.setValid();
            //ip
            hdr.report.version=4;
            hdr.report.ihl=5;
            hdr.report.diffserv=0;
            hdr.report.total_len=hdr.ipv4.total_len + 20 + 8 + 8;//+ipv4 + udp + payload
            hdr.report.ttl=64;
            hdr.report.protocol=IP_PROTOCOLS_UDP;
            hdr.report.src_addr=0x0a000001;
            hdr.report.src_addr=0x0a000002;
            //udp
            hdr.report.src_port=65534;
            hdr.report.dst_port=65534;
            hdr.report.checksum=0;
        }
        
        apply {
            // for debugging, route everything to debug port
            route_to_64();
            
            // decide if the packet is SYN or ACK
            tb_decide_packet_type.apply();
            
            // compute e_ack
            if(ig_md.pkt_type==PKT_TYPE_SEQ){
                compute_eack_1_();
                compute_eack_2_();
                compute_eack_3_();
                compute_eack_4_();
                compute_eack_5_();
                compute_eack_6_();
                if(hdr.tcp.flags==TCP_FLAGS_S){
                    compute_eack_last_if_syn();
                }
            }
            
            
            //get signature (after having eack)
            
            if(ig_md.pkt_type==PKT_TYPE_SEQ){
                get_pkt_signature_SEQ();
                get_location_SEQ();
            }else{
                get_pkt_signature_ACK();
                get_location_ACK();
            }
            
            
            
            // insert into table if syn
            // read from table if ack
            
            // Insert or Read from hash table
            if(ig_md.pkt_type==PKT_TYPE_SEQ){
                exec_table_1_insert();
            }else{
                exec_table_1_tryRead();
            }
            // To add multiple stage of hash tables:
            // syn: insert into table 2 if insertion failed in 1
            // ack: query table 2 if query failed in 1 (matched ts ==0)
            
            
            // send out report headers.
             if(ig_md.pkt_type==PKT_TYPE_SEQ){
                hdr.report.payload_1=ig_md.table_1_read;
                hdr.ethernet.src_addr=0x1;
            }else{
                if(ig_md.table_1_read==0){
                    hdr.ethernet.src_addr=0x2;
                    hdr.report.payload_1=0;
                }else{
                    hdr.report.payload_1=(TIMESTAMP-ig_md.table_1_read);
                    hdr.ethernet.src_addr=0x3;
                }
            }
            
        }
}

control SwitchEgress(
        inout header_t hdr,
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

