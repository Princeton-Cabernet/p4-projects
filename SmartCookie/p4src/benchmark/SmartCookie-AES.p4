/*
    SmartCookie: Blocking Large-Scale SYN Floods with a Split-Proxy Defense on Programmable Data Planes
    
    Copyright (C) 2023 Sophia Yoo, Xiaoqi Chen, Princeton University
    sy6 [at] princeton.edu
    
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

// Benchmark: reply to all SYN packets with Cookie=AES(4-tuple)

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_RECIRC = 16w0xff00;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
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
    bit<16> udp_total_len;
    bit<16> checksum;
}

header aes_inout_h {
    bit<8> s00;
    bit<8> s01;
    bit<8> s02;
    bit<8> s03;
    bit<8> s10;
    bit<8> s11;
    bit<8> s12;
    bit<8> s13;
    bit<8> s20;
    bit<8> s21;
    bit<8> s22;
    bit<8> s23;
    bit<8> s30;
    bit<8> s31;
    bit<8> s32;
    bit<8> s33;
}
header aes_meta_h {
    bit<16> dest_port;
    bit<8> curr_round;
    bit<8> ff;
}

struct header_t {
    ethernet_h ethernet;
    aes_inout_h aes;
    aes_meta_h aes_meta;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}


header aes_tmp_h {
    bit<32> v00;
    bit<32> v01;
    bit<32> v02;
    bit<32> v03;
    bit<32> v10;
    bit<32> v11;
    bit<32> v12;
    bit<32> v13;
    bit<32> v20;
    bit<32> v21;
    bit<32> v22;
    bit<32> v23;
    bit<32> v30;
    bit<32> v31;
    bit<32> v32;
    bit<32> v33;
    
    bit<32> s0a;
    bit<32> s1a;
    bit<32> s2a;
    bit<32> s3a;
    bit<32> s0b;
    bit<32> s1b;
    bit<32> s2b;
    bit<32> s3b;
}

struct ig_metadata_t {
    bool recirc;
    
    bit<9> rnd_port_for_recirc;
    bit<1> rnd_bit;

    bit<32> cookie;
    bit<32> timestamp_copy;
    bit<1> do_craft;

    aes_tmp_h aes_tmp;
}
struct eg_metadata_t {
}

#define TIMESTAMP_NOW_TICK_16 ((bit<32>) ig_intr_md.ingress_mac_tstamp[47:10])

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
        //pkt.extract(ig_md.resubmit_data_read);
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
            ETHERTYPE_RECIRC : parse_recirc;
            default : reject;
        }
    }

    state parse_recirc {
        pkt.extract(hdr.aes_meta);
        pkt.extract(hdr.aes);
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
        transition accept;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.aes_meta);
        pkt.emit(hdr.aes);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
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
        action reflect(){
            ig_intr_tm_md.ucast_egress_port=ig_intr_md.ingress_port;
        }
        action route_to(bit<9> port){
            ig_intr_tm_md.ucast_egress_port=port;
        }
        
        // Randomly select one of the two recirc ports
        Random< bit<1> >() rng;
        action get_rnd_bit(){
            ig_md.rnd_bit=rng.get();
        }
        
        #define GEN_LOOKUP_TABLE(R,C)     \
        action write_v_## R ##_## C ##_a(bit<32> v){  \
            ig_md.aes_tmp.v## R ## C =v;              \
        } \
        table tb_lookup_## R ##_## C ##_t {           \
            key = {  \
                hdr.aes.s## R ## C : exact;  \
                hdr.aes_meta.curr_round: exact;       \
            } \
            size = 3600; \
            actions = {  \
                write_v_## R ##_## C ##_a; \
            } \
        } \
        table tb_lookup_## R ##_## C ##_t2r {           \
            key = {  \
                hdr.aes.s## R ## C : exact;  \
                hdr.aes_meta.curr_round: exact;       \
            } \
            size = 3600; \
            actions = {  \
                write_v_## R ##_## C ##_a; \
            } \
        } \
        //done. note we actually need 256*14 entries at most
        
        #define GEN_LOOKUPS_FOR_R(R) \
        GEN_LOOKUP_TABLE(R,0) \
        GEN_LOOKUP_TABLE(R,1) \
        GEN_LOOKUP_TABLE(R,2) \
        GEN_LOOKUP_TABLE(R,3) \
        //for 4 cols at a time

        GEN_LOOKUPS_FOR_R(0)
        GEN_LOOKUPS_FOR_R(1)
        GEN_LOOKUPS_FOR_R(2)
        GEN_LOOKUPS_FOR_R(3)
        //all 16 tables generated.
        
        // Xor-ing 4 values (from 4 lookup tables) into 1 value.
        
        #define GEN_XOR_COMBINED_FOR_R(R,V1,V2,V3,V4) \
        action xor_s_## R ##_combined(){ \
            @in_hash{ hdr.aes.s## R ## 0 = (ig_md.aes_tmp.v## V1 ##[31:24] ^ ig_md.aes_tmp.v## V2 ##[31:24] ^ ig_md.aes_tmp.v## V3 ##[31:24] ^ ig_md.aes_tmp.v## V4 ##[31:24]); } \
            @in_hash{ hdr.aes.s## R ## 1 = (ig_md.aes_tmp.v## V1 ##[23:16] ^ ig_md.aes_tmp.v## V2 ##[23:16] ^ ig_md.aes_tmp.v## V3 ##[23:16] ^ ig_md.aes_tmp.v## V4 ##[23:16]); } \
            @in_hash{ hdr.aes.s## R ## 2 = (ig_md.aes_tmp.v## V1 ##[15: 8] ^ ig_md.aes_tmp.v## V2 ##[15: 8] ^ ig_md.aes_tmp.v## V3 ##[15: 8] ^ ig_md.aes_tmp.v## V4 ##[15: 8]); } \
            @in_hash{ hdr.aes.s## R ## 3 = (ig_md.aes_tmp.v## V1 ##[ 7: 0] ^ ig_md.aes_tmp.v## V2 ##[ 7: 0] ^ ig_md.aes_tmp.v## V3 ##[ 7: 0] ^ ig_md.aes_tmp.v## V4 ##[ 7: 0]); } \
        } \
        // Combined XOR 4-to-1 using in-hash
        GEN_XOR_COMBINED_FOR_R(0, 00,11,22,33)
        GEN_XOR_COMBINED_FOR_R(1, 10,21,32,03)
        GEN_XOR_COMBINED_FOR_R(2, 20,31,02,13)
        GEN_XOR_COMBINED_FOR_R(3, 30,01,12,23)

        //End of AES tables

        // === High level program logic starts here ===
        action init_aes_input(){
            //copy TCP header info into AES block
            //cookie=hash(4-tuple+seq)
            hdr.aes.s00 = hdr.ipv4.src_addr[31:24];
            hdr.aes.s01 = hdr.ipv4.src_addr[23:16];
            hdr.aes.s02 = hdr.ipv4.src_addr[15: 8];
            hdr.aes.s03 = hdr.ipv4.src_addr[ 7: 0];
            
            hdr.aes.s10 = hdr.ipv4.dst_addr[31:24];
            hdr.aes.s11 = hdr.ipv4.dst_addr[23:16];
            hdr.aes.s12 = hdr.ipv4.dst_addr[15: 8];
            hdr.aes.s13 = hdr.ipv4.dst_addr[ 7: 0];
            
            hdr.aes.s20 = hdr.tcp.src_port[15: 8];
            hdr.aes.s21 = hdr.tcp.src_port[ 7:0];
            hdr.aes.s22 = hdr.tcp.dst_port[15: 8];
            hdr.aes.s23 = hdr.tcp.dst_port[ 7: 0];

            @in_hash{ hdr.aes.s30 = hdr.tcp.seq_no[31:24]; }
            @in_hash{ hdr.aes.s31 = hdr.tcp.seq_no[23:16]; }
            @in_hash{ hdr.aes.s32 = hdr.tcp.seq_no[15: 8]; }
            @in_hash{ hdr.aes.s33 = hdr.tcp.seq_no[ 7: 0]; }
        }

        action write_aes_output_to_seq_lastxor(bit<8> s00, bit<8> s01, bit<8> s02, bit<8> s03){
            @in_hash{ ig_md.cookie[31:24] = hdr.aes.s00 ^ s00; }
            @in_hash{ ig_md.cookie[23:16] = hdr.aes.s01 ^ s01; }
            @in_hash{ ig_md.cookie[15: 8] = hdr.aes.s02 ^ s02; }
            @in_hash{ ig_md.cookie[ 7: 0] = hdr.aes.s03 ^ s03; }
        }

        action swap_ip_port(){
            //swaps
            bit<32> tmp1=hdr.ipv4.src_addr;
            hdr.ipv4.src_addr=hdr.ipv4.dst_addr;
            hdr.ipv4.dst_addr=tmp1;
            bit<16> tmp2=hdr.tcp.src_port;
            hdr.tcp.src_port=hdr.tcp.dst_port;
            hdr.tcp.dst_port=tmp2;
        }
        
        action incr_and_recirc(bit<8> next_round){
            hdr.aes_meta.curr_round=next_round;
            //route to recirc port
            //do_recirculate
            route_to(ig_md.rnd_port_for_recirc);
            hdr.ethernet.ether_type=ETHERTYPE_RECIRC;

            ig_md.do_craft=0;
        }

        
        action do_not_recirc(){
            route_to((bit<9>)hdr.aes_meta.dest_port);                
            //copy over the cookie!
            ig_md.do_craft=1;
            
            hdr.aes.setInvalid();
            hdr.aes_meta.setInvalid();
            hdr.ethernet.ether_type=ETHERTYPE_IPV4;
        }
        action do_not_recirc_final_xor(
            bit<8> s00,
            bit<8> s01,
            bit<8> s02,
            bit<8> s03,
            bit<8> s10,
            bit<8> s11,
            bit<8> s12,
            bit<8> s13,
            bit<8> s20,
            bit<8> s21,
            bit<8> s22,
            bit<8> s23,
            bit<8> s30,
            bit<8> s31,
            bit<8> s32,
            bit<8> s33
        ){
            do_not_recirc();
            //copy over the cookie!
            write_aes_output_to_seq_lastxor(s00,s01,s02,s03);
        }
        
        table tb_recirc_decision {
            key = {
                hdr.aes_meta.curr_round : exact;
            }
            actions = {
                incr_and_recirc;
                do_not_recirc;
                do_not_recirc_final_xor;
            }
            size = 20;
            default_action = do_not_recirc;
        }

        apply {

            if(! hdr.aes_meta.isValid()){
                //init!
                hdr.aes_meta.setValid();
                hdr.aes_meta.curr_round=0;
                hdr.aes_meta.ff=0xff;

                //bounce routing
                hdr.aes_meta.dest_port= (bit<16>)(ig_intr_md.ingress_port);

                //initialize AES calculation... 
                hdr.aes.setValid();
                
                init_aes_input();
            }else{//aes_meta valid
                if(!hdr.aes.isValid()){
                    exit;//buggy, must both be valid
                }
            }

            //Tofino 32-port has 2x 100G recirc ports. Use any one of them.
            get_rnd_bit();//ig_md.rnd_bit;
            if(ig_md.rnd_bit==0){
                ig_md.rnd_port_for_recirc=68;
            }else{
                ig_md.rnd_port_for_recirc=68+128;
            }

            //1st encryption round
            
            tb_lookup_0_0_t.apply();
            tb_lookup_0_1_t.apply();
            tb_lookup_0_2_t.apply();
            tb_lookup_0_3_t.apply();
            tb_lookup_1_0_t.apply();
            tb_lookup_1_1_t.apply();
            tb_lookup_1_2_t.apply();
            tb_lookup_1_3_t.apply();
            tb_lookup_2_0_t.apply();
            tb_lookup_2_1_t.apply();
            tb_lookup_2_2_t.apply();
            tb_lookup_2_3_t.apply();
            tb_lookup_3_0_t.apply();
            tb_lookup_3_1_t.apply();
            tb_lookup_3_2_t.apply();
            tb_lookup_3_3_t.apply();
            
            xor_s_0_combined();
            xor_s_1_combined();
            xor_s_2_combined();
            xor_s_3_combined();
            
            //2nd encryption round
            
            tb_lookup_0_0_t2r.apply();
            tb_lookup_0_1_t2r.apply();
            tb_lookup_0_2_t2r.apply();
            tb_lookup_0_3_t2r.apply();
            tb_lookup_1_0_t2r.apply();
            tb_lookup_1_1_t2r.apply();
            tb_lookup_1_2_t2r.apply();
            tb_lookup_1_3_t2r.apply();
            tb_lookup_2_0_t2r.apply();
            tb_lookup_2_1_t2r.apply();
            tb_lookup_2_2_t2r.apply();
            tb_lookup_2_3_t2r.apply();
            tb_lookup_3_0_t2r.apply();
            tb_lookup_3_1_t2r.apply();
            tb_lookup_3_2_t2r.apply();
            tb_lookup_3_3_t2r.apply();
            
            xor_s_0_combined();
            xor_s_1_combined();
            xor_s_2_combined();
            xor_s_3_combined();

            tb_recirc_decision.apply();

            @in_hash{ ig_md.timestamp_copy = TIMESTAMP_NOW_TICK_16; }

            if(ig_md.do_craft==1){//just do this once...
                //craft_synack
                swap_ip_port();
                hdr.tcp.ack_no=hdr.tcp.seq_no+1;
                @in_hash{  hdr.tcp.seq_no=ig_md.cookie ^ ig_md.timestamp_copy; }
            }
        }
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
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

