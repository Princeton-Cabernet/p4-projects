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

// Testbed parameters
const bit<9> SERVER_PORT=12; 
const bit<32> SERVER_IP=0x0C000003;//12.0.0.3

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_SIPH_INTM = 16w0xff00;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<16> PORT_TIMEDELTA_UPDATE = 5555; //for time delta
const bit<4> CALLBACK_TYPE_SYNACK=1;
const bit<4> CALLBACK_TYPE_TAGACK=2; 

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header sip_meta_h {
    bit<32> v_0;
    bit<32> v_1;
    bit<32> v_2;
    bit<32> v_3;
    bit<8> round;
    @padding bit<4> __padding1;
    bit<4> callback_type;
    @padding bit<7> __padding2;
    bit<9> egr_port;
    
    bit<32> cookie_time;
    bit<32> ack_verify_timediff;
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
    //
    bit<1> flag_cwr;
    bit<1> flag_ece; 
    //
    bit<1> flag_urg;
    bit<1> flag_ack;
    bit<1> flag_psh;
    bit<1> flag_rst;
    bit<1> flag_syn;
    bit<1> flag_fin;
    //
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

header udp_payload_h {
    bit<32> timestamp;
}

struct header_t {
    ethernet_h ethernet;
    sip_meta_h sip_meta;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    udp_payload_h udp_payload;
}

struct ig_metadata_t {    
    bit<32> timestamp_now_copy;
    bit<32> timestamp_minus_servertime;
    bit<32> msg_var;
    
    bit<1> bloom_read_1;
    bit<1> bloom_read_2;
    bool bloom_read_passed;
    bool ingress_is_server_port;
    bit<1> ack_verify_timediff_exceeded_limit;
    
    bit<1> flag_ece;
    bit<1> flag_ack;
    bit<1> flag_syn;
    
    bit<16> tcp_total_len;//always 20
    bit<1> redo_checksum;
}
struct eg_metadata_t {
        bit<32> msg_var;
    
    bit<32> cookie_val;
    bit<32> incoming_ack_minus_1;
    bit<32> incoming_seq_plus_1;

    bit<16> tcp_total_len;//always 20
    bit<1> redo_checksum;
    bit<1> tb_output_stage;
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
            ETHERTYPE_SIPH_INTM: parse_sip_meta;
            default : reject;
        }
    }
    
    state parse_sip_meta {
        pkt.extract(hdr.sip_meta);
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
            PORT_TIMEDELTA_UPDATE: parse_udp_payload;
            default: accept;
        }
    }
    
    state parse_udp_payload {
        pkt.extract(hdr.udp_payload);
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
        pkt.emit(hdr.sip_meta);
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
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_SIPH_INTM: parse_sip_meta;
            default : reject;
        }
    }
    
    state parse_sip_meta {
        pkt.extract(hdr.sip_meta);
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

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    
    Checksum() ip_checksum;
    Checksum() tcp_checksum;    
    
    apply {
        if(eg_md.redo_checksum == 1){            
            hdr.ipv4.hdr_checksum = ip_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });

            hdr.tcp.checksum = tcp_checksum.update({
                //==pseudo header
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                eg_md.tcp_total_len,
                //==actual header
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset,
                hdr.tcp.res,
                hdr.tcp.flag_cwr, 
                hdr.tcp.flag_ece, 
                hdr.tcp.flag_urg, 
                hdr.tcp.flag_ack, 
                hdr.tcp.flag_psh, 
                hdr.tcp.flag_rst, 
                hdr.tcp.flag_syn, 
                hdr.tcp.flag_fin, 
                hdr.tcp.window,
                hdr.tcp.urgent_ptr
                //hdr.payload
            });
        }//endif redo_checksum 

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.sip_meta);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
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
        
    action bypass_egress(){
        ig_intr_tm_md.bypass_egress=1;
    }
    action dont_bypass_egress(){
        ig_intr_tm_md.bypass_egress=0;
    }
     
    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
        bypass_egress(); // for safety, bypass egress as well
    }
    action dont_drop(){
        ig_intr_dprsr_md.drop_ctl = 0x0; 
    }
    
    action nop() {
    }
    action route_to(bit<9> port){
        ig_intr_tm_md.ucast_egress_port=port;
    hdr.ethernet.src_addr=1; 
    hdr.ethernet.dst_addr=(bit<48>) port; 
    }
    action reflect(){
        //send you back to where you're from
        route_to(ig_intr_md.ingress_port);
    }
    
    action do_recirc(){
    //    route_to(68);
    }
    
    
    // time-delta 
    
    Register<bit<32>,_ >(1) reg_timedelta;
    RegisterAction<bit<32>, _, bit<32>>(reg_timedelta) regact_timedelta_write = 
    {
        void apply(inout bit<32> value, out bit<32> ret){
            value = ig_md.timestamp_minus_servertime;
            ret = 0;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(reg_timedelta) regact_timedelta_read = 
    {
        void apply(inout bit<32> value, out bit<32> ret){
            ret = value;
        }
    };
        
        //#define TIMESTAMP_NOW_USEC ((bit<32>) ig_intr_md.ingress_mac_tstamp[41:10])
    #define TIMESTAMP_NOW_TICK_16 ((bit<32>) ig_intr_md.ingress_mac_tstamp[47:16])
    action timedelta_step0(){
        @in_hash{ ig_md.timestamp_now_copy = TIMESTAMP_NOW_TICK_16; }
    }
    action timedelta_step1_write(){
        ig_md.timestamp_minus_servertime = ig_md.timestamp_now_copy - hdr.udp_payload.timestamp;
    }
    action timedelta_step2_write(){
        regact_timedelta_write.execute(0);
    }
    action timedelta_step1_read(){
        ig_md.timestamp_minus_servertime = regact_timedelta_read.execute(0);
    }
    action timedelta_step2_read(){
        hdr.sip_meta.cookie_time = ig_md.timestamp_now_copy - ig_md.timestamp_minus_servertime;
    }
    action timedelta_step3_read(){
        hdr.sip_meta.cookie_time= hdr.sip_meta.cookie_time >> 12;
    }  
    
    // bloom filter for flows
    Register<bit<1>,_ >(32w4096) reg_bloom_1;
    RegisterAction<bit<1>, _, bit<1>>(reg_bloom_1) regact_bloom_1_get = 
    {
        void apply(inout bit<1> value, out bit<1> ret){
            ret = value;
        }
    };
    RegisterAction<bit<1>, _, bit<1>>(reg_bloom_1) regact_bloom_1_set = 
    {
        void apply(inout bit<1> value, out bit<1> ret){
            value = 1;
            ret = 0;
        }
    };

    Register<bit<1>,_ >(32w4096) reg_bloom_2;
    RegisterAction<bit<1>, _, bit<1>>(reg_bloom_2) regact_bloom_2_get = 
    {
        void apply(inout bit<1> value, out bit<1> ret){
            ret = value;
        }
    };
    RegisterAction<bit<1>, _, bit<1>>(reg_bloom_2) regact_bloom_2_set = 
    {
        void apply(inout bit<1> value, out bit<1> ret){
            value = 1;
            ret = 0;
        }
    };

    Hash<bit<12>>(HashAlgorithm_t.CRC16) hash_1;
    Hash<bit<12>>(HashAlgorithm_t.CRC32) hash_2;
    action set_bloom_1_a(){
        regact_bloom_1_set.execute(hash_1.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port,hdr.tcp.dst_port }));
    }
    action set_bloom_2_a(){
        regact_bloom_2_set.execute(hash_2.get({ 3w1, hdr.ipv4.src_addr, 3w1,  hdr.ipv4.dst_addr,  3w1, hdr.tcp.src_port,  3w1, hdr.tcp.dst_port }));
    }
    action get_bloom_1_a(){
        ig_md.bloom_read_1=regact_bloom_1_get.execute(hash_1.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port,hdr.tcp.dst_port }));
    }
    action get_bloom_2_a(){
        ig_md.bloom_read_2=regact_bloom_2_get.execute(hash_2.get({ 3w1, hdr.ipv4.src_addr, 3w1,  hdr.ipv4.dst_addr,  3w1, hdr.tcp.src_port,  3w1, hdr.tcp.dst_port }));
    }
        
        // packet in-out related

    action naive_routing(){
        @in_hash{ ig_intr_tm_md.ucast_egress_port = (bit<9>) hdr.ipv4.dst_addr[31:24]; }
        hdr.ethernet.src_addr=1;
        hdr.ethernet.dst_addr[47:8] = 0; 
        @in_hash{hdr.ethernet.dst_addr[7:0]=hdr.ipv4.dst_addr[31:24];} 
    }
    
    action craft_onward_ack(){
        hdr.tcp.seq_no=hdr.tcp.seq_no-1;
        hdr.tcp.data_offset=5;
        //add setup tag
        hdr.tcp.flag_ece=1;
    }

    // finally, decide next step for all types of packets
    // traffic, stop at first pass
    action client_to_server_nonsyn_ongoing(){
        route_to(SERVER_PORT); bypass_egress(); dont_drop();
    hdr.sip_meta.setInvalid(); hdr.ethernet.ether_type=ETHERTYPE_IPV4; 
    }
    action server_to_client_normal_traffic(){
        hdr.sip_meta.setInvalid();  hdr.ethernet.ether_type=ETHERTYPE_IPV4;
        naive_routing(); bypass_egress(); dont_drop();
    }
    action non_tcp_traffic(){
        naive_routing(); bypass_egress(); dont_drop();
    }
    // hash calc
    Hash<bit<32>>(HashAlgorithm_t.CRC32) cookie_hash;
    action start_crc_calc_synack(){
        hdr.sip_meta.callback_type=CALLBACK_TYPE_SYNACK;
        hdr.sip_meta.egr_port=ig_intr_md.ingress_port; 
        cookie_hash.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no }); 
    }
    action start_crc_calc_tagack(){
        hdr.sip_meta.callback_type=CALLBACK_TYPE_TAGACK;
        hdr.sip_meta.egr_port=SERVER_PORT; 
        cookie_hash.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no }); 
    }
    action pre_finalize_synack(){
        hdr.sip_meta.round=10;
        route_to(hdr.sip_meta.egr_port); dont_bypass_egress(); dont_drop();
    }
    action pre_finalize_tagack(){
        hdr.sip_meta.round=10;
        do_recirc(); dont_bypass_egress(); dont_drop();
    }
    
    action finalize_tagack(){
        route_to(hdr.sip_meta.egr_port);
        //don't bypass egress, perform checksum update in egress deparser 
        dont_bypass_egress();
        hdr.sip_meta.round=99; //DO_CHECKSUM
        // if failed cookie check, drop
        ig_intr_dprsr_md.drop_ctl = (bit<3>) ig_md.ack_verify_timediff_exceeded_limit; 
        
        craft_onward_ack();
        //move this logic to egress 
        // remove sip_meta header
        //hdr.sip_meta.setInvalid();  hdr.ethernet.ether_type=ETHERTYPE_IPV4;
    }
    @pragma stage 11
    table tb_triage_pkt_types_nextstep {
        key = {
            hdr.sip_meta.round: exact;
            hdr.tcp.isValid(): exact;
            hdr.udp_payload.isValid(): exact;
            
            ig_md.ingress_is_server_port: ternary;
            
            ig_md.flag_syn: ternary;
            ig_md.flag_ack: ternary;
            ig_md.flag_ece: ternary; 
            
            hdr.sip_meta.callback_type: ternary;
            
            ig_md.bloom_read_passed: ternary;
        }
        actions = {
            drop;
            start_crc_calc_synack;
            start_crc_calc_tagack;
            client_to_server_nonsyn_ongoing;
            server_to_client_normal_traffic;
            non_tcp_traffic;
            
            pre_finalize_synack;
            pre_finalize_tagack;
            finalize_tagack;
        }
        default_action = drop();
        const entries = {//all types of packets, from linker_config.json in Lucid
             
             //"event" : "udp_from_server_time"
             (0,false,true,   true,    _,_,_,  _, _): drop(); //already saved time delta
             //"event" : "iptcp_to_server_syn"
             (0,true,false,   false,   1,0,_,  _, _ ): start_crc_calc_synack();
             //"event" : "iptcp_to_server_non_syn"
             (0,true,false,   false,   0,_,_,  _, false): start_crc_calc_tagack();
             (0,true,false,   false,   0,_,_,  _, true): client_to_server_nonsyn_ongoing();
             
             //"event" : "iptcp_from_server_tagged"
             (0,true,false,   true,    _,_,1,  _, _): drop(); //already added to bf
             //"event" : "iptcp_from_server_non_tagged"
             (0,true,false,   true,    _,_,0,  _, _): server_to_client_normal_traffic();
             //"event" : "non_tcp_in"
             (0,false,true, false,     _,_,_,  _, _): non_tcp_traffic();
             (0,false,false, _,     _,_,_,  _, _): non_tcp_traffic();
             
             //round 8->10
             (8,true,false,  _,     _,_,_,  CALLBACK_TYPE_TAGACK, _): pre_finalize_tagack(); //round 8->10, tagack needs one last recirc, after 3rd pass (12 round) come back to ingress again for final determination
             (8,true,false,  _,     _,_,_,  CALLBACK_TYPE_SYNACK, _): pre_finalize_synack(); //round 8->10, route to client
             //round 12, tagack
             (12,true,false, _,     _,_,_,  CALLBACK_TYPE_TAGACK, _): finalize_tagack(); //route to server, drop if bad cookie 
        }
        size = 32;
    }
        
    Random< bit<1> >() rng;

    apply {    
        
        //stage 0
        //tb_maybe_sip_init.apply();
       
        //calculate all other cases in parallel
        
        timedelta_step0();
        if(hdr.udp_payload.isValid() && ig_intr_md.ingress_port==SERVER_PORT){
            timedelta_step1_write();
            timedelta_step2_write();
            //drop(); //for full parallelization, postpone to triage table
        }else{
            timedelta_step1_read();
            timedelta_step2_read();
            timedelta_step3_read();
        }
        
        if(hdr.tcp.isValid() && ig_intr_md.ingress_port == SERVER_PORT && hdr.tcp.flag_ece==1){
            set_bloom_1_a();
            set_bloom_2_a();
            ig_md.bloom_read_passed=false;
            //drop(); //for full parallelization, postpone to triage table
        }else{
            get_bloom_1_a();
            get_bloom_2_a();
            if(ig_md.bloom_read_1==1 && ig_md.bloom_read_2==1){
                ig_md.bloom_read_passed=true;
            }else{
                ig_md.bloom_read_passed=false;
            }
        }
        
        //pre-calculate conditions and save in metadata. used in final stage triage.
        if(ig_intr_md.ingress_port==SERVER_PORT){
            ig_md.ingress_is_server_port = true;
        }else{
            ig_md.ingress_is_server_port = false;
        }

        if(hdr.sip_meta.ack_verify_timediff==0 || hdr.sip_meta.ack_verify_timediff==1 || hdr.sip_meta.ack_verify_timediff==2){
            ig_md.ack_verify_timediff_exceeded_limit=0;
        }else{
            ig_md.ack_verify_timediff_exceeded_limit=1;
        }
        
        
        // hdr.sip_meta.round=hdr.sip_meta.round+2; // increment round as part of final-stage triage table

        if(hdr.tcp.isValid()){
            ig_md.flag_syn=hdr.tcp.flag_syn;
            ig_md.flag_ack=hdr.tcp.flag_ack;
            ig_md.flag_ece=hdr.tcp.flag_ece;
        }
        else{
            ig_md.flag_syn=0;
            ig_md.flag_ack=0;
            ig_md.flag_ece=0;
        }
        bit<1> rnd = rng.get();
        if(rnd==1){
            route_to(68);
        }
        else{
            route_to(68+128);
        }
        tb_triage_pkt_types_nextstep.apply();
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
   
    action clean_up(){
        hdr.sip_meta.setInvalid();
        hdr.ethernet.ether_type=ETHERTYPE_IPV4; 
    }

    action sip_final_xor_with_time(){
        @in_hash{ hdr.tcp.seq_no = 
        hdr.sip_meta.cookie_time ^ 
        hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3; 
        }
        clean_up();
    }

    action sip_final_xor_with_ackm1(){
        @in_hash{ eg_md.cookie_val = 
        eg_md.incoming_ack_minus_1 ^ 
        hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3; 
        }
    }
    
    action verify_timediff(){
        hdr.sip_meta.ack_verify_timediff = hdr.sip_meta.cookie_time - eg_md.cookie_val; // should be 0 or 1
    }

    action craft_synack_reply(){
        hdr.tcp.ack_no=eg_md.incoming_seq_plus_1;
        //move this call to a separate table call to avoid too many hashes in one action/table 
        //sip_final_xor_with_time(); // cookie_val = time ^ hash, -> synack
    
        //swap IP
        bit<32> tmp=hdr.ipv4.src_addr;
        hdr.ipv4.src_addr=hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr=tmp;
       
        //swap port 
        bit<16> tmp_port = hdr.tcp.src_port;  
        hdr.tcp.src_port=hdr.tcp.dst_port;
        hdr.tcp.dst_port=tmp_port;
    
        //packet crafting 
        hdr.tcp.data_offset=5;
        
        hdr.tcp.flag_ack=1;
        hdr.tcp.flag_syn=1;

        hdr.ipv4.ihl=5;
        hdr.ipv4.total_len=40; 

        //necessary for checksum update 
        eg_md.redo_checksum=1;
        eg_md.tcp_total_len=20; 

        //routing done in ingress
    }
    
    action drop(){
        ig_intr_dprs_md.drop_ctl=1;
    }
    action dont_drop(){
        ig_intr_dprs_md.drop_ctl=0;
    }

    action nop() {
    }
    table tb_decide_output_type_1 {
        key = {
            hdr.sip_meta.isValid(): exact;
            hdr.tcp.isValid(): exact;
            hdr.sip_meta.round: exact;
            hdr.sip_meta.callback_type: ternary;
        //eg_md.tb_output_stage: exact; 
         }
        actions = {
            craft_synack_reply; 
            sip_final_xor_with_ackm1;
            clean_up;
            nop;
        }
        default_action = nop;
        size = 16;
        const entries={
            (true, true, 12, CALLBACK_TYPE_SYNACK): craft_synack_reply();
            (true, true, 12, CALLBACK_TYPE_TAGACK): sip_final_xor_with_ackm1();  // cookie_val = (ack-1) ^ hash, ==? time(+1)
            (true, true, 12, _): clean_up();
        }
    }
    
    table tb_decide_output_type_2 {
        key = {
            hdr.sip_meta.isValid(): exact;
            hdr.tcp.isValid(): exact;
            hdr.sip_meta.round: exact;
            hdr.sip_meta.callback_type: ternary;
         }
        actions = {
            sip_final_xor_with_time;
            verify_timediff;
            nop;
        }
        default_action = nop;
        size = 16;
        const entries={
            (true, true, 12, CALLBACK_TYPE_SYNACK): sip_final_xor_with_time();//need second stage to not have two hash copies in one action 
            (true, true, 12, CALLBACK_TYPE_TAGACK): verify_timediff(); //need second stage to complete case for CALLBACK_TYPE_TAGACK 
        }
    }

    apply {
        //this is CRC benchmark, egress does not need to run hash rounds


        if(hdr.sip_meta.round != 99){
            hdr.sip_meta.round=hdr.sip_meta.round+2;
            eg_md.incoming_ack_minus_1=hdr.tcp.ack_no - 1;
            eg_md.incoming_seq_plus_1=hdr.tcp.seq_no + 1;
            eg_md.tcp_total_len=20;
            eg_md.redo_checksum=0;
            tb_decide_output_type_1.apply();     
            tb_decide_output_type_2.apply(); 
        }//endif round!=99
        else{ //round==99, here from ingress to perform checksum update in deparser  
            //don't do any further modification of packet 

            //necessary for checksum update 
            hdr.ipv4.ihl=5;
            hdr.ipv4.total_len=40; 

            eg_md.redo_checksum=1;
            eg_md.tcp_total_len=20; 
            // remove sip_meta header
            hdr.sip_meta.setInvalid();  hdr.ethernet.ether_type=ETHERTYPE_IPV4;
        }
    }//apply
}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;
