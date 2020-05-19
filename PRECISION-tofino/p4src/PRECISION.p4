/*
    PRECISION: A heavy-htter detection algorithm using Probabilistic Recirculation
    
    Copyright (C) 2019 Xiaoqi Chen, Princeton University
    xiaoqic [at] cs.princeton.edu
    
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


//== Preamble: macro, header and parser definitions

#define _OAT(act) table tb_## act {  \
            actions = {act;}                 \
            default_action = act();          \
            size = 1;               \
        }

#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_h {
    bit<3>  pri;
    bit<1>  cfi;
    bit<12> vlan_id;
    bit<16> etherType;
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
    vlan_h vlan;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

header resubmit_data_64bit_t {
    //size is 64, same as port meta
    bit<8> min_stage;
    bit<8> data_1;
    bit<16> data_2;
    bit<32> _padding;
}

header resubmit_data_skimmed_t {
    bit<8> min_stage;
    bit<8> data_1;
    bit<16> data_2;
}


@pa_container_size("ingress","ig_md.flow_id_part_1",32)
@pa_container_size("ingress","ig_md.flow_id_part_2",32)
@pa_container_size("ingress","ig_md.flow_id_part_3",32)
@pa_container_size("ingress","ig_md.flow_id_part_4",32)
@pa_container_size("ingress","ig_md.resubmit_data_read.min_stage",8)
@pa_container_size("ingress","ig_md.resubmit_data_write.min_stage",8)
struct ig_metadata_t {
    resubmit_data_64bit_t resubmit_data_read;
    resubmit_data_skimmed_t resubmit_data_write;
    
    //128bit flowID
    bit<32> flow_id_part_1;
    bit<32> flow_id_part_2;
    bit<32> flow_id_part_3;
    bit<32> flow_id_part_4;
    
    //register index to access (hash of flow ID, with different hash functions)
    bit<16> stage_1_loc;
    bit<16> stage_2_loc;
    //hash seeds, different width
    bit<3> hash_seed_1;
    bit<5> hash_seed_2;
    
    //is flowID matched register entry?
    bit<8> fid_matched_1_1;
    bit<8> fid_matched_1_2;
    bit<8> fid_matched_1_3;
    bit<8> fid_matched_1_4;
    bit<8> fid_matched_2_1;
    bit<8> fid_matched_2_2;
    bit<8> fid_matched_2_3;
    bit<8> fid_matched_2_4;
    
    bool matched_at_stage_1;
    bool matched_at_stage_2;
    
    //if so, we need to carry current count, and remember c_min/min_stage
    bit<32> counter_read_1;
    bit<32> counter_read_2;
    //bit<32> counter_incr;//you have a match, this is incremented value
    bit<32> c_min;
    bit<32> diff;
    
    //need some entropy for random coin flips!
    bit<32> entropy_long;
    bit<12> entropy_short;
}
struct eg_metadata_t {
}

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
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
        pkt.advance(64);  //tofino 1
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
            ETHERTYPE_VLAN: parse_vlan;
            default : reject;
        }
    }
    
    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: reject;
        }
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
         
    Resubmit() resubmit;
    
    apply {

        if (ig_intr_dprsr_md.resubmit_type == 1) {
            resubmit.emit(ig_md.resubmit_data_write);
        }
        
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
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


// == Start of control logic
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
            //route to CPU NIC. on model, it is veth250
            ig_intr_tm_md.ucast_egress_port=64;
        }

// == Calculate flow ID for the packet

        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;
        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_2;
        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_3;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_1;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_2;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_3;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_4;
        
        action copy_flow_id_common_1_(){
            ig_md.flow_id_part_1=hdr.ipv4.src_addr;//copy32_1.get({hdr.ipv4.src_addr});
        }
        action copy_flow_id_common_2_(){
            ig_md.flow_id_part_2=hdr.ipv4.dst_addr;//copy32_2.get({hdr.ipv4.dst_addr});
        }
        action copy_flow_id_common_3_(){
            //16+16bit ports
            //ig_md.flow_id_part_4[7:0]=hdr.ipv4.protocol;
            //ig_md.flow_id_part_4[8+12-1:8]=hdr.vlan.vlan_id;
            ig_md.flow_id_part_4=copy32_3.get({hdr.ipv4.protocol, hdr.vlan.vlan_id, 12w0});//12+8=20bit, remaining 12bit
        }
        action copy_flow_id_tcp(){
            ig_md.flow_id_part_3[15:0]=hdr.tcp.src_port;//copy16_1.get({hdr.tcp.src_port});
            ig_md.flow_id_part_3[31:16]=hdr.tcp.dst_port;//copy16_2.get({hdr.tcp.dst_port});
        }
        action copy_flow_id_udp(){
            ig_md.flow_id_part_3[15:0]=hdr.udp.src_port;//copy16_3.get({hdr.udp.src_port});
            ig_md.flow_id_part_3[31:16]=hdr.udp.dst_port;//copy16_4.get({hdr.udp.dst_port});
        }
        action copy_flow_id_unknown(){
            ig_md.flow_id_part_3=0;
        }
        _OAT(copy_flow_id_common_1_)
        _OAT(copy_flow_id_common_2_)
        _OAT(copy_flow_id_common_3_)
            
// == Calculate array indices for array access

        Hash<bit<16>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(16w0x8005,false,false,false,0,0)) hash1;
        Hash<bit<16>>(HashAlgorithm_t.CRC16, CRCPolynomial<bit<16>>(16w0x3D65,false,false,false,0,0)) hash2;
        //Hash<bit<16>>(HashAlgorithm_t.CRC32) hash3;
        //possible polynomials in standards:
        //0x8005,0x0589,0x3D65,0x1021,0x8BB7,0xA097
        
        action get_hashed_locations_1_(){
            ig_md.stage_1_loc=(bit<16>) hash1.get({
                ig_md.hash_seed_1,
                ig_md.flow_id_part_1,
                3w0,
                ig_md.flow_id_part_2,
                3w0,
                ig_md.flow_id_part_3,
                ig_md.flow_id_part_4
            });
        }
        action get_hashed_locations_2_(){
            ig_md.stage_2_loc=(bit<16>) hash2.get({
                ig_md.hash_seed_2,
                ig_md.flow_id_part_1,
                2w0,
                ig_md.flow_id_part_2,
                2w0,
                ig_md.flow_id_part_3,
                1w0,
                ig_md.flow_id_part_4
            });
        }
        _OAT(get_hashed_locations_1_)
        //this can be later...
        _OAT(get_hashed_locations_2_)
        
        action init_hash_seed(bit<3> v1, bit<5> v2, bit<7> v3){
            ig_md.hash_seed_1=v1;
            ig_md.hash_seed_2=v2;
        }
        table tb_init_hash_seed {
            actions = {
                init_hash_seed;
            }
            default_action = init_hash_seed(3w2,5w17,7w71);
        }
        //enables re-seeding from control plane
        

// == Register arrays for the stateful data structure

        Register<bit<32>,_>(32w65536) reg_flowid_1_1_R;
        Register<bit<32>,_>(32w65536) reg_flowid_1_2_R;
        Register<bit<32>,_>(32w65536) reg_flowid_1_3_R;
        Register<bit<32>,_>(32w65536) reg_flowid_1_4_R;
        Register<bit<32>,_>(32w65536) reg_counter_1_R;
        Register<bit<32>,_>(32w65536) reg_flowid_2_1_R;
        Register<bit<32>,_>(32w65536) reg_flowid_2_2_R;
        Register<bit<32>,_>(32w65536) reg_flowid_2_3_R;
        Register<bit<32>,_>(32w65536) reg_flowid_2_4_R;
        Register<bit<32>,_>(32w65536) reg_counter_2_R;
        
        
        // Define read/write actions for each flowID array
        #define RegAct_FlowID(st,pi) \
        RegisterAction<bit<32>, _, bit<8>>(reg_flowid_## st ##_## pi ##_R) stage_## st ##_fid_match_## pi ##_RA= {  \
            void apply(inout bit<32> value, out bit<8> rv) {          \
                rv = 0;                                                    \
                bit<32> in_value;                                          \
                in_value = value;                                          \
                if(in_value==ig_md.flow_id_part_## pi ){                   \
                    rv = 1;}                                               \
            }                                                              \
        };                                                                 \
        \
        RegisterAction<bit<32>, _, bit<8>>(reg_flowid_## st ##_## pi ##_R) stage_## st ##_fid_write_## pi ##_RA= {  \
            void apply(inout bit<32> value, out bit<8> rv) {               \
                rv = 0;                                                    \
                bit<32> in_value;                                          \
                in_value = value;                                          \
                value=ig_md.flow_id_part_ ## pi;                           \
            }                                                                            \
        };                                                                               \
        action exec_stage_## st ##_fid_match_## pi ##_(){  ig_md.fid_matched_## st ##_## pi=stage_## st ##_fid_match_## pi ##_RA.execute(ig_md.stage_## st ##_loc);} \
        action exec_stage_## st ##_fid_write_## pi ##_(){ stage_## st ##_fid_write_## pi ##_RA.execute(ig_md.stage_## st ##_loc);}                                          \
        //done
        
        RegAct_FlowID(1,1)
        RegAct_FlowID(1,2)
        RegAct_FlowID(1,3)
        RegAct_FlowID(1,4)
        RegAct_FlowID(2,1)
        RegAct_FlowID(2,2)
        RegAct_FlowID(2,3)
        RegAct_FlowID(2,4)
        
        _OAT(exec_stage_1_fid_match_1_)
        _OAT(exec_stage_1_fid_write_1_)
        _OAT(exec_stage_1_fid_match_2_)
        _OAT(exec_stage_1_fid_write_2_)
        _OAT(exec_stage_1_fid_match_3_)
        _OAT(exec_stage_1_fid_write_3_)
        _OAT(exec_stage_1_fid_match_4_)
        _OAT(exec_stage_1_fid_write_4_)
        _OAT(exec_stage_2_fid_match_1_)
        _OAT(exec_stage_2_fid_write_1_)
        _OAT(exec_stage_2_fid_match_2_)
        _OAT(exec_stage_2_fid_write_2_)
        _OAT(exec_stage_2_fid_match_3_)
        _OAT(exec_stage_2_fid_write_3_)
        _OAT(exec_stage_2_fid_match_4_)
        _OAT(exec_stage_2_fid_write_4_)
        
        
        action set_matched_at_stage_1_(){
            ig_md.matched_at_stage_1=true;
        }
        action set_matched_at_stage_2_(){
            ig_md.matched_at_stage_2=true;
        }
        _OAT(set_matched_at_stage_1_)
        _OAT(set_matched_at_stage_2_)
        
        // Define stateful actions for matching flow ID
        #define RegAct_Counter(st) \
        RegisterAction<bit<32>, _, bit<32>>(reg_counter_## st  ##_R) stage_## st ##_counter_read = {  \
            void apply(inout bit<32> value, out bit<32> rv) {          \
                rv = 0;                                               \
                bit<32> in_value;                                     \
                in_value = value;                                     \
                rv = value;                                           \
            }                                                                            \
        };                                                                               \
        action exec_stage_## st ##_counter_read(){  ig_md.counter_read_## st =stage_## st ##_counter_read.execute(ig_md.stage_## st ##_loc);} \
        RegisterAction<bit<32>, _, bit<32>>(reg_counter_## st  ##_R) stage_## st ##_counter_incr = {  \
            void apply(inout bit<32> value, out bit<32> rv) {          \
                rv = 0;                                               \
                bit<32> in_value;                                     \
                in_value = value;                                     \
                value = in_value+1;                                   \
                rv = value;                                           \
            }                                                                            \
        };                                                                               \
        action exec_stage_## st ##_counter_incr(){  ig_md.counter_read_## st =stage_## st ##_counter_incr.execute(ig_md.stage_## st ##_loc);} \
        //done
        
        RegAct_Counter(1)
        RegAct_Counter(2)
        _OAT(exec_stage_1_counter_read)
        _OAT(exec_stage_1_counter_incr)
        _OAT(exec_stage_2_counter_read)
        _OAT(exec_stage_2_counter_incr)

// == Randomization, for running Probabilistic Recirculation

        Random<bit<32>>() rng1;
        Random<bit<12>>() rng2;
        action get_randomness_1_(){
            ig_md.entropy_long=rng1.get();
        }
        action get_randomness_2_(){
            ig_md.entropy_short=rng2.get();
        }
        _OAT(get_randomness_1_)
        _OAT(get_randomness_2_)
        
        // Find out which stage has the minimum count.
        // We use a 32-bit register here for comparing two 32bit numbers
        Register<bit<32>,_>(32w32) dummy_reg1;
        Register<bit<32>,_>(32w32) dummy_reg2;
        RegisterAction<bit<32>, _, bit<32>>(dummy_reg1) get_min_stage = {
             void apply(inout bit<32> value, out bit<32> rv) {         
                rv = 0;                                               
                bit<32> in_value;                                     
                in_value = value;                                     
                if(ig_md.diff>0x7fffff){//negative
                    value=1;
                }
                else{
                    value=2;
                }
                if((bool) 1)
                    rv=value;
            }                             
        };
        action exec_get_min_stage() {
            ig_md.resubmit_data_write.min_stage=(bit<8>) get_min_stage.execute(0);
        }
        _OAT(exec_get_min_stage)
        
        action clear_resubmit_flag(){
            ig_intr_dprsr_md.resubmit_type = 0;
        }
        action clone_and_recirc_replace_entry(){
            //trigger resubmit
            ig_intr_dprsr_md.resubmit_type = 1;
        }
        
        // Approximate coin flip! See our paper for discussion of 1.125-approximation to coin flip probability. 
        // Section IV.D @ https://doi.org/10.1109/TNET.2020.2982739
        @stage(11)
        table better_approximation {
                // Goal: recirculate using probability 1/(2^x*T) nearest to 1/(carry_min+1), x between [1..63], T between [8..15]
                actions = {
                    NoAction();
                    clone_and_recirc_replace_entry();
                }
                key = {
                    ig_md.c_min: ternary;
                    ig_md.entropy_long: ternary;
                    ig_md.entropy_short: range;
                }
                size = 512;
                default_action = NoAction();
                const entries = {
        #include "entries_better_32.p4inc"
                }
            }
        
        #undef _OAT
        #define _OAT(act) tb_##act.apply()
        apply {
            //for debugging
            route_to_64();
            
            // === Preprocessing ===
            // Get flow ID
            _OAT(copy_flow_id_common_1_);
            _OAT(copy_flow_id_common_2_);
            _OAT(copy_flow_id_common_3_);
            
            if(hdr.tcp.isValid()){copy_flow_id_tcp();}
            else if(hdr.udp.isValid()){copy_flow_id_udp();}
            else {copy_flow_id_unknown();}
            
            // optional hash re-seeding 
            // tb_init_hash_seed.apply();
            
            // Get hashed locations based on flow ID
            _OAT(get_hashed_locations_1_);
            _OAT(get_hashed_locations_2_);
            
            
            // === Start of PRECISION stage counter logic ===
            
            
            // For normal packets, for each stage, we match flow ID, then increment or compute carry_min
            // to simplify program logic, we ignore a special case, where both slots are the same flow ID.
            // For resubmitted packet, just do write FID + INCR at the right stage.
            
            bool is_resubmitted=(bool) ig_intr_md.resubmit_flag;
            bit<8> resubmitted_min_stage=ig_md.resubmit_data_read.min_stage;
            
            // = Stage 1 match =
            
            if(!is_resubmitted){
                _OAT(exec_stage_1_fid_match_1_);
            }else if(is_resubmitted && resubmitted_min_stage==1){
                _OAT(exec_stage_1_fid_write_1_);
            }
            if(!is_resubmitted){
                _OAT(exec_stage_1_fid_match_2_);
            }else if(is_resubmitted && resubmitted_min_stage==1){
                _OAT(exec_stage_1_fid_write_2_);
            }

            if(!is_resubmitted){
                _OAT(exec_stage_1_fid_match_3_);
            }else if(is_resubmitted && resubmitted_min_stage==1){
                _OAT(exec_stage_1_fid_write_3_);
            }
            if(!is_resubmitted){
                _OAT(exec_stage_1_fid_match_4_);
            }else if(is_resubmitted && resubmitted_min_stage==1){
                _OAT(exec_stage_1_fid_write_4_);
            }
            
            //have a boolean alias, for immediate use in gateway table controlling stage 2 fid match
            bool matched_at_stage_1=((ig_md.fid_matched_1_1!=0) && 
               (ig_md.fid_matched_1_2!=0) && 
               (ig_md.fid_matched_1_3!=0) && 
               (ig_md.fid_matched_1_4!=0));
            //also have a boolean phv value, for longer gateway matches
            if(matched_at_stage_1)
            {
                _OAT(set_matched_at_stage_1_);
            }
            
            // = Stage 1 incr =            
            if(is_resubmitted && resubmitted_min_stage==1){
                _OAT(exec_stage_1_counter_incr);
            }else if(ig_md.matched_at_stage_1){
                _OAT(exec_stage_1_counter_incr);
            }else{
                _OAT(exec_stage_1_counter_read);
            }
            
            
            // = Stage 2 match =
            
            if(!is_resubmitted && !matched_at_stage_1){
                _OAT(exec_stage_2_fid_match_1_);
            }else if(is_resubmitted && resubmitted_min_stage==2){
                _OAT(exec_stage_2_fid_write_1_);
            }
            if(!is_resubmitted && !matched_at_stage_1){
                _OAT(exec_stage_2_fid_match_2_);
            }else if(is_resubmitted && resubmitted_min_stage==2){
                _OAT(exec_stage_2_fid_write_2_);
            }
            
            if(!is_resubmitted && !matched_at_stage_1){
                _OAT(exec_stage_2_fid_match_3_);
            }else if(is_resubmitted && resubmitted_min_stage==2){
                _OAT(exec_stage_2_fid_write_3_);
            }
            if(!is_resubmitted && !matched_at_stage_1){
                _OAT(exec_stage_2_fid_match_4_);
            }else if(is_resubmitted && resubmitted_min_stage==2){
                _OAT(exec_stage_2_fid_write_4_);
            }
            
             if((ig_md.fid_matched_2_1!=0) && 
                (ig_md.fid_matched_2_2!=0) && 
                (ig_md.fid_matched_2_3!=0) && 
                (ig_md.fid_matched_2_4!=0))
                {
                _OAT(set_matched_at_stage_2_);
                }
            
            // = Stage 2 incr =           
            if(is_resubmitted && resubmitted_min_stage==2){
                _OAT(exec_stage_2_counter_incr);
            }else if(ig_md.matched_at_stage_2){
                _OAT(exec_stage_2_counter_incr);
            }else{
                _OAT(exec_stage_2_counter_read);
            }
            
            // Always compute min_stage and c_min, even it's not useful
            ig_md.diff= ig_md.counter_read_1 - ig_md.counter_read_2;
            ig_md.resubmit_data_write.setValid();
            _OAT(exec_get_min_stage);
            
            //ig_md.c_min=min(ig_md.counter_read_1, ig_md.counter_read_2);
            if(ig_md.resubmit_data_write.min_stage==1){
                ig_md.c_min=ig_md.counter_read_1;
            }else if(ig_md.resubmit_data_write.min_stage==2){
                ig_md.c_min=ig_md.counter_read_2;
            }
            
            // prepare entropy
            _OAT(get_randomness_1_);
            _OAT(get_randomness_2_);
            
            clear_resubmit_flag();
            
            // === If none matched: choose your min stage, for recirculation (actually resubmit) ===
            if(!is_resubmitted && !ig_md.matched_at_stage_1 && !ig_md.matched_at_stage_2){
                //none matched
                //prepare for resubmit! 
                better_approximation.apply();
            }
            else if(is_resubmitted){
                // finished second pipeline pass. route as normal.
            }
            else if(ig_md.matched_at_stage_1){
                // matched with counter.
            }else if(ig_md.matched_at_stage_2){
                // matched with counter.
            } 
            
            
                
            if(ig_md.matched_at_stage_1){
                hdr.ethernet.dst_addr=(bit<48>)ig_md.counter_read_1;
            }else if(ig_md.matched_at_stage_2){
                hdr.ethernet.dst_addr=(bit<48>)ig_md.counter_read_2;
            }else{
                hdr.ethernet.dst_addr=0;
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

