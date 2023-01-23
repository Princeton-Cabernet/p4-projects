// vim: syntax=P4
/*
	SipHash-2-4 Ingress-only
	Copyright (C) 2021 Sophia Yoo & Xiaoqi Chen, Princeton University
	sophiayoo [at] princeton.edu
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

// supported input lengths: 1~4 words.
#ifndef NUM_WORDS
	#define NUM_WORDS 4
#endif

#define SIP_PORT 5555
#define SIP_KEY_0 ((bit<64>) 0x0706050403020100)
#define SIP_KEY_1 ((bit<64>) 0x0f0e0d0c0b0a0908)
const bit<64> const_0 = 0x736f6d6570736575;
const bit<64> const_1 = 0x646f72616e646f6d;
const bit<64> const_2 = 0x6c7967656e657261;
const bit<64> const_3 = 0x7465646279746573;

#define ROUND_TYPE_COMPRESSION 0
#define ROUND_TYPE_FINALIZATION 1
#define ROUND_TYPE_END 2

#include "loops_macro.h"

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

header sip_inout_h {
	#define vardef_m(i) bit<64> m_##i;
	__LOOP(NUM_WORDS, vardef_m)
}

header sip_meta_h {
	bit<64> v_0;
	bit<64> v_1;
	bit<64> v_2;
	bit<64> v_3;
	bit<16> dest_port;
	bit<8> curr_round;
}

struct header_t {
	ethernet_h ethernet;
	sip_inout_h sip;
	sip_meta_h sip_meta;
	ipv4_h ipv4;
	tcp_h tcp;
	udp_h udp;
}

header sip_tmp_h {
	bit<64> a_0;
	bit<64> a_1;
	bit<64> a_2;
	bit<64> a_3;
	bit<64> i_0;
	bit<64> hval;
	bit<8> round_type;
}

struct ig_metadata_t {
	bool recirc;
	bit<9> rnd_port_for_recirc;
	bit<1> rnd_bit;
	sip_tmp_h sip_tmp;
}

struct eg_metadata_t {
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
			default : reject;
		}
	}

	state parse_sip {
		pkt.extract(hdr.sip);
		transition accept;
	}

	state parse_sip_and_meta {
		pkt.extract(hdr.sip);
		pkt.extract(hdr.sip_meta);
		transition accept;
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
			SIP_PORT: parse_sip;
			SIP_PORT+1: parse_sip_and_meta;
			default: accept;
		}
	}
}

control SwitchIngressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.sip);
		pkt.emit(hdr.sip_meta);
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

control SwitchIngress(
		inout header_t hdr,
		inout ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

	action drop(){
		ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
	}

	action nop() {
	}

	action routing_decision(){
		//packet routing: for now we simply bounce back the packet.
		//any routing match-action logic should be added here.
		hdr.sip_meta.dest_port=(bit<16>) ig_intr_md.ingress_port;
	}

	action route_to(bit<9> port){
		ig_intr_tm_md.ucast_egress_port=port;
	}

	//select one of two ports for recirculation
	Random< bit<1> >() rng;

	action get_rnd_bit(){
		ig_md.rnd_bit = rng.get();
		//ig_md.rnd_bit = ig_intr_md.ingress_mac_tstamp[0:0];
	}
	
	action do_recirculate(){
		route_to(ig_md.rnd_port_for_recirc);
	}

	action incr_and_recirc(bit<8> next_round){
		hdr.sip_meta.curr_round = next_round;
		do_recirculate();
		//hdr.sip_meta.setValid();
		hdr.udp.dst_port=SIP_PORT+1;
	}

	action do_not_recirc(){
		route_to((bit<9>)hdr.sip_meta.dest_port);
		hdr.udp.dst_port=SIP_PORT;
		#define writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,writeout_m)
		
		ig_md.sip_tmp.round_type = ROUND_TYPE_END; 
		//@in_hash { hdr.sip.m_0 = hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3; }
		//use pre-computed result
		hdr.sip.m_0 = ig_md.sip_tmp.hval; 

		hdr.sip_meta.setInvalid();
	}

	table tb_recirc_decision {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		actions = {
			incr_and_recirc;
			do_not_recirc;
			nop;
		}
		size = 20;
		default_action = nop;
		const entries = {
			//(0): incr_and_recirc(1);
			//total rounds: w*2+4, only last round no recirc
			
			//compression rounds w*2
			#define rule_incr_one(i) (i): incr_and_recirc(i+1);
			#define allrules(n) __LOOP( n, rule_incr_one)
			//for i in range(0,2*n):
			__MUL(2, NUM_WORDS, allrules)
			
			//finalization rounds
			(NUM_WORDS*2+0): incr_and_recirc(NUM_WORDS*2+1);
			(NUM_WORDS*2+1): incr_and_recirc(NUM_WORDS*2+2);
			(NUM_WORDS*2+2): incr_and_recirc(NUM_WORDS*2+3);
			(NUM_WORDS*2+3): do_not_recirc();
		}
	}
	

	action sip_init(bit<64> key_0, bit<64> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
	}
	
	#define MSG_VAR ig_md.sip_tmp.i_0

	action sip_preround_1(){
		@in_hash{ hdr.sip_meta.v_3[63:32] = hdr.sip_meta.v_3[63:32] ^ MSG_VAR[63:32]; }
	}
	action sip_preround_2(){
		@in_hash{ hdr.sip_meta.v_3[31:0] = hdr.sip_meta.v_3[31:0] ^ MSG_VAR[31:0]; }
	}
	
	action sip_1_a1(){
		//a_0 = i_0 + i_1
		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 13
		//@in_hash { ig_md.sip_tmp.a_1 = hdr.sip_meta.v_1[50:0] ++ hdr.sip_meta.v_1[63:51]; }
		@in_hash { ig_md.sip_tmp.a_1[63:32] = hdr.sip_meta.v_1[50:19]; }
	}
	action sip_1_a2(){
		@in_hash { ig_md.sip_tmp.a_1[31:0] = hdr.sip_meta.v_1[18:0] ++ hdr.sip_meta.v_1[63:51]; }
	}
	action sip_1_b1(){
		//a_3 = i_3 << 16
		//@in_hash { ig_md.sip_tmp.a_3 = hdr.sip_meta.v_3[47:0] ++ hdr.sip_meta.v_3[63:48]; }
		@in_hash { ig_md.sip_tmp.a_3[63:32]=hdr.sip_meta.v_3[47:16]; }
	}
	action sip_1_b2(){
		@in_hash { ig_md.sip_tmp.a_3[31: 0]=hdr.sip_meta.v_3[15:0] ++ hdr.sip_meta.v_3[63:48]; }
	}
	
	action sip_2_a1(){
		//b_1 = a_1 ^ a_0
		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_2;
		//b_0 = a_0 << 32
		//ig_md.sip_tmp.i_0 = ig_md.sip_tmp.a_0[31:0] ++ ig_md.sip_tmp.a_0[63:32];
		@in_hash{ hdr.sip_meta.v_0[63:32] = ig_md.sip_tmp.a_0[31:0]; }
		//b_2 = a_2
		hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2;
	}
	action sip_2_a2(){
		@in_hash{ hdr.sip_meta.v_0[31:0] = ig_md.sip_tmp.a_0[63:32]; }
	}

 
	action sip_3_a1(){
		//c_2 = b_2 + b_1
		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_1;
		//c_0 = b_0 + b_3
		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_3;
		//c_1 = b_1 << 17
		//@in_hash { ig_md.sip_tmp.a_1 = ig_md.sip_tmp.i_1[46:0] ++ ig_md.sip_tmp.i_1[63:47]; }
		@in_hash { ig_md.sip_tmp.a_1[63:32] = hdr.sip_meta.v_1[46:15]; }
	}
	action sip_3_a2(){
		@in_hash { ig_md.sip_tmp.a_1[31:0] = hdr.sip_meta.v_1[14:0] ++ hdr.sip_meta.v_1[63:47]; }
	} 
   
	action sip_3_b1(){
		//c_3 = b_3 << 21
		//@in_hash { ig_md.sip_tmp.a_3 = ig_md.sip_tmp.i_3[42:0] ++ ig_md.sip_tmp.i_3[63:43]; }
		@in_hash {ig_md.sip_tmp.a_3[63:32] = hdr.sip_meta.v_3[42:11];}
	}
	action sip_3_b2(){
		@in_hash { ig_md.sip_tmp.a_3[31:0] = hdr.sip_meta.v_3[10:0] ++ hdr.sip_meta.v_3[63:43]; }
	}


	action sip_4_a1(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_0;
		//d_2 = c_2 << 32
		//hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2[31:0] ++ ig_md.sip_tmp.a_2[63:32];
		@in_hash{ hdr.sip_meta.v_2[63:32]=ig_md.sip_tmp.a_2[31:0]; }
	}
	action sip_4_a2(){
		@in_hash{ hdr.sip_meta.v_2[31:0]=ig_md.sip_tmp.a_2[63:32]; }
	}
	
	action sip_postround_1(){
		@in_hash{ hdr.sip_meta.v_0[63:32] = ig_md.sip_tmp.a_0[63:32] ^ MSG_VAR[63:32]; }
	}
	action sip_postround_2(){
		@in_hash{ hdr.sip_meta.v_0[31:0] = ig_md.sip_tmp.a_0[31:0] ^ MSG_VAR[31:0]; }
	}
	
	action sip_speculate_end_1(){
			@in_hash{ ig_md.sip_tmp.hval[63:32] = hdr.sip_meta.v_0[63:32] ^  hdr.sip_meta.v_1[63:32]^  hdr.sip_meta.v_2[63:32]^  hdr.sip_meta.v_3[63:32]; }
	}
	action sip_speculate_end_2(){
			@in_hash{ ig_md.sip_tmp.hval[31:0] = hdr.sip_meta.v_0[31:0] ^ hdr.sip_meta.v_1[31:0] ^ hdr.sip_meta.v_2[31:0] ^ hdr.sip_meta.v_3[31:0]; }
	}

	// round 0~(2*NUM_WORDS-1)
	#define def_start_m(i) action start_m_## i ##_compression(){\
		ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR = hdr.sip.m_## i; 								\
	}
	__LOOP(NUM_WORDS,def_start_m)

	action start_nop(){
		MSG_VAR=0;
	}
	//round 2*NUM_WORDS (first finalization round)
	action start_finalization_first(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR = 0;
		// also xor v2 with FF at beginning of the first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 64w0xff;
	}
	//round 2*NUM_WORDS +1 ~ +3 (last 3 finalization rounds)
	action start_finalization_else(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR = 0;
	}

	table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define actname_start_m(i) start_m_## i ##_compression;
			__LOOP(NUM_WORDS, actname_start_m)
			start_nop;
			start_finalization_first;
			start_finalization_else;
		}
		const entries = {
			// note: (0) is actually handled by start_first_pass()
			#define match_start_m(i) (i*2): start_m_## i ##_compression();
			__LOOP(NUM_WORDS, match_start_m)
			
			// note: odd round has compression, even round does not
			#define match_start_even_m(i) (i*2+1): start_nop();
			__LOOP(NUM_WORDS, match_start_even_m)
			
			(NUM_WORDS*2): start_finalization_first();
			(NUM_WORDS*2+1): start_finalization_else();
			(NUM_WORDS*2+2): start_finalization_else();
			(NUM_WORDS*2+3): start_finalization_else();
		}
	}

	#define def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,def_pre_end_m)

	action pre_end_nop(){
		MSG_VAR=0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define actname_pre_end_m(i) pre_end_m_## i ##_compression;
			__LOOP(NUM_WORDS, actname_pre_end_m)
			pre_end_nop;

		}
		const entries = {
			#define match_pre_end_m(i) (i*2+1): pre_end_m_## i ##_compression();
			__LOOP(NUM_WORDS, match_pre_end_m)
			
			// note: even round has no ending compression
			#define match_pre_end_even_m(i) (i*2): pre_end_nop();
			__LOOP(NUM_WORDS, match_pre_end_even_m)
			
			// 4 rounds of finalization, msg=0
			(NUM_WORDS*2): pre_end_nop();
			(NUM_WORDS*2+1): pre_end_nop();
			(NUM_WORDS*2+2): pre_end_nop();
			(NUM_WORDS*2+3): pre_end_nop();
		}
	}

	
	action start_first_pass(){
		//first pass init
		hdr.sip_meta.setValid();
		hdr.sip_meta.curr_round=0;

		sip_init(SIP_KEY_0, SIP_KEY_1);
		start_m_0_compression();

		routing_decision();
	}
	

	apply {
		// check for valid sip data
		bool is_sip = hdr.sip.isValid();
		if(!is_sip){
			drop();
			exit;
		}
		else{
			//logic check for first pass
			if(!hdr.sip_meta.isValid()){
				start_first_pass();
			}
			else
				tb_start_round.apply();
		}
	
		//compression xor msg, only for odd rounds
		//note: for finalization rounds msg is zero, no effect	
		//v3^=m
		sip_preround_1();
		sip_preround_2();
		//SipRound
		sip_1_a1();
		sip_1_a2();
		sip_1_b1();
		sip_1_b2(); 
		sip_2_a1();
		sip_2_a2();
		sip_3_a1();
		sip_3_a2();
		sip_3_b1();
		sip_3_b2();
		sip_4_a1();
		sip_4_a2();
		tb_pre_end.apply(); 
		//compression xor msg, only for even rounds
		//v0^=m
		sip_postround_1();
		sip_postround_2();

		sip_speculate_end_1();
		sip_speculate_end_2();

		// randomly choose a recirculation port
		get_rnd_bit();
		if (ig_md.rnd_bit == 0){
			ig_md.rnd_port_for_recirc = 68;
		} else{
			ig_md.rnd_port_for_recirc = 68 + 128;
		}
		
		tb_recirc_decision.apply();
		
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