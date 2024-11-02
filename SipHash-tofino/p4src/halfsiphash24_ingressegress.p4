// vim: syntax=P4
/*
    HalfSipHash-2-4 Ingress+Egress

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

// supported input lengths: 2~8 words.
#ifndef NUM_WORDS
    #define NUM_WORDS 4
    #define NUM_WORDS_IG 2
    #define NUM_WORDS_EG 2
#endif
#if !((NUM_WORDS_IG+NUM_WORDS_EG==NUM_WORDS) && (NUM_WORDS_IG-NUM_WORDS_EG==0 || NUM_WORDS_IG-NUM_WORDS_EG==1 ))
	#error "Please set NUM_WORDS_IG to be floor((NUM_WORDS+1)/2) and NUM_WORDS_EG to be floor((NUM_WORDS)/2)."
#endif

#define SIP_PORT 5555
#define SIP_KEY_0 0x33323130
#define SIP_KEY_1 0x42413938
const bit<32> const_0 = 0;
const bit<32> const_1 = 0;
const bit<32> const_2 = 0x6c796765;
const bit<32> const_3 = 0x74656462;

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
	#define vardef_m(i) bit<32> m_##i;
	__LOOP(NUM_WORDS, vardef_m)
}

header sip_meta_h {
	bit<32> v_0;
	bit<32> v_1;
	bit<32> v_2;
	bit<32> v_3;
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
	bit<32> a_0;
	bit<32> a_1;
	bit<32> a_2;
	bit<32> a_3;
	bit<32> i_0;
	bit<32> i_1;
	bit<32> i_2;
	bit<32> i_3;
	bit<8> round_type;
}

struct ig_metadata_t {
	bool recirc;
	bit<9> rnd_port_for_recirc;
	bit<1> rnd_bit;
	sip_tmp_h sip_tmp;
}

struct eg_metadata_t {
	sip_tmp_h sip_tmp;
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

parser TofinoEgressParser(
		packet_in pkt,
		out egress_intrinsic_metadata_t eg_intr_md) {

	state start {
		pkt.extract(eg_intr_md);
		transition accept;
	}
}
parser SwitchEgressParser(
		packet_in pkt,
		out header_t hdr,
		out eg_metadata_t eg_md,
		out egress_intrinsic_metadata_t eg_intr_md) {

	TofinoEgressParser() tofino_parser;

	state start {
		tofino_parser.apply(pkt, eg_intr_md);
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

control SwitchEgressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.sip);
		pkt.emit(hdr.sip_meta);
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

	action do_not_recirc_end_in_ig(){
		route_to((bit<9>)hdr.sip_meta.dest_port);
		hdr.udp.dst_port=SIP_PORT;
		#define ig_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,ig_writeout_m)
		@in_hash { hdr.sip.m_0 = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		hdr.sip_meta.setInvalid();
	}

	action do_not_recirc_end_in_eg(bit<8> next_round){
		route_to((bit<9>)hdr.sip_meta.dest_port);
		hdr.sip_meta.curr_round = next_round;
	}

	table tb_recirc_decision {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		actions = {
			incr_and_recirc;
			do_not_recirc_end_in_eg;
			do_not_recirc_end_in_ig;
			nop;
		}
		size = 32;
		default_action = nop;
		const entries = {
			// ingress performs round 0,4,8,...
			// even NUM_WORDS last round ends in egress, odd ends in ingress
			#define ig_rule_incr_m(i) (i*4): incr_and_recirc(i*4+2);
			#if (NUM_WORDS%2==0)
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2): do_not_recirc_end_in_eg(NUM_WORDS*2+2);
			#else
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2+2): do_not_recirc_end_in_ig();
			#endif
		}

	}
	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
        }

        #define MSG_VAR_IG ig_md.sip_tmp.i_0
	action sip_1_odd(){
		//for first SipRound in set of <c> SipRounds
		//i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_IG;
	}
	action sip_1_a(){
		//a_0 = i_0 + i_1
		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 5
		@in_hash { ig_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}
	action sip_1_b(){
		//a_3 = i_3 << 8
		ig_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];
	}
	action sip_2_a(){
		//b_1 = a_1 ^ a_0
		ig_md.sip_tmp.i_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		ig_md.sip_tmp.i_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		ig_md.sip_tmp.i_0 = ig_md.sip_tmp.a_0[15:0] ++ ig_md.sip_tmp.a_0[31:16];
		//b_2 = a_2
		ig_md.sip_tmp.i_2 = ig_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		//c_2 = b_2 + b_1
		ig_md.sip_tmp.a_2 = ig_md.sip_tmp.i_2 + ig_md.sip_tmp.i_1;
		//c_0 = b_0 + b_3
		ig_md.sip_tmp.a_0 = ig_md.sip_tmp.i_0 + ig_md.sip_tmp.i_3;
		//c_1 = b_1 << 13
		@in_hash { ig_md.sip_tmp.a_1 = ig_md.sip_tmp.i_1[18:0] ++ ig_md.sip_tmp.i_1[31:19]; }
	}
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { ig_md.sip_tmp.a_3 = ig_md.sip_tmp.i_3[24:0] ++ ig_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_0;
		//d_2 = c_2 << 16
		hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2[15:0] ++ ig_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		//d_0 = c_0
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		//d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0 ^ MSG_VAR_IG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define ig_def_start_m(i) action start_m_## i ##_compression(){\
		ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_IG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,ig_def_start_m)

	//round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_IG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	//round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_IG = 0;
	}

	table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define ig_actname_start_m_mul2(ix2) start_m_## ix2 ##_compression;
			#define ig_actname_start_m(i) __MUL(2,i, ig_actname_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_actname_start_m)
				start_finalization_a;
			#else
				__LOOP(NUM_WORDS_IG, ig_actname_start_m)
				start_finalization_b;
			#endif
		}
		const entries = {
			#define ig_match_start_m_mul2(ix2) (ix2*2): start_m_## ix2 ##_compression();
			#define ig_match_start_m(i)  __MUL(2,i, ig_match_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_match_start_m)
				(NUM_WORDS*2): start_finalization_a();
			#else
				__LOOP(NUM_WORDS_IG, ig_match_start_m)
				(NUM_WORDS*2+2): start_finalization_b();
			#endif
		}
	}

	#define ig_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_IG = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,ig_def_pre_end_m)
	action pre_end_finalization_a(){
		MSG_VAR_IG = 0;
	}
	action pre_end_finalization_b(){
		MSG_VAR_IG = 0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define ig_actname_pre_end_m_mul2(ix2) pre_end_m_## ix2 ##_compression;
			#define ig_actname_pre_end_m(i) __MUL(2,i, ig_actname_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_actname_pre_end_m)
				pre_end_finalization_a;
			#else
				__LOOP(NUM_WORDS_IG, ig_actname_pre_end_m)
				pre_end_finalization_b;
			#endif
		}
		const entries = {
			#define ig_match_pre_end_m_mul2(ix2) (ix2*2): pre_end_m_## ix2 ##_compression();
			#define ig_match_pre_end_m(i) __MUL(2,i, ig_match_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_match_pre_end_m)
				(NUM_WORDS*2): pre_end_finalization_a();
			#else
				__LOOP(NUM_WORDS_IG, ig_match_pre_end_m)
				(NUM_WORDS*2+2): pre_end_finalization_b();
			#endif
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

		//compression round: xor msg
		//note: for finalization rounds msg is zero, no effect
		//v3^=m
		sip_1_odd();
		//first SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		sip_4_a();
		sip_4_b_odd();
		//second SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		tb_pre_end.apply();
		sip_4_a();
		//v0^=m
		sip_4_b_even();

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
		inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

	action nop() {
	}

	action final_round_xor(){
		hdr.udp.dst_port=SIP_PORT;
		#define eg_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,eg_writeout_m)
		@in_hash { hdr.sip.m_0 = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		hdr.sip_meta.setInvalid();
	}

	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
	}

	#define MSG_VAR_EG eg_md.sip_tmp.i_0
	action sip_1_odd(){
		//for first SipRound in set of <c> SipRounds
		//i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_EG;
	}
	action sip_1_a(){
		//a_0 = i_0 + i_1
		eg_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		eg_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 5
		@in_hash { eg_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}
	action sip_1_b(){
		//a_3 = i_3 << 8
		eg_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];

	}
	action sip_2_a(){
		//b_1 = a_1 ^ a_0
		eg_md.sip_tmp.i_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		eg_md.sip_tmp.i_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		eg_md.sip_tmp.i_0 = eg_md.sip_tmp.a_0[15:0] ++ eg_md.sip_tmp.a_0[31:16];
		//b_2 = a_2
		eg_md.sip_tmp.i_2 = eg_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		//c_2 = b_2 + b_1
		eg_md.sip_tmp.a_2 = eg_md.sip_tmp.i_2 + eg_md.sip_tmp.i_1;
		//c_0 = b_0 + b_3
		eg_md.sip_tmp.a_0 = eg_md.sip_tmp.i_0 + eg_md.sip_tmp.i_3;
		//c_1 = b_1 << 13
		@in_hash { eg_md.sip_tmp.a_1 = eg_md.sip_tmp.i_1[18:0] ++ eg_md.sip_tmp.i_1[31:19]; }
	}
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { eg_md.sip_tmp.a_3 = eg_md.sip_tmp.i_3[24:0] ++ eg_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_0;
		//d_2 = c_2 << 16
		hdr.sip_meta.v_2 = eg_md.sip_tmp.a_2[15:0] ++ eg_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		//d_0 = c_0
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		//d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0 ^ MSG_VAR_EG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define eg_def_start_m(i) action start_m_## i ##_compression(){\
		eg_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_EG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,eg_def_start_m)

	//round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_EG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	//round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_EG = 0;
	}

	table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define eg_actname_start_m_mul2plus1(ix2p1) start_m_## ix2p1 ##_compression;
			#define eg_actname_start_m_mul2(ix2) __ADD(1,ix2,eg_actname_start_m_mul2plus1)
			#define eg_actname_start_m(i) __MUL(2,i, eg_actname_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_actname_start_m)
				start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_actname_start_m)
				start_finalization_a;
			#endif
		}
		const entries = {
			#define eg_match_start_m_mul2plus1(ix2p1) (ix2p1*2): start_m_## ix2p1 ##_compression();
			#define eg_match_start_m_mul2(ix2) __ADD(1,ix2,eg_match_start_m_mul2plus1)
			#define eg_match_start_m(i) __MUL(2,i, eg_match_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS+2): start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS): start_finalization_a;
			#endif
		}
	}

	#define eg_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_EG = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,eg_def_pre_end_m)
	action pre_end_finalization_a(){
		MSG_VAR_EG = 0;
	}
	action pre_end_finalization_b(){
		MSG_VAR_EG = 0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define eg_actname_pre_end_m_mul2plus1(ix2p1) pre_end_m_## ix2p1 ##_compression;
			#define eg_actname_pre_end_m_mul2(ix2) __ADD(1,ix2,eg_actname_pre_end_m_mul2plus1)
			#define eg_actname_pre_end_m(i) __MUL(2,i, eg_actname_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_actname_pre_end_m)
				start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_actname_pre_end_m)
				start_finalization_a;
			#endif
		}
		const entries = {
			#define eg_match_pre_end_m_mul2plus1(ix2p1) (ix2p1*2): pre_end_m_## ix2p1 ##_compression();
			#define eg_match_pre_end_m_mul2(ix2) __ADD(1,ix2,eg_match_pre_end_m_mul2plus1)
			#define eg_match_pre_end_m(i) __MUL(2,i, eg_match_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS+2): start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS): start_finalization_a;
			#endif
		}
	}

	apply {
		if(!hdr.sip_meta.isValid()){
			exit;
		}
		else
			tb_start_round.apply();

		//compression round: xor msg
		//note: for finalization rounds msg is zero, no effect//v3^=m
		sip_1_odd();
		//first SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		sip_4_a();
		sip_4_b_odd();
		//second SipRound
		sip_1_a();
		sip_1_b();
		sip_2_a();
		sip_3_a();
		sip_3_b();
		tb_pre_end.apply();
		sip_4_a();
		//v0^=m
		sip_4_b_even();

		if(hdr.sip_meta.curr_round < (NUM_WORDS*2+2)){
			//need more rounds in ingress pipeline, packet should be during recirculation right now
			hdr.sip_meta.curr_round = hdr.sip_meta.curr_round + 2;
		}else{
			final_round_xor();
		}
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
