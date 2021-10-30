/*
	Unbiased delay measurement in the data plane
	Copyright (C) 2021 Xiaoqi Chen, Princeton University
	
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

// Main program of measuring delay distributions, using a fridge to match SYN and SYN-ACK packets

#include <core.p4>
#include <tna.p4>

//== Headers
#include "headers.h"
//== Metadata variables
#include "metadata.h"
//== Parsers and Deparsers
#include "parsers.h"

//== Modules
#include "calc_tcp_eack.p4"
#include "fridge_structure.p4"
#include "tally_histogram.p4"

// == Actual control logic
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
	action reflect(){
		ig_intr_tm_md.ucast_egress_port=ig_intr_md.ingress_port; //send you back to where you're from
	}

	Calc_Tcp_Eack() calc_eack;
	Fridge<bit<128> >() fridge;

	apply {
		bit<32> eack;
		calc_eack.apply(hdr, eack);

		bit<32> timestamp=ig_intr_md.ingress_mac_tstamp[41:10]; 
		
		//in this prototype, only measure handshake RTT delay
		if(hdr.tcp.isValid() && hdr.tcp.flags==TCP_FLAGS_S){
			//insert TCP SYN with expected ACK number
			bit<128> fid=hdr.ipv4.src_addr++hdr.ipv4.dst_addr++hdr.tcp.src_port++hdr.tcp.dst_port   ++   eack; 
			const bool is_insert=true;	
			fridge.apply(fid,timestamp,is_insert,ig_md.fridge_output);
		}else if(hdr.tcp.isValid() && hdr.tcp.flags==TCP_FLAGS_S+TCP_FLAGS_A){
			//query upon SYN-ACK, reversed flow ID
			bit<128> fid=hdr.ipv4.dst_addr++hdr.ipv4.src_addr++hdr.tcp.dst_port++hdr.tcp.src_port  ++  hdr.tcp.ack_no;
			const bool is_insert=false;	
			fridge.apply(fid,timestamp,is_insert,ig_md.fridge_output);
		}

		//send digest to control plane if query successful
		//if(ig_md.fridge_output.query_successful){
		//	ig_intr_dprsr_md.digest_type = 1;
		//}	
		//let deparser read ig_md.fridge_output.query_successful directly, saves one stage

		//send packet back to sender
		reflect();
	}
}

control SwitchEgress(
		inout header_t hdr,
		inout eg_metadata_t eg_md,
		in egress_intrinsic_metadata_t eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
		inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
	Tally_Histogram() tally_histogram;
	apply {
		if(eg_md.fridge_output.query_successful==1){
			tally_histogram.apply(eg_md.fridge_output);
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
