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

// Calculate the expected ACK number of an outgoing TCP packet

#include "headers.h"

control Calc_Tcp_Eack(in header_t hdr, out bit<32> eack){
	bit<32> tmp_1;
	bit<32> tmp_2;
	bit<32> tmp_3;
	bit<32> total_hdr_len_bytes;
	bit<32> total_body_len_bytes;
	//force allocation to different stages using action(){...}
	action step1a(){
		@in_hash{ tmp_1= (bit<32>) (hdr.ipv4.ihl ++ 2w0); }
	}
	action step1b(){
		@in_hash{ tmp_2= (bit<32>) (hdr.tcp.data_offset ++ 2w0); }	
	}
	action step1c(){
		tmp_3=16w0 ++ hdr.ipv4.total_len;
	}
	action step2(){
		total_hdr_len_bytes=tmp_1+tmp_2;
	}
	action step3(){
		total_body_len_bytes=tmp_3 - total_hdr_len_bytes;
	}
	action step4(){
		eack=hdr.tcp.seq_no + total_body_len_bytes;
	}
	
	apply{
		if(hdr.tcp.isValid()){
			step1a();step1b();step1c();
			step2();
			step3();
			step4();
			if(hdr.tcp.flags==TCP_FLAGS_S){
				eack=eack+1;
			}
		}else{
			eack=0;
		}
	}
}
