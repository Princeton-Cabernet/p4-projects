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

// Tally Histogram: Use lookup table to calculate inverted survival probability, then maintain weighted sum of delay samples.

control Tally_Histogram(in fridge_output_t fridge_output){
	// We first calculate the "bin" index of the RTT, using base-2 logarithm
	bit<8> logDelay;
	action set_log(bit<8> l){
		logDelay=l;
	}
	// The actual table rules are range matches, the compiler shall convert them into TCAM rules
	// Split into two tables, so rules are shorter

	table tb_logDelay_lower {
		key = {
			fridge_output.delay[15:0] : range;
		}
		actions = {
			set_log;
		}
		default_action = set_log(0); //Delay is 0 means the lowest bin. 
		size=32;
		const entries = {
			(0..1): set_log(0);
			(2..3): set_log(1);
			(4..7): set_log(2);
			(8..15): set_log(3);
			(16..31): set_log(4);
			(32..63): set_log(5);
			(64..127): set_log(6);
			(128..255): set_log(7);
			(256..511): set_log(8);
			(512..1023): set_log(9);
			(1024..2047): set_log(10);
			(2048..4095): set_log(11);
			(4096..8191): set_log(12);
			(8192..16383): set_log(13);
			(16384..32767): set_log(14);
			(32768..65535): set_log(15);
		}
	}
	
	table tb_logDelay_upper {
		key = {
			fridge_output.delay[31:16] : range;
		}
		actions = {
			set_log;
		}
		default_action = set_log(31); //delayis 0 means invalid. should never be triggered.
		size=32;
		const entries = {
			(0..1): set_log(0+16);
			(2..3): set_log(1+16);
			(4..7): set_log(2+16);
			(8..15): set_log(3+16);
			(16..31): set_log(4+16);
			(32..63): set_log(5+16);
			(64..127): set_log(6+16);
			(128..255): set_log(7+16);
			(256..511): set_log(8+16);
			(512..1023): set_log(9+16);
			(1024..2047): set_log(10+16);
			(2048..4095): set_log(11+16);
			(4096..8191): set_log(12+16);
			(8192..16383): set_log(13+16);
			(16384..32767): set_log(14+16);
			(32768..65535): set_log(15+16);
		}
	}

	// We also calculate the correction factor using match-action rules
	bit<32> weight;
	action tally(bit<32> w){
		weight=w;	
	}
	
	table tb_tally_weight{
		key = {
			fridge_output.survival_cnt[19:0]: range;
		}
		actions = {
			tally;
		}
		default_action = tally(0); //count too big means invalid sample
		const entries = {
			#include "tally_correction_factor_entries.h"
		}
	}	
	
	// Accumulate the weights
	Register<bit<32>,_>(32w32) Delay_histogram;
	RegisterAction<bit<32>, _, bit<32>>(Delay_histogram) Delay_histogram_add={
		void apply(inout bit<32> value, out bit<32> rv) {
			value=value + weight;
			rv=value;
		}
	};
	action exec_Delay_histogram_add(){
			Delay_histogram_add.execute(logDelay);
	}

	apply {
		if(fridge_output.delay[31:16]==0){
			tb_logDelay_lower.apply();
		}else{
			tb_logDelay_upper.apply();
		}
		tb_tally_weight.apply();
		exec_Delay_histogram_add();
	}
}
