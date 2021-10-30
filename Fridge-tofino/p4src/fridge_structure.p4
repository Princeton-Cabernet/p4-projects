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

// Fridge: data structure with insertion counter for unbiased measurement

#ifndef REG_SIZE
	#error "Please specify the size of fridge's underlying registers by defining REG_SIZE."
#endif
#ifndef ENTRY_PROB_LOG2
	#error "Please specify the fridge's entry probability by defining ENTRY_PROB_LOG2."
#endif

control Fridge<T_fid>(in T_fid fid, in bit<32> timestamp, in bool is_insert, out fridge_output_t fridge_output){
	// Insert fid into fridge, or query if fid exists in fridge

	// Entry probability implementations
	#if ENTRY_PROB_LOG2==0 //special case: p=1
	bit<1> entropy;
	action randomize(){
		entropy=0;
	}
	#else //p!=1
	Random< bit<ENTRY_PROB_LOG2> >() rng;
	bit<ENTRY_PROB_LOG2> entropy;
	action randomize(){
		entropy=rng.get();
	}
	#endif

	// Calculate hash-indexed addreses and 32-bit signature based on fid
	bit<32> pkt_signature;
	bit<16> hashed_location_1;
	Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16;
	Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32;
	action calc_signature(){
		pkt_signature=crc32.get({fid});
	}
	action calc_hashed_location(){
		hashed_location_1=crc16.get({fid});
	}

	// Insertion counter
	Register<bit<32>,_>(32w1) reg_ins_ctr;
	bit<32> ins_ctr;
	RegisterAction<bit<32>, _, bit<32>>(reg_ins_ctr) ins_ctr_add= {  
		void apply(inout bit<32> value, out bit<32> rv) { 
			value=value+1;
			rv = value;							   
		}								  
	};
	RegisterAction<bit<32>, _, bit<32>>(reg_ins_ctr) ins_ctr_read= {  
		void apply(inout bit<32> value, out bit<32> rv) {	  
			rv = value;	
		}								  
	};
	action exec_ins_ctr_add(){
		ins_ctr=ins_ctr_add.execute(0);
	}
	action exec_ins_ctr_read(){
		ins_ctr=ins_ctr_read.execute(0);
	}

	// The frirge consists of three arrays: signature(fid), timestamp, insertion counter
	Register<bit<32>,_>(REG_SIZE) array_signature;
	Register<bit<32>,_>(REG_SIZE) array_timestamp;
	Register<bit<32>,_>(REG_SIZE) array_insctr;
	bool array_read_signature_matched;
	bit<32> array_read_tsdiff;
	bit<32> array_read_insctrdiff;

	RegisterAction<bit<32>, _, bool>(array_signature) array_signature_write= {  
		void apply(inout bit<32> value, out bool rv) {	  
			value=pkt_signature;
			rv=false;
		}								  
	};
	RegisterAction<bit<32>, _, bool>(array_signature) array_signature_compare= {  
		void apply(inout bit<32> value, out bool rv) {	  
			if(value==pkt_signature){
				rv=true;
				value=0;//Also delete existing value
			}else{
				rv=false;
			}
		}								  
	};
	action exec_array_signature_write(){
		array_signature_write.execute(hashed_location_1);
	}
	action exec_array_signature_compare(){
		array_read_signature_matched=array_signature_compare.execute(hashed_location_1);
	}
	
	RegisterAction<bit<32>, _, bit<32>>(array_timestamp) array_timestamp_write= {  
		void apply(inout bit<32> value, out bit<32> rv) {	  
			value=timestamp;
			rv=0;
		}								  
	};
	RegisterAction<bit<32>, _, bit<32>>(array_timestamp) array_timestamp_readdiff= {  
		void apply(inout bit<32> value, out bit<32> rv) {	  
			rv=timestamp-value;
		}								  
	};
	action exec_array_timestamp_write(){
		array_timestamp_write.execute(hashed_location_1);
	}
	action exec_array_timestamp_readdiff(){
		array_read_tsdiff=array_timestamp_readdiff.execute(hashed_location_1);
	}
	
	RegisterAction<bit<32>, _, bit<32>>(array_insctr) array_insctr_write= {  
		void apply(inout bit<32> value, out bit<32> rv) {	  
			value=ins_ctr;
			rv=0;
		}								  
	};
	RegisterAction<bit<32>, _, bit<32>>(array_insctr) array_insctr_readdiff= {  
		void apply(inout bit<32> value, out bit<32> rv) {	  
			rv=ins_ctr-value;
		}								  
	};
	action exec_array_insctr_write(){
		array_insctr_write.execute(hashed_location_1);
	}
	action exec_array_insctr_readdiff(){
		array_read_insctrdiff=array_insctr_readdiff.execute(hashed_location_1);
	}

	apply {
		randomize();
		calc_signature();
		calc_hashed_location();
		fridge_output.query_successful=0;
		if(is_insert && (entropy==0)){
			//insert w.p. p=2^-ENTRY_PROB_LOG2
			exec_ins_ctr_add();	
			exec_array_signature_write();
			exec_array_timestamp_write();
			exec_array_insctr_write();
		}else{
			//is query
			exec_ins_ctr_read();
			exec_array_signature_compare();
			if(array_read_signature_matched){
				exec_array_timestamp_readdiff();
				exec_array_insctr_readdiff();
				fridge_output.query_successful=1;
				fridge_output.survival_cnt=array_read_insctrdiff;
				fridge_output.delay=array_read_tsdiff;
			}
		}	
	}
}
