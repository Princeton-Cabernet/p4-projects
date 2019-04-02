/*
    AES-128 encryption in P4
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
#define COPYRIGHT_STRING 0xA9204147504c7633
//"© AGPLv3"


// Standard headers
#include <core.p4>
#include <v1model.p4>

// AES encryption lookup tables, to fill match-action entries at compile time. You may also fill it in at run time.
#ifndef EMPTY_LUT_FILL_AT_RUNTIME
	#include "LUT.h"
#else
	#define GEN_LUT0(FN) {}
	#define GEN_LUT1(FN) {}
	#define GEN_LUT2(FN) {}
	#define GEN_LUT3(FN) {}
	#define GEN_LUT_SBOX(FN) {}
#endif


// We define a special header type to pass in the cleartext & outut ciphertext
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

#define ETHERTYPE_AES_TOY 0x9999

// We perform one block of AES.
// To perform multiple block using modes like CBC/CTR, etc., simply XOR a counter/IV with value before starting AES.
header aes_inout_t {
    bit<128> value;
    bit<8> ff; // should be 0xFF.
}
header copyright_t {
	bit<64> value;
}

struct my_headers_t {
    ethernet_t   ethernet;
    aes_inout_t     aes_inout;
	copyright_t copy;
}

header aes_meta_t {
    // internal state, 4 rows
    bit<32> r0;
    bit<32> r1;
    bit<32> r2;
    bit<32> r3;
    // temporary accumulator, for XOR-ing the result of many LUTs
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;
}


struct my_metadata_t {
    aes_meta_t aes;
}

parser MyParser(
    packet_in                 packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_AES_TOY : parse_aes;
            default      : accept;
        }
    }

    state parse_aes {
        packet.extract(hdr.aes_inout);
        transition accept;
    }
}

control MyVerifyChecksum(inout my_headers_t hdr, inout my_metadata_t meta) {
    apply { }
}

control MyIngress(
    inout my_headers_t     hdr,
    inout my_metadata_t    meta,
    inout standard_metadata_t  standard_metadata)
{
    action reflect() {
        bit<48> tmp;
        // Reflect the packet back to sender.
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;
		hdr.copy.setValid();
		hdr.copy.value=COPYRIGHT_STRING;
    }

    action _drop() {
        mark_to_drop();
    }

	// ===== Start of AES logic =====

	action read_cleartext(){
		meta.aes.t0=hdr.aes_inout.value[127:96];
		meta.aes.t1=hdr.aes_inout.value[95:64];
		meta.aes.t2=hdr.aes_inout.value[63:32];
		meta.aes.t3=hdr.aes_inout.value[31:0];
	}

	action mask_key(bit<128> key128){
		meta.aes.r0= meta.aes.t0^key128[127:96];
		meta.aes.r1= meta.aes.t1^key128[95:64];
		meta.aes.r2= meta.aes.t2^key128[63:32];
		meta.aes.r3= meta.aes.t3^key128[31:0];
	}

	action write_ciphertext(){
		hdr.aes_inout.value[127:96]=meta.aes.r0;
		hdr.aes_inout.value[95:64]=meta.aes.r1;
		hdr.aes_inout.value[63:32]=meta.aes.r2;
		hdr.aes_inout.value[31:0]=meta.aes.r3;

	}

#define TABLE_MASK_KEY(ROUND,SUBKEY128) table mask_key_round_##ROUND { \
		actions = {mask_key;} \
		default_action = mask_key(SUBKEY128); \
	}
// For demonstration purpose, here we put in all the 10-round subkeys derived from an example key 0x01010101020202020303030304040404
	TABLE_MASK_KEY( 0,0x01010101020202020303030304040404)
	TABLE_MASK_KEY( 1,0xf2f3f3f3f0f1f1f1f3f2f2f2f7f6f6f6)
	TABLE_MASK_KEY( 2,0xb2b1b19b4240406ab1b2b2984644446e)
	TABLE_MASK_KEY( 3,0xadaa2ec1efea6eab5e58dc33181c985d)
	TABLE_MASK_KEY( 4,0x39ec626cd6060cc7885ed0f4904248a9)
	TABLE_MASK_KEY( 5,0x5beb10cd3b8bdcb5be66d3fcba42596)
	TABLE_MASK_KEY( 6,0x6c812113bf399cd8e4dff1e72f7bd471)
	TABLE_MASK_KEY( 7,0xdc98206b2f01ede562fef3979543b48)
	TABLE_MASK_KEY( 8,0xad2bd0b01fdbce6e49f4215730a01a1f)
	TABLE_MASK_KEY( 9,0x568910b44952deda00a6ff8d3006e592)
	TABLE_MASK_KEY(10,0xf505fb04602816a46a47ee776a29b75)

#define APPLY_MASK_KEY(ROUND) mask_key_round_##ROUND##.apply();


	action new_round() {
		// Could be skipped, if we use better renaming and read key first.
		// We do this for the sake of code tidyness. More efficient implementation possible, using fewer hardware stages.
		meta.aes.t0=0;  meta.aes.t1=0;  meta.aes.t2=0;  meta.aes.t3=0;
	}

// Macros for defining actions, XOR value from LUT to accummulator variable

#define merge_to(T) action merge_to_t##T##(bit<32> val){\
		meta.aes.t##T##=meta.aes.t##T##^val;	\
	}
	merge_to(0)
	merge_to(1)
	merge_to(2)
	merge_to(3)

// XOR value from LUT to a slice of accummulator variable
#define merge_to_partial(T,SLICE,SLICE_BITS)  action merge_to_t##T##_slice##SLICE##(bit<8> val){ \
	meta.aes.t##T##SLICE_BITS##=meta.aes.t##T##SLICE_BITS##^val;\
	}
	merge_to_partial(0,0,[31:24])
	merge_to_partial(0,1,[23:16])
	merge_to_partial(0,2,[15: 8])
	merge_to_partial(0,3,[ 7: 0])
	merge_to_partial(1,0,[31:24])
	merge_to_partial(1,1,[23:16])
	merge_to_partial(1,2,[15: 8])
	merge_to_partial(1,3,[ 7: 0])
	merge_to_partial(2,0,[31:24])
	merge_to_partial(2,1,[23:16])
	merge_to_partial(2,2,[15: 8])
	merge_to_partial(2,3,[ 7: 0])
	merge_to_partial(3,0,[31:24])
	merge_to_partial(3,1,[23:16])
	merge_to_partial(3,2,[15: 8])
	merge_to_partial(3,3,[ 7: 0])

// Macros for defining lookup tables, which is match-action table that XOR the value into accumulator variable
#define TABLE_LUT(NAME,READ,WHICH_LUT,WRITE) table NAME { \
		key= {READ:exact;}\
		actions = {WRITE;}\
		const entries = WHICH_LUT(WRITE)\
		}

#define LUT00(ROUND)	TABLE_LUT(aes_sbox_lut_00_r##ROUND, meta.aes.r0[31:24], GEN_LUT0, merge_to_t0)
#define LUT01(ROUND)	TABLE_LUT(aes_sbox_lut_01_r##ROUND, meta.aes.r1[23:16], GEN_LUT1, merge_to_t0)
#define LUT02(ROUND)	TABLE_LUT(aes_sbox_lut_02_r##ROUND, meta.aes.r2[15: 8], GEN_LUT2, merge_to_t0)
#define LUT03(ROUND)	TABLE_LUT(aes_sbox_lut_03_r##ROUND, meta.aes.r3[7 : 0], GEN_LUT3, merge_to_t0)

#define LUT10(ROUND)	TABLE_LUT(aes_sbox_lut_10_r##ROUND, meta.aes.r1[31:24], GEN_LUT0, merge_to_t1)
#define LUT11(ROUND)	TABLE_LUT(aes_sbox_lut_11_r##ROUND, meta.aes.r2[23:16], GEN_LUT1, merge_to_t1)
#define LUT12(ROUND)	TABLE_LUT(aes_sbox_lut_12_r##ROUND, meta.aes.r3[15: 8], GEN_LUT2, merge_to_t1)
#define LUT13(ROUND)	TABLE_LUT(aes_sbox_lut_13_r##ROUND, meta.aes.r0[7 : 0], GEN_LUT3, merge_to_t1)

#define LUT20(ROUND)	TABLE_LUT(aes_sbox_lut_20_r##ROUND, meta.aes.r2[31:24], GEN_LUT0, merge_to_t2)
#define LUT21(ROUND)	TABLE_LUT(aes_sbox_lut_21_r##ROUND, meta.aes.r3[23:16], GEN_LUT1, merge_to_t2)
#define LUT22(ROUND)	TABLE_LUT(aes_sbox_lut_22_r##ROUND, meta.aes.r0[15: 8], GEN_LUT2, merge_to_t2)
#define LUT23(ROUND)	TABLE_LUT(aes_sbox_lut_23_r##ROUND, meta.aes.r1[7 : 0], GEN_LUT3, merge_to_t2)

#define LUT30(ROUND)	TABLE_LUT(aes_sbox_lut_30_r##ROUND, meta.aes.r3[31:24], GEN_LUT0, merge_to_t3)
#define LUT31(ROUND)	TABLE_LUT(aes_sbox_lut_31_r##ROUND, meta.aes.r0[23:16], GEN_LUT1, merge_to_t3)
#define LUT32(ROUND)	TABLE_LUT(aes_sbox_lut_32_r##ROUND, meta.aes.r1[15: 8], GEN_LUT2, merge_to_t3)
#define LUT33(ROUND)	TABLE_LUT(aes_sbox_lut_33_r##ROUND, meta.aes.r2[7 : 0], GEN_LUT3, merge_to_t3)

// We need one copy of all tables for each round. Otherwise, there's dependency issue...
#define GENERATE_ALL_TABLE_LUT(ROUND) LUT00(ROUND) LUT01(ROUND) LUT02(ROUND) LUT03(ROUND) LUT10(ROUND) LUT11(ROUND) LUT12(ROUND) LUT13(ROUND) LUT20(ROUND) LUT21(ROUND) LUT22(ROUND) LUT23(ROUND) LUT30(ROUND) LUT31(ROUND) LUT32(ROUND) LUT33(ROUND)
GENERATE_ALL_TABLE_LUT(1)
GENERATE_ALL_TABLE_LUT(2)
GENERATE_ALL_TABLE_LUT(3)
GENERATE_ALL_TABLE_LUT(4)
GENERATE_ALL_TABLE_LUT(5)
GENERATE_ALL_TABLE_LUT(6)
GENERATE_ALL_TABLE_LUT(7)
GENERATE_ALL_TABLE_LUT(8)
GENERATE_ALL_TABLE_LUT(9)
//Only round 1-9 requires mixcolumns. round 10 is different:
// LAST round is special, use SBOX directly as LUT
	TABLE_LUT(aes_sbox_lut_00_rLAST, meta.aes.r0[31:24], GEN_LUT_SBOX, merge_to_t0_slice0)
	TABLE_LUT(aes_sbox_lut_01_rLAST, meta.aes.r1[23:16], GEN_LUT_SBOX, merge_to_t0_slice1)
	TABLE_LUT(aes_sbox_lut_02_rLAST, meta.aes.r2[15: 8], GEN_LUT_SBOX, merge_to_t0_slice2)
	TABLE_LUT(aes_sbox_lut_03_rLAST, meta.aes.r3[7 : 0], GEN_LUT_SBOX, merge_to_t0_slice3)

	TABLE_LUT(aes_sbox_lut_10_rLAST, meta.aes.r1[31:24], GEN_LUT_SBOX, merge_to_t1_slice0)
	TABLE_LUT(aes_sbox_lut_11_rLAST, meta.aes.r2[23:16], GEN_LUT_SBOX, merge_to_t1_slice1)
	TABLE_LUT(aes_sbox_lut_12_rLAST, meta.aes.r3[15: 8], GEN_LUT_SBOX, merge_to_t1_slice2)
	TABLE_LUT(aes_sbox_lut_13_rLAST, meta.aes.r0[7 : 0], GEN_LUT_SBOX, merge_to_t1_slice3)

	TABLE_LUT(aes_sbox_lut_20_rLAST, meta.aes.r2[31:24], GEN_LUT_SBOX, merge_to_t2_slice0)
	TABLE_LUT(aes_sbox_lut_21_rLAST, meta.aes.r3[23:16], GEN_LUT_SBOX, merge_to_t2_slice1)
	TABLE_LUT(aes_sbox_lut_22_rLAST, meta.aes.r0[15: 8], GEN_LUT_SBOX, merge_to_t2_slice2)
	TABLE_LUT(aes_sbox_lut_23_rLAST, meta.aes.r1[7 : 0], GEN_LUT_SBOX, merge_to_t2_slice3)

	TABLE_LUT(aes_sbox_lut_30_rLAST, meta.aes.r3[31:24], GEN_LUT_SBOX, merge_to_t3_slice0)
	TABLE_LUT(aes_sbox_lut_31_rLAST, meta.aes.r0[23:16], GEN_LUT_SBOX, merge_to_t3_slice1)
	TABLE_LUT(aes_sbox_lut_32_rLAST, meta.aes.r1[15: 8], GEN_LUT_SBOX, merge_to_t3_slice2)
	TABLE_LUT(aes_sbox_lut_33_rLAST, meta.aes.r2[7 : 0], GEN_LUT_SBOX, merge_to_t3_slice3)

#define AP(ROUND,i)  aes_sbox_lut_##i##_r##ROUND##.apply();
#define APPLY_ALL_TABLE_LUT(ROUND) AP(ROUND,00) AP(ROUND,01) AP(ROUND,02) AP(ROUND,03) AP(ROUND,10) AP(ROUND,11) AP(ROUND,12) AP(ROUND,13) AP(ROUND,20) AP(ROUND,21) AP(ROUND,22) AP(ROUND,23) AP(ROUND,30) AP(ROUND,31) AP(ROUND,32) AP(ROUND,33)

	// ==== End of AES LUTs, start of contorl logic ====

    apply {
        if (hdr.aes_inout.isValid() && hdr.aes_inout.ff==0xFF) {
			read_cleartext();
			// Start AES
			APPLY_MASK_KEY(0);
			// 10-1 Rounds
			new_round(); APPLY_ALL_TABLE_LUT(1); APPLY_MASK_KEY(1);
			new_round(); APPLY_ALL_TABLE_LUT(2); APPLY_MASK_KEY(2);
			new_round(); APPLY_ALL_TABLE_LUT(3); APPLY_MASK_KEY(3);
			new_round(); APPLY_ALL_TABLE_LUT(4); APPLY_MASK_KEY(4);
			new_round(); APPLY_ALL_TABLE_LUT(5); APPLY_MASK_KEY(5);
			new_round(); APPLY_ALL_TABLE_LUT(6); APPLY_MASK_KEY(6);
			new_round(); APPLY_ALL_TABLE_LUT(7); APPLY_MASK_KEY(7);
			new_round(); APPLY_ALL_TABLE_LUT(8); APPLY_MASK_KEY(8);
			new_round(); APPLY_ALL_TABLE_LUT(9); APPLY_MASK_KEY(9);
			// one last round, S-box only
			new_round(); APPLY_ALL_TABLE_LUT(LAST); APPLY_MASK_KEY(10);
			// End AES

			write_ciphertext();
			// Send the packet back to the sender (for debug only).
			reflect();
        } else {
            _drop();
        }
    }
}

control MyEgress(
    inout my_headers_t        hdr,
    inout my_metadata_t       meta,
    inout standard_metadata_t standard_metadata) {
    apply {   }
}

control MyComputeChecksum(
    inout my_headers_t  hdr,
    inout my_metadata_t meta)
{
    apply {   }
}

control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.aes_inout);
        packet.emit(hdr.copy);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
