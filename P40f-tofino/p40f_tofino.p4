/**********************************************************************
 *  P40f - P4 OS Fingerprinting.
 *  Copyright 2021 Sherry Bai, Hyojoon Kim. Princeton University.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************/

/* -*- P4_16 -*- */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define HASH_BASE 16w0
#define HASH_MAX 16w15


const bit<10> MIRROR_SESSION_ID = 250;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 6;

// Maximum number of OS labels we can track
const bit<16> MAX_OS_LABELS = 1024;

// Percent of specific, non-fuzzy signature matches to verify
const bit<8> PERCENT_TO_SAMPLE = 10;

// TCP control field values
const bit<6> SYN_FLAG = 1 << 1;
const bit<6> PSH_FLAG = 1 << 3;
const bit<6> URG_FLAG = 1 << 5;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_option_t {
    bit<8> kind;
    varbit<312> content;
}

header tcp_option_nop_or_eol_t {
    bit<8> kind;
}

header tcp_option_sack_permitted_t {
    bit<8> kind;
    bit<8> length;
}

header tcp_option_ss_t {
    bit<8> kind;
    bit<8> length;
    bit<16> mss;
}

header tcp_option_s_t {
    bit<8> kind;
    bit<8> length;
    bit<8> scale;
}

header tcp_option_ts_t {
    bit<8> kind;
    bit<8> length;
    bit<32> tsval;
    bit<32> tsecr;
}

header tcp_option_sack_top_t {
    bit<8> kind;
    bit<8> length;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

struct p0f_metadata_subset_t {
    bit<32> tsval;
    bit<16> mss;
    bit<8> scale;
    bit<1> sack_permitted;
    /* 
    concatenate kind fields (cast to 4 bits) of tcp options 
    todo: use less space-intensive way of storing olayout?
    */
    bit<4> option1;
    bit<4> option2;
    bit<4> option3;
    bit<4> option4;
    bit<4> option5;
    bit<4> option6;
    bit<4> option7;
    bit<4> option8;
    bit<4> option9;
    bit<4> option10;

    /* quirks */
    bit<1> quirk_df;
    bit<1> quirk_nz_id;
    bit<1> quirk_zero_id;
    bit<1> quirk_ecn;
    bit<1> quirk_nz_mbz;
    bit<1> quirk_zero_seq;
    bit<1> quirk_nz_ack;
    bit<1> quirk_opt_zero_ts1; 
    bit<1> own_timestamp_seen;
    bit<1> quirk_opt_eol_nz;
    bool is_quirk_opt_eol_zero_bool;
    bit<1> quirk_opt_exws;
    // currently not used because we just reject 
    // incorrectly-formatted packets
    bit<1> quirk_opt_bad;
}

struct p0f_metadata_t {
    bit<4> ver;
    bit<8> ttl;
    bit<9> olen;
    bit<16> mss;
    bit<16> wsize;
    bit<16> wsize_div_mss;
    bit<8> scale;
    bit<1> sack_permitted;
    /* 
    concatenate kind fields (cast to 4 bits) of tcp options 
    todo: use less space-intensive way of storing olayout?
    */
    bit<4> option1;
    bit<4> option2;
    bit<4> option3;
    bit<4> option4;
    bit<4> option5;
    bit<4> option6;
    bit<4> option7;
    bit<4> option8;
    bit<4> option9;
    bit<4> option10;

    /* quirks */
    bit<1> quirk_df;
    bit<1> quirk_nz_id;
    bit<1> quirk_zero_id;
    bit<1> quirk_ecn;
    bit<1> quirk_nz_mbz;
    bit<1> quirk_zero_seq;
    bit<1> quirk_nz_ack;
    bit<1> quirk_zero_ack;
    bit<1> quirk_opt_zero_ts1; 
    bit<1> own_timestamp_seen;
    bit<32> tsval;
    bit<1> quirk_opt_eol_nz;
    bool is_quirk_opt_eol_zero_bool;
    bit<1> quirk_opt_exws;
    // currently not used because we just reject 
    // incorrectly-formatted packets
    bit<1> quirk_opt_bad;
    bit<1> pclass;
}

struct p0f_result_t {
    bit<16> result;
    bit<1> is_generic_fuzzy;
    bit<1> drop_ip_flag;
}

struct os_stats_t {
    bit<32> read_holder;  // Temporarily hold register read during updates
}

struct cms_helper_t {
    bit<32> hash_1;
    bit<16> count_1;
}

header resubmit_data_t {
    bit<1> stage_indicator; // 0 or 1 for stage 1 or 2 in the sip/cip table
    bit<7> _padding0;
    bit<8> _padding1;
    bit<16> _padding2;
    bit<32> _padding3;
}

header resubmit_data_skimmed_t {
    bit<8> stage_indicator; // 0 or 1 for stage 1 or 2 in the sip/cip table
}

struct metadata {
    resubmit_data_t resubmit_data_read;
    resubmit_data_skimmed_t resubmit_data_write;

    p0f_metadata_t p0f_metadata;
    p0f_result_t p0f_result;
    os_stats_t os_stats;
    cms_helper_t cms_helper;
}


header p40f_result_hdr_t {
    p0f_result_t    p0f_result;
    bit<6>          padding;
}

header p40f_hdr_t { 

    p0f_metadata_subset_t p0f_metadata;
    p0f_result_t   p0f_result;
    os_stats_t     os_stats;
    bit<8> padding;
}

struct eg_metadata_t {
    p0f_metadata_t p0f_metadata;
    p0f_result_t p0f_result;
    os_stats_t os_stats;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    tcp_t                tcp;

    tcp_option_nop_or_eol_t         tcp_option_1_eol;
    tcp_option_nop_or_eol_t         tcp_option_1_nop;
    tcp_option_ss_t                 tcp_option_1_ss;
    tcp_option_s_t                  tcp_option_1_s;
    tcp_option_sack_permitted_t     tcp_option_1_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_1_sack;
    tcp_option_ts_t                 tcp_option_1_ts;

    tcp_option_nop_or_eol_t         tcp_option_2_eol;
    tcp_option_nop_or_eol_t         tcp_option_2_nop;
    tcp_option_ss_t                 tcp_option_2_ss;
    tcp_option_s_t                  tcp_option_2_s;
    tcp_option_sack_permitted_t     tcp_option_2_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_2_sack;
    tcp_option_ts_t                 tcp_option_2_ts;

    tcp_option_nop_or_eol_t         tcp_option_3_eol;
    tcp_option_nop_or_eol_t         tcp_option_3_nop;
    tcp_option_ss_t                 tcp_option_3_ss;
    tcp_option_s_t                  tcp_option_3_s;
    tcp_option_sack_permitted_t     tcp_option_3_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_3_sack;
    tcp_option_ts_t                 tcp_option_3_ts;

    tcp_option_nop_or_eol_t         tcp_option_4_eol;
    tcp_option_nop_or_eol_t         tcp_option_4_nop;
    tcp_option_ss_t                 tcp_option_4_ss;
    tcp_option_s_t                  tcp_option_4_s;
    tcp_option_sack_permitted_t     tcp_option_4_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_4_sack;
    tcp_option_ts_t                 tcp_option_4_ts;

    tcp_option_nop_or_eol_t         tcp_option_5_eol;
    tcp_option_nop_or_eol_t         tcp_option_5_nop;
    tcp_option_ss_t                 tcp_option_5_ss;
    tcp_option_s_t                  tcp_option_5_s;
    tcp_option_sack_permitted_t     tcp_option_5_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_5_sack;
    tcp_option_ts_t                 tcp_option_5_ts;

    tcp_option_nop_or_eol_t         tcp_option_6_eol;
    tcp_option_nop_or_eol_t         tcp_option_6_nop;
    tcp_option_ss_t                 tcp_option_6_ss;
    tcp_option_s_t                  tcp_option_6_s;
    tcp_option_sack_permitted_t     tcp_option_6_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_6_sack;
    tcp_option_ts_t                 tcp_option_6_ts;

    tcp_option_nop_or_eol_t         tcp_option_7_eol;
    tcp_option_nop_or_eol_t         tcp_option_7_nop;
    tcp_option_ss_t                 tcp_option_7_ss;
    tcp_option_s_t                  tcp_option_7_s;
    tcp_option_sack_permitted_t     tcp_option_7_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_7_sack;
    tcp_option_ts_t                 tcp_option_7_ts;

    tcp_option_nop_or_eol_t         tcp_option_8_eol;
    tcp_option_nop_or_eol_t         tcp_option_8_nop;
    tcp_option_ss_t                 tcp_option_8_ss;
    tcp_option_s_t                  tcp_option_8_s;
    tcp_option_sack_permitted_t     tcp_option_8_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_8_sack;
    tcp_option_ts_t                 tcp_option_8_ts;

    tcp_option_nop_or_eol_t         tcp_option_9_eol;
    tcp_option_nop_or_eol_t         tcp_option_9_nop;
    tcp_option_ss_t                 tcp_option_9_ss;
    tcp_option_s_t                  tcp_option_9_s;
    tcp_option_sack_permitted_t     tcp_option_9_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_9_sack;
    tcp_option_ts_t                 tcp_option_9_ts;

    tcp_option_nop_or_eol_t         tcp_option_10_eol;
    tcp_option_nop_or_eol_t         tcp_option_10_nop;
    tcp_option_ss_t                 tcp_option_10_ss;
    tcp_option_s_t                  tcp_option_10_s;
    tcp_option_sack_permitted_t     tcp_option_10_sack_permitted;      
    tcp_option_sack_top_t           tcp_option_10_sack;
    tcp_option_ts_t                 tcp_option_10_ts;

    p40f_hdr_t                      p40f_hdr;
    p40f_result_hdr_t               p40f_result_hdr;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/


parser Tcp_option_parser_new2(packet_in b,
                        in bit<4> tcp_hdr_data_offset,
                        inout headers hdr, 
                        inout metadata meta)
{
    bit<9> tcp_hdr_bytes_left;
    bit<1> own_timestamp_seen = 0;
    bit<1> eol_seen = 0;
    bit<8> kind_g = 0;

    ParserCounter() parser_counter;

    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        
        verify(hdr.tcp.dataOffset >= 5, error.TcpDataOffsetTooSmall);
        // multiply data offset field by 4
        //tcp_hdr_bytes_left = ((bit<9>) (hdr.tcp.dataOffset - 5)) << 2;
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        //transition next_option;

        parser_counter.set(tcp_hdr_data_offset);
        parser_counter.decrement(5);
        transition next_option_1;
    }
    
    #define Parsing_Part1(step)                             \
    state next_option_## step ## {                          \
        transition select(parser_counter.is_zero()) {       \
            true : accept;                                  \
            default : next_option_## step ##_part2;         \
        }                                                   \
    }                                                       \
                                                            \

    #define Parsing_Part2(step)                             \
    state next_option_## step ##_part2 {                    \
        bit<8> kind = b.lookahead<bit<8>>();                \
                                                            \
                                                            \
        transition select(kind) {                           \
            0: parse_tcp_option_## step ##_end;             \
            1: parse_tcp_option_## step ##_nop;             \
            2: parse_tcp_option_## step ##_ss;              \
            3: parse_tcp_option_## step ##_s;               \
            4: parse_tcp_option_## step ##_sack_permitted;  \
            5: parse_tcp_option_## step ##_sack;            \
            8: parse_tcp_option_## step ##_timestamps;      \
            default : accept;                               \
        }                                                   \
    }                                                       \
                                                            \

    state parse_tcp_option_end {
        parser_counter.decrement(8w8);
        b.advance(32w8);

        transition select(parser_counter.is_zero()) {
            true:       accept;
            default:    parse_eol_data_left;    
        }
    }

    state parse_eol_data_left {
        meta.p0f_metadata.quirk_opt_eol_nz = 1;
        transition accept;
    }

    #define Parse_TcpOptions(step,next)                     \
    state parse_tcp_option_## step ##_end {                 \
        b.extract(hdr.tcp_option_## step ##_eol);           \
        parser_counter.decrement(8w8);                      \   
                                                            \
        transition select(parser_counter.is_zero()) {       \
            true:       accept;                             \
            default:    parse_eol_data_left;                \
        }                                                   \
    }                                                       \
                                                            \
    state parse_tcp_option_## step ##_nop {     \
        b.extract(hdr.tcp_option_## step ##_nop); \
        parser_counter.decrement(8w8);          \
        transition next_option_## next ##;      \
    }                                           \
                                                \
    state parse_tcp_option_## step ##_ss {      \
        b.extract(hdr.tcp_option_## step ##_ss); \
        meta.p0f_metadata.mss = hdr.tcp_option_## step ##_ss.mss;              \
        parser_counter.decrement(8w32);         \
        transition next_option_## next ##;      \
    }                                           \
                                                \
    state parse_tcp_option_## step ##_s {       \
        b.extract(hdr.tcp_option_## step ##_s); \
        meta.p0f_metadata.scale = hdr.tcp_option_## step ##_s.scale;              \
        parser_counter.decrement(8w24);         \
        transition next_option_## next ##;      \
    }                                           \
                                                \
    state parse_tcp_option_## step ##_sack_permitted {   \
        b.extract(hdr.tcp_option_## step ##_sack_permitted); \
        parser_counter.decrement(8w16);         \
        transition next_option_## next ##;      \
    }                                           \
                                                \
    state parse_tcp_option_## step ##_sack {    \
        bit<8> n_sack_bytes = b.lookahead<tcp_option_sack_top_t>().length; \
        transition select(n_sack_bytes) {       \
            10:         parse_tcp_option_## step ##_sack_advance_10;    \
            18:         parse_tcp_option_## step ##_sack_advance_18;    \
            26:         parse_tcp_option_## step ##_sack_advance_26;    \
            34:         parse_tcp_option_## step ##_sack_advance_34;    \
            default:    next_option_## next ##;                         \
        }                                                               \
                                                                        \
    }                                                                   \
                                                                        \
    state parse_tcp_option_## step ##_sack_advance_10 { \
        parser_counter.decrement(8w80);                 \
        b.advance(32w80);                               \
        transition next_option_## next ##;              \
    }                                                   \
                                                        \
    state parse_tcp_option_## step ##_sack_advance_18 { \
        parser_counter.decrement(8w144);                \
        b.advance(32w144);                              \
        transition next_option_## next ##;              \
    }                                                   \
                                                        \
    state parse_tcp_option_## step ##_sack_advance_26 { \
        parser_counter.decrement(8w208);                \
        b.advance(32w208);                              \
        transition next_option_## next ##;              \
    }                                                   \
                                                        \
    state parse_tcp_option_## step ##_sack_advance_34 { \
        parser_counter.decrement(8w200);                \
        parser_counter.decrement(8w72);                 \
        b.advance(32w272);                              \
        transition next_option_## next ##;              \
    }                                                   \
                                                        \
    state parse_tcp_option_## step ##_timestamps {      \
        b.extract(hdr.tcp_option_## step ##_ts); \
        parser_counter.decrement(80);                   \
        meta.p0f_metadata.tsval = hdr.tcp_option_## step ##_ts.tsval;          \
        meta.p0f_metadata.own_timestamp_seen = 1;                                       \
        transition next_option_## next ##;              \
    }                                                   \

    Parsing_Part1(1)
    Parsing_Part2(1)
    Parse_TcpOptions(1,2)

    Parsing_Part1(2)
    Parsing_Part2(2)
    Parse_TcpOptions(2,3)

    Parsing_Part1(3)
    Parsing_Part2(3)
    Parse_TcpOptions(3,4)

    Parsing_Part1(4)
    Parsing_Part2(4)
    Parse_TcpOptions(4,5)

    Parsing_Part1(5)
    Parsing_Part2(5)
    Parse_TcpOptions(5,6)

    Parsing_Part1(6)
    Parsing_Part2(6)
    Parse_TcpOptions(6,7)

    Parsing_Part1(7)
    Parsing_Part2(7)
    Parse_TcpOptions(7,8)

    Parsing_Part1(8)
    Parsing_Part2(8)
    Parse_TcpOptions(8,9)

    Parsing_Part1(9)
    Parsing_Part2(9)
    Parse_TcpOptions(9,10)

    Parsing_Part1(10)
    Parsing_Part2(10)
    Parse_TcpOptions(10,11)

    state next_option_11 {
        transition select(parser_counter.is_zero()) {
            true : accept;
            default : accept; // stop parsing. More than 10 options is unlikely. never seen.
        }                                            
    }                                                
}


parser TofinoIngressParser(
        packet_in pkt,
        inout metadata ig_meta,
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
        pkt.extract(ig_meta.resubmit_data_read);
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition accept;
    }
}


/* Parser */
parser MyIngressParser(packet_in packet,
                       out headers hdr,
                       out metadata meta,
                       out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    ParserCounter() counter;

    state start {
        tofino_parser.apply(packet, meta, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        /* calculate length of ip header */
        // multiply ihl field by 4
        //ipv4_options_bytes = ((bit<9>)(hdr.ipv4.ihl - 5)) << 2;
        //meta.p0f_metadata.olen = ipv4_options_bytes;
        
        // Let's move this calculation outside. When installing rules, 
        // make script calculate ihl and put rules with 'ihl' instead of 'olen'. 
        // meta.p0f_metadata.olen = (bit<9>)(hdr.ipv4.ihl);// do it at control.

        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        Tcp_option_parser_new2.apply(packet, hdr.tcp.dataOffset, hdr, meta); 
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                 inout metadata meta,
                 in ingress_intrinsic_metadata_t ig_intr_md,
                 in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
                 inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
                 inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    action dropPacket() {
        //mark_to_drop(); // seems doing nothing is same as dropping.
    }
   
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        ig_intr_md_for_tm.ucast_egress_port = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            dropPacket;
            //NoAction;
        }
        size = 1024;
        //default_action = NoAction();
        default_action = dropPacket();
    }

    // Bloom filter (count-min-sketch) for checking if IP packet should be
    // forwarded to software
    // (Packets with dst port 80 and with seq number equal to that of 
    // associated SYN packet + 1 are assumed to be HTTP GET requests.)
    Register<bit<16>,bit<32>>(32w15+1) http_cms_1;
    RegisterAction<bit<16>, bit<32>, bit<16>>(http_cms_1) http_cms1_reg_inc_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            value = value + 1;
            read_value = value;
        }
    };
    RegisterAction<bit<16>, bit<32>, bit<16>>(http_cms_1) http_cms1_reg_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;
        }
    };

    // Count-min sketch implementation for tracking IPs to drop
    // Adapted from
    // https://github.com/p4lang/tutorials/blob/846f059ddd9c53157ea9cc2ec7c0b2d5359f2df0/SIGCOMM_2016/heavy_hitter/p4src/heavy_hitter.p4

    Register<bit<16>,bit<32>>(32w15+1) cms_1; 
    RegisterAction<bit<16>, bit<32>, bit<16>>(cms_1) cms1_reg_inc_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            value = value + 1;
            read_value = value;
        }
    };
    RegisterAction<bit<16>, bit<32>, bit<16>>(cms_1) cms1_reg_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;
        }
    };


    /* wsize register */
    Register<bit<16>,bit<16>>(32w65535,0) wsize_reg; // using wsize as index as it is.
    RegisterAction<bit<16>,_,bit<16>>(wsize_reg) wsize_reg_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            read_value = value;
        }
    };

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_1;
    Random<bit<8>>() random_8bit;

    action add_ip_to_drop_set() {
        meta.cms_helper.hash_1 = hash_1.get({hdr.ipv4.srcAddr});

        meta.cms_helper.count_1 = cms1_reg_inc_read_action.execute(meta.cms_helper.hash_1);
    }

    action check_ip_in_drop_set() {
        meta.cms_helper.hash_1 = hash_1.get({hdr.ipv4.srcAddr});

        // Check at location hash_1 in cms_1
        meta.cms_helper.count_1 = cms1_reg_read_action.execute(meta.cms_helper.hash_1);
    }

    action set_result(bit<16> result, bit<1> is_generic_fuzzy) {
        // set result
        hdr.p40f_result_hdr.p0f_result.result = result;
        hdr.p40f_result_hdr.p0f_result.is_generic_fuzzy = is_generic_fuzzy;

        hdr.p40f_result_hdr.p0f_result.result = result;
    }

    action set_result_drop_ip(bit<16> result, bit<1> is_generic_fuzzy) {
        // set result
        set_result(result, is_generic_fuzzy);
        hdr.p40f_hdr.p0f_result.drop_ip_flag = 1;
    }

    action set_result_drop_pkt(bit<16> result, bit<1> is_generic_fuzzy) {
        // set result
        set_result(result, is_generic_fuzzy);

        // mark to drop
        //hdr.p40f_hdr.p0f_result.drop_flag = 1;
    }

    action set_result_redirect(
        bit<16> result, 
        bit<1> is_generic_fuzzy, 
        ip4Addr_t redirect_addr) {
        // set result
        set_result(result, is_generic_fuzzy);

        // change destination ip address
        hdr.ipv4.dstAddr = redirect_addr;
    }

    table result_match {
        key = {

            hdr.ipv4.version: range; // 4..6
            hdr.ipv4.ttl: range; 
            hdr.ipv4.ihl: exact;
            meta.p0f_metadata.mss: ternary;      //1400, 
            hdr.tcp.window: ternary;    //varius
            meta.p0f_metadata.scale: ternary;  // *

            hdr.tcp_option_1_eol.isValid():  ternary;
            hdr.tcp_option_1_nop.isValid():  ternary;
            hdr.tcp_option_1_ss.isValid():  ternary;
            hdr.tcp_option_1_s.isValid():  ternary;
            hdr.tcp_option_1_sack_permitted.isValid():  ternary;
            hdr.tcp_option_1_sack.isValid():  ternary;
            hdr.tcp_option_1_ts.isValid():  ternary;

            hdr.tcp_option_2_eol.isValid():  ternary;
            hdr.tcp_option_2_nop.isValid():  ternary;
            hdr.tcp_option_2_ss.isValid():  ternary;
            hdr.tcp_option_2_s.isValid():  ternary;
            hdr.tcp_option_2_sack_permitted.isValid():  ternary;
            hdr.tcp_option_2_sack.isValid():  ternary;
            hdr.tcp_option_2_ts.isValid():  ternary;

            hdr.tcp_option_3_eol.isValid():  ternary;
            hdr.tcp_option_3_nop.isValid():  ternary;
            hdr.tcp_option_3_ss.isValid():  ternary;
            hdr.tcp_option_3_s.isValid():  ternary;
            hdr.tcp_option_3_sack_permitted.isValid():  ternary;
            hdr.tcp_option_3_sack.isValid():  ternary;
            hdr.tcp_option_3_ts.isValid():  ternary;

            hdr.tcp_option_4_eol.isValid():  ternary;
            hdr.tcp_option_4_nop.isValid():  ternary;
            hdr.tcp_option_4_ss.isValid():  ternary;
            hdr.tcp_option_4_s.isValid():  ternary;
            hdr.tcp_option_4_sack_permitted.isValid():  ternary;
            hdr.tcp_option_4_sack.isValid():  ternary;
            hdr.tcp_option_4_ts.isValid():  ternary;


            hdr.tcp_option_5_eol.isValid():  ternary;
            hdr.tcp_option_5_nop.isValid():  ternary;
            hdr.tcp_option_5_ss.isValid():  ternary;
            hdr.tcp_option_5_s.isValid():  ternary;
            hdr.tcp_option_5_sack_permitted.isValid():  ternary;
            hdr.tcp_option_5_sack.isValid():  ternary;
            hdr.tcp_option_5_ts.isValid():  ternary;


            hdr.tcp_option_6_eol.isValid():  ternary;
            hdr.tcp_option_6_nop.isValid():  ternary;
            hdr.tcp_option_6_ss.isValid():  ternary;
            hdr.tcp_option_6_s.isValid():  ternary;
            hdr.tcp_option_6_sack_permitted.isValid():  ternary;
            hdr.tcp_option_6_sack.isValid():  ternary;
            hdr.tcp_option_6_ts.isValid():  ternary;


            hdr.tcp_option_7_eol.isValid():  ternary;
            hdr.tcp_option_7_nop.isValid():  ternary;
            hdr.tcp_option_7_ss.isValid():  ternary;
            hdr.tcp_option_7_s.isValid():  ternary;
            hdr.tcp_option_7_sack_permitted.isValid():  ternary;
            hdr.tcp_option_7_sack.isValid():  ternary;
            hdr.tcp_option_7_ts.isValid():  ternary;


            hdr.tcp_option_8_eol.isValid():  ternary;
            hdr.tcp_option_8_nop.isValid():  ternary;
            hdr.tcp_option_8_ss.isValid():  ternary;
            hdr.tcp_option_8_s.isValid():  ternary;
            hdr.tcp_option_8_sack_permitted.isValid():  ternary;
            hdr.tcp_option_8_sack.isValid():  ternary;
            hdr.tcp_option_8_ts.isValid():  ternary;


            hdr.tcp_option_9_eol.isValid():  ternary;
            hdr.tcp_option_9_nop.isValid():  ternary;
            hdr.tcp_option_9_ss.isValid():  ternary;
            hdr.tcp_option_9_s.isValid():  ternary;
            hdr.tcp_option_9_sack_permitted.isValid():  ternary;
            hdr.tcp_option_9_sack.isValid():  ternary;
            hdr.tcp_option_9_ts.isValid():  ternary;


            hdr.tcp_option_10_eol.isValid():  ternary;
            hdr.tcp_option_10_nop.isValid():  ternary;
            hdr.tcp_option_10_ss.isValid():  ternary;
            hdr.tcp_option_10_s.isValid():  ternary;
            hdr.tcp_option_10_sack_permitted.isValid():  ternary;
            hdr.tcp_option_10_sack.isValid():  ternary;
            hdr.tcp_option_10_ts.isValid():  ternary;

            meta.p0f_metadata.quirk_df: ternary;       
            meta.p0f_metadata.quirk_nz_id: ternary;
            meta.p0f_metadata.quirk_zero_id: exact;   //none
            meta.p0f_metadata.quirk_ecn: ternary;
            meta.p0f_metadata.quirk_nz_mbz: exact;      //none
            meta.p0f_metadata.quirk_zero_seq: exact;    //none
            meta.p0f_metadata.quirk_nz_ack: exact;
            meta.p0f_metadata.quirk_zero_ack: exact;    //none
            meta.p0f_metadata.quirk_opt_zero_ts1: exact;

        }
        actions = {
            set_result;
            set_result_drop_ip;
            set_result_drop_pkt;
            set_result_redirect;
        }
        size = 1024;
        default_action = set_result(MAX_OS_LABELS-1, 0);
    }


    apply {

        // initaillize
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) { 
            meta.p0f_metadata.quirk_opt_zero_ts1 = 0; 
            meta.p0f_metadata.tsval = 0;
            meta.p0f_metadata.own_timestamp_seen = 0;


            meta.p0f_metadata.quirk_df = 0;
            meta.p0f_metadata.quirk_nz_id = 0;
            meta.p0f_metadata.quirk_zero_id = 0;
            meta.p0f_metadata.quirk_ecn = 0;
            meta.p0f_metadata.quirk_nz_mbz = 0;
            meta.p0f_metadata.quirk_zero_seq = 0;
            meta.p0f_metadata.quirk_nz_ack = 0;
            meta.p0f_metadata.quirk_zero_ack = 0;

            hdr.p40f_result_hdr.setValid();

            // set flag if own timestamp is zero
//            if (hdr.p40f_hdr.p0f_metadata.own_timestamp_seen == 1 && hdr.p40f_hdr.p0f_metadata.tsval == 0) {
//                hdr.p40f_hdr.p0f_metadata.quirk_opt_zero_ts1 = 1;
//            }
//          //Joon. TODO. TEST
            if (meta.p0f_metadata.own_timestamp_seen == 1 && meta.p0f_metadata.tsval == 0) {
                meta.p0f_metadata.quirk_opt_zero_ts1 = 1;
            }
            
            // Only fingerprint TCP packets with SYN flag set and ACK, RST, FIN
            // not set.
            if (hdr.tcp.ctrl == SYN_FLAG
                || hdr.tcp.ctrl == (SYN_FLAG | PSH_FLAG)
                || hdr.tcp.ctrl == (SYN_FLAG | URG_FLAG)
                || hdr.tcp.ctrl == (SYN_FLAG | PSH_FLAG | URG_FLAG)) {
                // ================ OS Fingerprinting ================

                /* quirks */
                /* IP-specific quirks */
                if (hdr.ipv4.flags & 0x02 != 0) {  // 010, 011
                    /* df: "don't fragment" set */ 
                    meta.p0f_metadata.quirk_df = 1;
                    if (hdr.ipv4.identification != 0) {
                        /* id+: df set but IPID not zero */
                        meta.p0f_metadata.quirk_nz_id = 1;
                    }
                }
                if (hdr.ipv4.diffserv & 0x03 != 0) {
                    /* ecn support */
                    meta.p0f_metadata.quirk_ecn = 1;
                }
                if (hdr.ipv4.flags & 0x04 != 0) {  // 100, 101, 110, 111
                    /* 0+: "must be zero field" not zero */
                    meta.p0f_metadata.quirk_nz_mbz = 1;
                }

                /* TCP-specific quirks */
                // CWR and ECE flags both set, or only NS flag set
                if (hdr.tcp.ecn & 0x03 != 0 || hdr.tcp.ecn & 0x04 != 0) {
                    /* ecn: explicit congestion notification support */
                    meta.p0f_metadata.quirk_ecn = 1;
                }

                if (hdr.tcp.seqNo == 0) {
                    /* seq-: sequence number is zero */
                    meta.p0f_metadata.quirk_zero_seq = 1;
                }
                if (hdr.tcp.ctrl & 0x10 == 0) {
                    if (hdr.tcp.ackNo != 0 && hdr.tcp.ctrl & 0x04 == 0) {
                        /* ack+: ACK flag not set but ACK number nonzero */
                        meta.p0f_metadata.quirk_nz_ack = 1;
                    }
                }

                // Set p0f_result field.
                result_match.apply();
            
                // ================ IPv4 Forwarding ================
                if (hdr.ipv4.isValid()) {
                    //ig_intr_md_for_tm.ucast_egress_port=4;
                    ipv4_lpm.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                inout eg_metadata_t eg_md,
                in egress_intrinsic_metadata_t eg_intr_md,
                in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
                inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
                inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
 

    Register<bit<32>,bit<16>>((bit<32>)MAX_OS_LABELS) os_counters;
    RegisterAction<bit<32>, bit<16>, bit<32>>(os_counters) os_counter_inc_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + 1;
            read_value = value;
        }
    };


    apply {
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {

    Checksum() ipv4_csum;

    apply {

        if(hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_csum.update({ 
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.totalLen,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.fragOffset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr });
        }
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/


control MyIngressDeparser(packet_out pkt,
                          inout headers hdr,
                          in metadata meta,
                          in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {


    //Mirror() mirror; // mirror constructor

    apply {
        //if (ig_intr_dprsr_md.mirror_type == 3w1) {
        //    mirror.emit(MIRROR_SESSION_ID);
        //}

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.p40f_result_hdr);
    }
}

control MyEgressDeparser(packet_out packet, 
                         inout headers hdr, 
                         in eg_metadata_t eg_md,
                         in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.p40f_result_hdr);
    }

}

parser MyEgressParser(packet_in packet,
                       out headers hdr,
                       out eg_metadata_t eg_md,
                       out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

    state parse_ip {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition parse_p40f_result;
    }

    state parse_p40f_result {
        packet.extract(hdr.p40f_result_hdr);
        transition accept;
    }
}
                       

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;

Switch(pipe) main;
