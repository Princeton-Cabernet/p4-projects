// vim: syntax=P4
/*
    ConQuest: Fine-Grained Queue Measurement in the Data Plane
    
    Copyright (C) 2020 Xiaoqi Chen, Princeton University
    xiaoqic [at] cs.princeton.edu / https://doi.org/10.1145/3359989.3365408
    
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


// Baseline program: add ECN naively

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
    bit<6> diffserv;
    bit<2> ecn; 
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
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct ig_metadata_t {
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

parser EtherIPTCPUDPParser(
    packet_in pkt,
    out header_t hdr) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
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

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    EtherIPTCPUDPParser() layer4_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {    
    apply {    
        pkt.emit(hdr);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
    EtherIPTCPUDPParser() layer4_parser;
    state start {
        pkt.extract(eg_intr_md);
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser: recalculate checksum
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    Checksum() ipv4_checksum;
    apply {     
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});
    
        pkt.emit(hdr.ethernet);
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
         
        action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
        }
        action not_drop(){
            ig_intr_dprsr_md.drop_ctl = 0x0;
        }
        action nop() {
        }
        action route_to(bit<9> port){
            ig_intr_tm_md.ucast_egress_port=port;
        }
   
        apply {
            bit<9> dest;
            @in_hash{ dest= (bit<9>)  hdr.ipv4.dst_addr[31:24]; }
            route_to(dest);
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
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
        
        action set_ecn_bits() {
            hdr.ipv4.ecn = 0b11;
        }
        action nop(){}
        action drop(){
            eg_intr_dprs_md.drop_ctl = 1;
        }

        apply {
            bit<9> enq_qdepth_KB=eg_intr_md.enq_qdepth[18:10];
            const bit<9> THRES=300;

            if(enq_qdepth_KB>THRES){
                if(hdr.ipv4.ecn != 0){
                    set_ecn_bits();
                }else{
                    drop();
                }    
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
