/**********************************************************************
 *  Copyright 2019 Hyojoon Kim. Princeton University.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
**********************************************************************/

#include "includes/p4anony_headers.p4"

typedef bit<9>  egressSpec_t;
typedef bit<32> mask_t;

struct headers { 
    ethernet_t       ethernet;
    vlan_tag_t       vlan;
    arp_rarp_t       arp;
    arp_rarp_ipv4_t  arp_ipv4;
    ipv4_t           ipv4;
    tcp_t            tcp;
    udp_t            udp;
}

struct metadata {
    bit<4> is_arp;
    bit<4> is_ipv4;
    bit<4> hashed_mac_srcAddr_oui;
    bit<4> hashed_mac_srcAddr_id;
    bit<4> hashed_mac_dstAddr_oui;
    bit<4> hashed_mac_dstAddr_id;
    dstAddr_oui_t dst_mac_mc_oui;
    srcAddr_oui_t src_mac_oui;
    srcAddr_id_t src_mac_id;
    dstAddr_oui_t dst_mac_oui;
    dstAddr_id_t dst_mac_id;
    bit<32> ipv4_srcip;
    bit<32> ipv4_dstip;
    bit<32> srcip_subnet_part;
    bit<32> srcip_hash_part;
    bit<32> dstip_subnet_part;
    bit<32> dstip_hash_part;
    bit<32> srcip_subnetmask;
    bit<32> dstip_subnetmask;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser OntasParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.src_mac_oui = hdr.ethernet.srcAddr_oui;
        meta.src_mac_id = hdr.ethernet.srcAddr_id;
        meta.dst_mac_oui = hdr.ethernet.dstAddr_oui;
        meta.dst_mac_id = hdr.ethernet.dstAddr_id;

        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.is_ipv4 = (bit<4>) 1;
        meta.ipv4_srcip = hdr.ipv4.srcAddr;
        meta.ipv4_dstip = hdr.ipv4.dstAddr;
        meta.srcip_subnet_part = hdr.ipv4.srcAddr;
        meta.dstip_subnet_part = hdr.ipv4.dstAddr;
    
        transition select(hdr.ipv4.protocol) {
            IPPROTO_TCP : parse_tcp;
            IPPROTO_UDP : parse_udp;
            default: accept;
        }
    }
    
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.protoType) {
            ETHERTYPE_IPV4 : parse_arp_rarp_ipv4;
            default : accept;
        }
    }
    
    state parse_arp_rarp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.is_arp = (bit<4>) 1;
        meta.ipv4_srcip = hdr.arp_ipv4.srcProtoAddr;
        meta.ipv4_dstip =  hdr.arp_ipv4.dstProtoAddr;
        meta.srcip_subnet_part = hdr.arp_ipv4.srcProtoAddr;
        meta.dstip_subnet_part = hdr.arp_ipv4.dstProtoAddr;
        transition accept;
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control OntasVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control OntasIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /************ ACTIONS ************/
    
    /* Set output port */
    action set_egr_action(egressSpec_t egress_spec) {
        standard_metadata.egress_spec = egress_spec;
    }
    
    action nop_action() {
    }
    
    action _drop_action() {
        mark_to_drop(standard_metadata);
    }
    
    action multicast_mac_catch_action() {
        meta.dst_mac_mc_oui = hdr.ethernet.dstAddr_oui & 0x110000;
    }
    
    /***************************************************************
     * Prepare hashing by dividing subnet part and hash part
     * by masking.  SRC IP.
     * 
     * mask1:    subnet mask (e.g., 255.255.255.0)
     * mask2:    wildcard part mask (e.g., 0.0.0.255)
     */
    action prepare_srcip_hash_action(mask_t mask1, mask_t mask2) {
        meta.srcip_subnet_part = meta.ipv4_srcip & mask1;
        meta.srcip_hash_part = meta.ipv4_srcip & mask2;

        meta.srcip_subnetmask =  mask1;
    }
    
    /***************************************************************
     * Prepare hashing by dividing subnet part and hash part
     * by masking. DST IP. 
     * 
     * mask1:    subnet mask (e.g., 255.255.255.0)
     * mask2:    wildcard part mask (e.g., 0.0.0.255)
     */
    action prepare_dstip_hash_action(mask_t mask1,mask_t mask2) {
        meta.dstip_subnet_part = meta.ipv4_dstip & mask1;
        meta.dstip_hash_part = meta.ipv4_dstip & mask2;
    
        meta.dstip_subnetmask = mask1;
    }
    
    action hash_mac_src_id_action() {
        hash(hdr.ethernet.srcAddr_id, HashAlgorithm.crc32, 32w0, {meta.src_mac_id}, 32w24);
        meta.hashed_mac_srcAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_src_oui_action() {
        hash(hdr.ethernet.srcAddr_oui, HashAlgorithm.crc32, 32w0, {meta.src_mac_oui}, 32w24);
        meta.hashed_mac_srcAddr_oui = (bit<4>) 1;
    }
    
    action hash_arp_mac_src_id_action() {
        hdr.arp_ipv4.srcHwAddr_id = hdr.ethernet.srcAddr_id;
    }
    
    action hash_arp_mac_src_oui_action() {
        hdr.arp_ipv4.srcHwAddr_oui = hdr.ethernet.srcAddr_oui;
    }
    
    action hash_mac_dst_id_action() {
        hash(hdr.ethernet.dstAddr_id, HashAlgorithm.crc32, 32w0, {meta.dst_mac_id}, 32w24);
        meta.hashed_mac_dstAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_dst_oui_action() {
        hash(hdr.ethernet.dstAddr_oui, HashAlgorithm.crc32, 32w0, {meta.dst_mac_oui}, 32w24);
        meta.hashed_mac_dstAddr_oui = (bit<4>) 1;
    }
    
    action hash_arp_mac_dst_id_action() {
        hdr.arp_ipv4.dstHwAddr_id = hdr.ethernet.dstAddr_id;
    }
    
    action hash_arp_mac_dst_oui_action() {
        hdr.arp_ipv4.dstHwAddr_oui = hdr.ethernet.dstAddr_oui;
    }
    
    action hash_and_modify_src0_action() { 
        hash(meta.srcip_hash_part, HashAlgorithm.crc32, 32w0, {meta.srcip_hash_part}, 32w32);
    }
    action hash_and_modify_src8_action() { 
        hash(meta.srcip_hash_part, HashAlgorithm.crc32_custom, 32w0, {meta.srcip_hash_part}, 32w24);
    }
    action hash_and_modify_src16_action() { 
        hash(meta.srcip_hash_part, HashAlgorithm.crc16, 32w0, {meta.srcip_hash_part}, 32w16);
    }
    action hash_and_modify_src24_action() { 
        hash(meta.srcip_hash_part, HashAlgorithm.crc16_custom, 32w0, {meta.srcip_hash_part}, 32w8);
    }
    action hash_and_modify_dst0_action() { 
        hash(meta.dstip_hash_part, HashAlgorithm.crc32, 32w0, {meta.dstip_hash_part}, 32w32);
    }
    action hash_and_modify_dst8_action() { 
        hash(meta.dstip_hash_part, HashAlgorithm.crc32_custom, 32w0, {meta.dstip_hash_part}, 32w24);
    }
    action hash_and_modify_dst16_action() { 
        hash(meta.dstip_hash_part, HashAlgorithm.crc16, 32w0, {meta.dstip_hash_part}, 32w16);
    }
    action hash_and_modify_dst24_action() { 
        hash(meta.dstip_hash_part, HashAlgorithm.crc16_custom, 32w0, {meta.dstip_hash_part}, 32w8);
    }
    
    action ip_overwrite_action() { 
        hdr.ipv4.srcAddr = meta.srcip_subnet_part | meta.srcip_hash_part;
        hdr.ipv4.dstAddr = meta.dstip_subnet_part | meta.dstip_hash_part;

    }
    
    action arp_ip_overwrite_action() { 
        hdr.arp_ipv4.srcProtoAddr = meta.srcip_subnet_part | meta.srcip_hash_part;
        hdr.arp_ipv4.dstProtoAddr = meta.dstip_subnet_part | meta.dstip_hash_part;
    }


    /************ CONTROL ************/
    table anony_mac_src_id_tb {
        key =  {
            standard_metadata.ingress_port : exact;
        }
        actions  = {
            hash_mac_src_id_action;
            nop_action;
        }
    }
    
    table anony_mac_src_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions =  {
            hash_mac_src_oui_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_src_id_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_arp_mac_src_id_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_src_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions  = {
            hash_arp_mac_src_oui_action;
            nop_action;
        }
    }
    
    table anony_mac_dst_id_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_mac_dst_id_action;
            nop_action;
        }
    }
    
    table anony_mac_dst_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions =  {
            hash_mac_dst_oui_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_dst_id_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_arp_mac_dst_id_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_dst_oui_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_arp_mac_dst_oui_action;
            nop_action;
        }
    }
    
    table anony_srcip_tb {
        key = {
            meta.ipv4_srcip : ternary;
        }
        actions =  {
            prepare_srcip_hash_action;
            nop_action;
        }
    }
    
    table anony_dstip_tb {
        key = {
            meta.ipv4_dstip : ternary;
        }
    
        actions = {
            prepare_dstip_hash_action;
            nop_action;
        }
    }
    
    table hashing_src0_tb {
        key = {
             standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_src0_action;
            nop_action;
        }
    }
    
    table hashing_src8_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_src8_action;
            nop_action;
        }
    }
    
    table hashing_src16_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_src16_action;
            nop_action;
        }
    }
    
    table hashing_src24_tb {
        key= {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_src24_action;
            nop_action;
        }
    }
    
    table hashing_dst0_tb {
        key =  {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_dst0_action;
            nop_action;
        }
    }
    
    table hashing_dst8_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_dst8_action;
            nop_action;
        }
    }
    table hashing_dst16_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_dst16_action;
            nop_action;
        }
    }
    table hashing_dst24_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            hash_and_modify_dst24_action;
            nop_action;
        }
    }
    
    table forward_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_egr_action;
            nop_action;
        }
    }
    
    table multicast_mac_catch_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            multicast_mac_catch_action;
        }
    }
    
    table arp_ip_overwrite_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            arp_ip_overwrite_action;
        }
    }
    
    table ipv4_ip_overwite_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            ip_overwrite_action;
        }
    }
    
    apply {
        // Needed for catching multicast packets
        //  based on DST MAC address (starts with 01:xx:xx:xx:xx:xx)
        multicast_mac_catch_tb.apply();

        // Anonymize SRC MAC
        anony_mac_src_oui_tb.apply();
        anony_mac_src_id_tb.apply();

        // Only anonymize if DST MAC indicates
        //  that it's not a broadcast or multicast packet.
        if (hdr.ethernet.dstAddr_oui!=0xffffff) {
            if (hdr.ethernet.dstAddr_id!=0xffffff) {
                if (meta.dst_mac_mc_oui!=0x010000) {
                    anony_mac_dst_oui_tb.apply();
                    anony_mac_dst_id_tb.apply();
                }
            }
        }

        // If ARP reply and DST MAC is hashed,
        //   hash DST MAC in ARP packet too.
        if (hdr.arp.opcode == 2) {
            if (meta.hashed_mac_dstAddr_id == 1) {
                anony_arp_mac_dst_id_tb.apply();
            }
            if (meta.hashed_mac_dstAddr_oui == 1) {
                anony_arp_mac_dst_oui_tb.apply();
            }
        }

        // If SRC MAC is hashed,
        //   hash SRC MAC in ARP packet too.
        if (meta.hashed_mac_srcAddr_id == 1) {
            anony_arp_mac_src_id_tb.apply();
        }
        if (meta.hashed_mac_srcAddr_oui == 1) {
            anony_arp_mac_src_oui_tb.apply();
        }

        // Anoymize IPv4 SRC address (prep step)
        anony_srcip_tb.apply();
        if (meta.srcip_subnetmask == 0x0) {
            hashing_src0_tb.apply();
        }
        else if (meta.srcip_subnetmask == 0xff000000) {
            hashing_src8_tb.apply();
        }
        else if (meta.srcip_subnetmask == 0xffff0000) {
            hashing_src16_tb.apply();
        }
        else {
            hashing_src24_tb.apply();
        }

        // Anoymize IPv4 DST address (prep step)
        anony_dstip_tb.apply();
        if (meta.dstip_subnetmask == 0x0) {
            hashing_dst0_tb.apply();
        }
        else if (meta.dstip_subnetmask == 0xff000000) {
            hashing_dst8_tb.apply();
        }
        else if (meta.dstip_subnetmask == 0xffff0000) {
            hashing_dst16_tb.apply();
        }
        else {
            hashing_dst24_tb.apply();
        }

        // If ARP packet, and should anonymize IPv4, 
        //  anonymize IP address in ARP packet.
        if (meta.is_arp == 1) {
            arp_ip_overwrite_tb.apply();
        }

        // Actual IPv4 address anonymization step
        if (meta.is_ipv4 == 1) {
            ipv4_ip_overwite_tb.apply();
        }

        // Forward packet based on input_port
        forward_tb.apply();
    }
}


control OntasEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control OntasComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	    update_checksum(
	    hdr.ipv4.isValid(),
        {     hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}


/*************************************************************************
 * ***********************  D E P A R S E R  *******************************
 * *************************************************************************/

control OntasDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}



/*************************************************************************
 * ***********************  S W I T C H  *******************************
 * *************************************************************************/

V1Switch(
    OntasParser(),
    OntasVerifyChecksum(),
    OntasIngress(),
    OntasEgress(),
    OntasComputeChecksum(),
    OntasDeparser()
) main;
