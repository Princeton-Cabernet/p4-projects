/**********************************************************************
 *  P4 ONTAS.
 *  Copyright 2020 Hyojoon Kim. Princeton University.
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
#include "includes/p4anony_fieldlists.p4"
#include "includes/p4anony_actions.p4"

calculated_field ipv4.hdrChecksum  {
//    verify ipv4_checksum;
    update ipv4_checksum;
}

parser_exception p4_pe_default {
    return ingress;
}

parser_exception p4_pe_checksum {
    return ingress;
}


/**** CREATE HEADER INSTANCES ****/

header ethernet_t ethernet;
header vlan_tag_t vlan;
header arp_rarp_t arp;
header arp_rarp_ipv4_t arp_ipv4;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;
metadata local_metadata_t localm;


/************ PARSERS ************/

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    set_metadata(localm.src_mac_oui, latest.srcAddr_oui);
    set_metadata(localm.src_mac_id, latest.srcAddr_id);
    set_metadata(localm.dst_mac_oui, latest.dstAddr_oui);
    set_metadata(localm.dst_mac_id, latest.dstAddr_id);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_ARP : parse_arp;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(localm.is_ipv4, 1);
    set_metadata(localm.ipv4_srcip, latest.srcAddr);
    set_metadata(localm.ipv4_dstip, latest.dstAddr);
    set_metadata(localm.srcip_subnet_part, latest.srcAddr);
    set_metadata(localm.dstip_subnet_part, latest.dstAddr);

    return select(latest.fragOffset, latest.protocol) {
        IPPROTO_TCP : parse_tcp;
        IPPROTO_UDP : parse_udp;
        default: ingress;
    }
}

parser parse_vlan {
    extract(vlan);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_arp {
    extract(arp);
    return select(latest.protoType) {
        ETHERTYPE_IPV4 : parse_arp_rarp_ipv4;
        default : ingress;
    }
}

parser parse_arp_rarp_ipv4 {
    extract(arp_ipv4);
    set_metadata(localm.is_arp, 1);
    set_metadata(localm.ipv4_srcip, latest.srcProtoAddr);
    set_metadata(localm.ipv4_dstip, latest.dstProtoAddr);
    set_metadata(localm.srcip_subnet_part, latest.srcProtoAddr);
    set_metadata(localm.dstip_subnet_part, latest.dstProtoAddr);
    return ingress;
}

parser parse_tcp {
    extract(tcp);
    return ingress;
}

parser parse_udp {
    extract(udp);
    return ingress;
}


/************ CONTROL ************/

table anony_mac_src_id_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }

    actions {
        hash_mac_src_id_action;
        nop_action;
    }
}

table anony_mac_src_oui_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_mac_src_oui_action;
        nop_action;
    }
}

table anony_arp_mac_src_id_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_arp_mac_src_id_action;
        nop_action;
    }
}

table anony_arp_mac_src_oui_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_arp_mac_src_oui_action;
        nop_action;
    }
}

table anony_mac_dst_id_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }

    actions {
        hash_mac_dst_id_action;
        nop_action;
    }
}

table anony_mac_dst_oui_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_mac_dst_oui_action;
        nop_action;
    }
}

table anony_arp_mac_dst_id_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_arp_mac_dst_id_action;
        nop_action;
    }
}

table anony_arp_mac_dst_oui_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }

    actions {
        hash_arp_mac_dst_oui_action;
        nop_action;
    }
}

table anony_srcip_tb {
    reads {
//        ig_intr_md.ingress_port : exact;
        localm.ipv4_srcip : ternary;
    }
    actions {
        prepare_srcip_hash_action;
        nop_action;
    }
}

table anony_dstip_tb {
    reads {
//        ipv4.dstAddr : ternary;
        localm.ipv4_dstip : ternary;
    }

    actions {
        prepare_dstip_hash_action;
        nop_action;
    }
}

table hashing_src0_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_src0_action;
        nop_action;
    }
}

table hashing_src8_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_src8_action;
        nop_action;
    }
}

table hashing_src16_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_src16_action;
        nop_action;
    }
}

table hashing_src24_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_src24_action;
        nop_action;
    }
}

table hashing_dst0_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_dst0_action;
        nop_action;
    }
}

table hashing_dst8_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_dst8_action;
        nop_action;
    }
}
table hashing_dst16_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_dst16_action;
        nop_action;
    }
}
table hashing_dst24_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        hash_and_modify_dst24_action;
        nop_action;
    }
}

table forward_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_egr_action;
        nop_action;
    }
}

table multicast_mac_catch_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        multicast_mac_catch_action;
    }
}

table arp_ip_overwrite_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        arp_ip_overwrite_action;
    }
}

table ipv4_ip_overwite_tb {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        ip_overwrite_action;
    }
}

/*
 *table acl_tb {
 *    reads {
 *        ethernet.dstAddr : ternary;
 *        ethernet.srcAddr : ternary;
 *    }
 *    actions {
 *        nop_action;
 *        _drop_action;
 *    }
 *}
 */

control ingress {

    // Needed for catching multicast packets
    //  based on DST MAC address (starts with 01:xx:xx:xx:xx:xx)
    apply(multicast_mac_catch_tb);

    // Anonymize SRC MAC
    apply(anony_mac_src_oui_tb);
    apply(anony_mac_src_id_tb);

    // Only anonymize if DST MAC indicates
    //  that it's not a broadcast or multicast packet.
    if (ethernet.dstAddr_oui!=0xffffff) {
        if (ethernet.dstAddr_id!=0xffffff) {
            if (localm.dst_mac_mc_oui!=0x010000) {
                apply(anony_mac_dst_oui_tb);
                apply(anony_mac_dst_id_tb);
            }
        }
    }

    // If ARP reply and DST MAC is hashed,
    //   hash DST MAC in ARP packet too.
    if (arp.opcode == 2) {
        if (localm.hashed_mac_dstAddr_id == 1) {
            apply(anony_arp_mac_dst_id_tb);
        }
        if (localm.hashed_mac_dstAddr_oui == 1) {
            apply(anony_arp_mac_dst_oui_tb);
        }
    }

    // If SRC MAC is hashed,
    //   hash SRC MAC in ARP packet too.
    if (localm.is_arp == 1) {
        if (localm.hashed_mac_srcAddr_id == 1) {
            apply(anony_arp_mac_src_id_tb);
        }
        if (localm.hashed_mac_srcAddr_oui == 1) {
            apply(anony_arp_mac_src_oui_tb);
        }
    }

    // Anoymize IPv4 SRC address (prep step)
    apply(anony_srcip_tb);
    if (localm.srcip_subnetmask == 0x0) {
        apply(hashing_src0_tb);
    }
    else if (localm.srcip_subnetmask == 0xff000000) {
        apply(hashing_src8_tb);
    }
    else if (localm.srcip_subnetmask == 0xffff0000) {
        apply(hashing_src16_tb);
    }
    else {
        apply(hashing_src24_tb);
    }

    // Anoymize IPv4 DST address (prep step)
    apply(anony_dstip_tb);
    if (localm.dstip_subnetmask == 0x0) {
        apply(hashing_dst0_tb);
    }
    else if (localm.dstip_subnetmask == 0xff000000) {
        apply(hashing_dst8_tb);
    }
    else if (localm.dstip_subnetmask == 0xffff0000) {
        apply(hashing_dst16_tb);
    }
    else {
        apply(hashing_dst24_tb);
    }

    // If ARP packet, and should anonymize IPv4, 
    //  anonymize IP address in ARP packet.
    if (localm.is_arp == 1) {
        apply(arp_ip_overwrite_tb);
    }

    // Actual IPv4 address anonymization step
    if (localm.is_ipv4 == 1) {
        apply(ipv4_ip_overwite_tb);
    }

    // Forward packet based on input_port
    apply(forward_tb);
}

control egress {
//    apply(acl);
}

