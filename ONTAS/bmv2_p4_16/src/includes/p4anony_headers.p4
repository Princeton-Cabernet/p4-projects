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


#include <core.p4>
#include <v1model.p4>


#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/************ HEADERS ************/

typedef bit<24> srcAddr_oui_t;
typedef bit<24> srcAddr_id_t;
typedef bit<24> dstAddr_oui_t;
typedef bit<24> dstAddr_id_t;

header ethernet_t { 
    dstAddr_oui_t dstAddr_oui;
    dstAddr_id_t  dstAddr_id;
    srcAddr_oui_t srcAddr_oui;
    srcAddr_id_t  srcAddr_id;
    bit<16> etherType;
}

header vlan_tag_t {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> etherType;
}

header arp_rarp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
}

header arp_rarp_ipv4_t {
    srcAddr_oui_t srcHwAddr_oui;
    srcAddr_id_t srcHwAddr_id;
    bit<32> srcProtoAddr;
    dstAddr_oui_t dstHwAddr_oui;
    dstAddr_id_t dstHwAddr_id;
    bit<32> dstProtoAddr;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> hdr_length;
    bit<16> checksum;
}


