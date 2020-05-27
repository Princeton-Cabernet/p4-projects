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



#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/************ HEADERS ************/

header_type ethernet_t { 
    fields { 
        dstAddr_oui : 24;
        dstAddr_id  : 24;
        srcAddr_oui : 24;
        srcAddr_id  : 24;
        etherType   : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 12;
        etherType : 16;
    }
}

header_type arp_rarp_t {
    fields {
        hwType  : 16;
        protoType  : 16;
        hwAddrLen  : 8;
        protoAddrLen  : 8;
        opcode  : 16;
    }
}

header_type arp_rarp_ipv4_t {
    fields {
        srcHwAddr_oui : 24;
        srcHwAddr_id : 24;
        srcProtoAddr  : 32;
        dstHwAddr_oui  : 24;
        dstHwAddr_id  : 24;
        dstProtoAddr  : 32;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        hdr_length : 16;
        checksum : 16;
    }
}

header_type local_metadata_t {
    fields {
        is_arp : 4;
        is_ipv4: 4;
        hashed_mac_srcAddr_oui : 4;
        hashed_mac_srcAddr_id : 4;
        hashed_mac_dstAddr_oui : 4;
        hashed_mac_dstAddr_id : 4;
        dst_mac_mc_oui    : 24;
        src_mac_oui       : 24;
        src_mac_id        : 24;
        dst_mac_oui       : 24;
        dst_mac_id        : 24;
        ipv4_srcip : 32;
        ipv4_dstip : 32;
        srcip_subnet_part : 32;
        srcip_hash_part   : 32;
        dstip_subnet_part : 32;
        dstip_hash_part   : 32;
        srcip_subnetmask  : 32;
        dstip_subnetmask  : 32;
    }
}

