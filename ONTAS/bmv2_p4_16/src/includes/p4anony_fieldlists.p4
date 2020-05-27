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



/************ FIELD_LISTS ************/

field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}


field_list ipv4_srcaddr_part {
    localm.srcip_hash_part;
}

field_list ipv4_dstaddr_part {
    localm.dstip_hash_part;
}

field_list mac_srcaddr_id {
//    ethernet.srcAddr_id;
    localm.src_mac_id;
}

field_list mac_srcaddr_oui {
//    ethernet.srcAddr_oui;
    localm.src_mac_oui;
}

field_list mac_dstaddr_id {
//    ethernet.dstAddr_id;
    localm.dst_mac_id;
}

field_list mac_dstaddr_oui {
//    ethernet.dstAddr_oui;
    localm.dst_mac_oui;
}

field_list_calculation ipv4_src_part_calc0 {
    input {
        ipv4_srcaddr_part;
    }
    algorithm : crc32;
    output_width : 32;
}

field_list_calculation ipv4_src_part_calc8 {
    input {
        ipv4_srcaddr_part;
    }
    algorithm : crc32;
    output_width : 24;
}

field_list_calculation ipv4_src_part_calc16 {
    input {
        ipv4_srcaddr_part;
    }
    algorithm : crc32;
    output_width : 16;
}

field_list_calculation ipv4_src_part_calc24 {
    input {
        ipv4_srcaddr_part;
    }
    algorithm : crc32;
    output_width : 8;
}

field_list_calculation ipv4_dst_part_calc0 {
    input {
        ipv4_dstaddr_part;
    }
    algorithm : crc32;
    output_width : 32;
}
field_list_calculation ipv4_dst_part_calc8 {
    input {
        ipv4_dstaddr_part;
    }
    algorithm : crc32;
    output_width : 24;
}
field_list_calculation ipv4_dst_part_calc16 {
    input {
        ipv4_dstaddr_part;
    }
    algorithm : crc32;
    output_width : 16;
}
field_list_calculation ipv4_dst_part_calc24 {
    input {
        ipv4_dstaddr_part;
    }
    algorithm : crc32;
    output_width : 8;
}

field_list_calculation mac_src_calc_id {
    input {
        mac_srcaddr_id;
    }
    algorithm : crc32;
    output_width : 24;
}

field_list_calculation mac_src_calc_oui {
    input {
        mac_srcaddr_oui;
    }
    algorithm : crc32;
    output_width : 24;
}

field_list_calculation mac_dst_calc_id {
    input {
        mac_dstaddr_id;
    }
    algorithm : crc32;
    output_width : 24;
}

field_list_calculation mac_dst_calc_oui {
    input {
        mac_dstaddr_oui;
    }
    algorithm : crc32;
    output_width : 24;
}


