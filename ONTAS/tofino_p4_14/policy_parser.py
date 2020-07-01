################################################################
# Python Script
#  - Description: Script for parsing policy
#  - Author: Hyojoon Kim (joonk@princeton.edu)
################################################################

#/**********************************************************************
# *  Copyright 2020 Hyojoon Kim. Princeton University.
# *
# *  Licensed under the Apache License, Version 2.0 (the "License");
# *  you may not use this file except in compliance with the License.
# *  You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# *  Unless required by applicable law or agreed to in writing, software
# *  distributed under the License is distributed on an "AS IS" BASIS,
# *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# *  See the License for the specific language governing permissions and
# *  limitations under the License.
#**********************************************************************/



import argparse
import os,sys,copy
import ipaddress
import requests
import json


def read_configuration_file(config_file):
    fd = open(config_file, 'r')
    tmp_list = fd.readlines()
    json_string = ""
    for l in tmp_list:
        if not l.startswith('#'):
            json_string += (l)
    json_string = json_string[:-1]
    gconfig = json.loads(json_string)
    fd.close()

    return gconfig


def validate_config(gconfig):
    for key in gconfig:
        if gconfig[key] == "yes":
            gconfig[key] = 1
        elif gconfig[key] == "no":
            gconfig[key] = 0
        elif key=="anonymize_srcipv4" or key=="anonymize_dstipv4":
            for prefix in gconfig[key]:
                try:
                    ipaddress.ip_network(prefix, strict=False)
                except:
                    print('Wrong IPv4 prefix format in config file: "{}". Abort.'.format(prefix))
                    return
        elif key!="inport" and key!="outport":
            print('Wrong option value in  config file: "{}:{}". Abort.'.format(key,gconfig[key]))
            return 
    return gconfig


def translate_to_entries(gconfig):
    table_cmds = ''

    # Multicast, Broadcast 
    if not gconfig["anonymize_multicast_broadcast"]:
        table_cmds += "table_add multicast_mac_catch_tb multicast_mac_catch_action {} =>\n".format(gconfig["inport"])

    # SRC and DST MAC     
    if gconfig["anonymize_srcmac_oui"]:
        table_cmds += "table_add anony_mac_src_oui_tb {} =>\n".format(gconfig["inport"])
    else:
        table_cmds += "table_set_default anony_mac_src_oui_tb nop_action\n"
    if gconfig["anonymize_srcmac_id"]:
        table_cmds += "table_add anony_mac_src_id_tb hash_mac_src_id_action {} =>\n".format(gconfig["inport"])
    else:
        table_cmds += "table_set_default anony_mac_src_id_tb nop_action\n"
    if gconfig["anonymize_dstmac_oui"]:
        table_cmds += "table_add anony_mac_dst_oui_tb {} =>\n".format(gconfig["inport"])
    else:
        table_cmds += "table_set_default anony_mac_dst_oui_tb nop_action\n"
    if gconfig["anonymize_dstmac_id"]:
        table_cmds += "table_add anony_mac_dst_id_tb hash_mac_dst_id_action {} =>\n".format(gconfig["inport"])
    else:
        table_cmds += "table_set_default anony_mac_dst_id_tb nop_action\n"
 
    # IP address
    for prefix in gconfig["anonymize_srcipv4"]:
        ipv4addr = ipaddress.ip_network(prefix, strict=False)
        mask1 = int(ipv4addr.netmask)
        table_cmds += "table_add anony_srcip_tb prepare_srcip_hash_action {} {} => {} {} 1\n".format(ipv4addr.network_address,ipv4addr.netmask,mask1,0xffffffff-mask1)
    for prefix in gconfig["anonymize_dstipv4"]:
        ipv4addr = ipaddress.ip_network(prefix, strict=False)
        mask1 = int(ipv4addr.netmask)
        table_cmds += "table_add anony_dstip_tb prepare_dstip_hash_action {} {} => {} {} 1\n".format(ipv4addr.network_address,ipv4addr.netmask,mask1,0xffffffff-mask1)
    
    table_cmds += "table_set_default ipv4_ip_overwite_tb ip_overwrite_action\n"
 
    # ARP 
    if gconfig["anonymize_mac_in_arphdr"]:
        table_cmds += "table_set_default anony_arp_mac_src_id_tb hash_arp_mac_src_id_action\n"
        table_cmds += "table_set_default anony_arp_mac_src_oui_tb hash_arp_mac_src_oui_action\n"
        table_cmds += "table_set_default anony_arp_mac_dst_id_tb hash_arp_mac_dst_id_action\n"
        table_cmds += "table_set_default anony_arp_mac_dst_oui_tb hash_arp_mac_dst_oui_action\n"
    else:
        table_cmds += "table_set_default anony_arp_mac_src_id_tb nop_action\n"
        table_cmds += "table_set_default anony_arp_mac_src_oui_tb nop_action\n"
        table_cmds += "table_set_default anony_arp_mac_dst_id_tb nop_action\n"
        table_cmds += "table_set_default anony_arp_mac_dst_oui_tb nop_action\n"

    if gconfig["anonymize_ipv4_in_arphdr"]:
        table_cmds += "table_set_default arp_ip_overwrite_tb arp_ip_overwrite_action\n"
    else:
        table_cmds += "table_set_default arp_ip_overwrite_tb nop_action\n"

    # output
    table_cmds += "table_add forward_tb set_egr_action {} => {}\n".format(gconfig["inport"], gconfig["outport"])

#    print(table_cmds)
    return table_cmds


## Main function ##     
def main():

    parser = argparse.ArgumentParser(description='Script to parse anonymization policy')
    parser.add_argument('-c', dest='config_file', action='store', required=True,
                        help='Configuration file')
    parser.add_argument('-o', dest='output_file', action='store', required=True,
                        help='Output file')

    # Parse
    args = parser.parse_args()

    # Check number of arguments. 
    if len(sys.argv[1:])<4:
        print ("\nERROR: Wrong number of parameters. -c and -o are required.\n")
        parser.print_help()
        sys.exit(-1)

    # Check validity of option values
    if os.path.isfile(args.config_file) is False:
        print ("\nERROR: Specifid configuration file does not exist. Abort.\n")
        parser.print_help()
        sys.exit(-1)

    # Read configuration
    gconfig = read_configuration_file(args.config_file)
    gconfig = validate_config(gconfig)
    if not gconfig:
        print ("\nERROR: Error in configuration file. Abort.\n")
        sys.exit(-1)

    # Translate to flow table entries and save.
    table_cmds = translate_to_entries(gconfig)
    fd = open(args.output_file, 'w+')
    fd.write(table_cmds)
    fd.close()


if __name__ == '__main__':
    main()
