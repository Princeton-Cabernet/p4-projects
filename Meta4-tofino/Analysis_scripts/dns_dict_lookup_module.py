################################################################################
# Python methods to lookup hostname with IP address
#  - Description: 
#  - Author: Hyojoon Kim (joonk@princeton.edu)
################################################################################

################################################################################
# Copyright (C) 2020  Hyojoon Kim (Princeton University)
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
################################################################################

import pickle
import os,sys
import ipaddress

PRINCETON_SUBNETS = [ipaddress.ip_network(x) for x in \
                     ["128.112.0.0/16", "140.180.0.0/16", "204.153.48.0/23","66.180.176.0/24","66.180.177.0/24","66.180.180.0/22"]]


def check_if_princeton(ip_str):
    ipaddr = ipaddress.ip_address(ip_str)
    for subnet in PRINCETON_SUBNETS:
        if ipaddr in subnet:
            return True
    return False


def lookup_ip(ip_str, ip_to_qname_map):

    if ip_str in ip_to_qname_map:
        qname_set = ip_to_qname_map[ip_str][0]
        return ",".join(qname_set)

    return ""


def read_dictionary(filename):

    ip_to_qname_map = {}
    with open(filename,'rb') as pickle_fd:
        ip_to_qname_map = pickle.load(pickle_fd)

    return ip_to_qname_map
