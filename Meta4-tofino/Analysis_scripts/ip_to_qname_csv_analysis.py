################################################################################
# Python script for ..
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

import argparse, pickle
import os,sys,copy,datetime
import ipaddress
import operator
import socket
#import time,pytz, calendar
import json
#from scapy.all import *

PRINCETON_SUBNETS = [ipaddress.ip_network(x) for x in \
                     ["128.112.0.0/16", "140.180.0.0/16", "204.153.48.0/23","66.180.176.0/24","66.180.177.0/24","66.180.180.0/22"]]
EPOCH_THRESHOLD = 1585672304

def check_if_princeton(ip_str):
    ipaddr = ipaddress.ip_address(ip_str)
    for subnet in PRINCETON_SUBNETS:
        if ipaddr in subnet:
            return True
    return False

def check_directory_and_add_slash(path):
    return_path = path
  
    # No path given  
    if return_path == None:
        print ("None is given as path. Check given parameter.")
        return ''
      
    # Path is not a directory, or does not exist.  
    if os.path.isdir(return_path) is False:
        print ("Path is not a directory, or does not exist.: '%s'. Abort" % (return_path))
        return ''
  
    # Add slash if not there.  
    if return_path[-1] != '/':
        return_path = return_path + '/'
  
    # Return
    return return_path



def check_ip_and_direction(src_ip, dst_ip):
    
    ip_to_check = None
    is_incoming = True

    is_src_inside = check_if_princeton(src_ip)
    is_dst_inside = check_if_princeton(dst_ip)

    if is_src_inside and is_dst_inside:
        pass # TODO what to do if both are in Princeton?
    elif is_src_inside:
        ip_to_check = dst_ip
        is_incoming = False
    else:
        ip_to_check = src_ip
        is_incoming = True

    return ip_to_check, is_incoming


def get_qname(ip_to_check, epoch, ip_to_qname_map):
    qname = "Other"

    # Get value with key. 
    qnameset_epochset_tuple = ip_to_qname_map.get(ip_to_check)
    if qnameset_epochset_tuple is None:
        qname = "Other"
#        try: 
#            data = socket.gethostbyaddr(ip_to_check)
#            qname = data[0]
#        except socket.herror:
#            qname = "Other"
    else:
        within_epoch_threshold = False
        epochset = qnameset_epochset_tuple[1]
        for e in epochset:
            if abs(e-epoch) < EPOCH_THRESHOLD:
                within_epoch_threshold = True
                break
        if within_epoch_threshold is False:
            qname = "Other" #TODO? 
            print("Cannot find DNS exchange within time threshold: {}".format(ip_to_check))
        else:
            qname = str(qnameset_epochset_tuple[0])

    return qname


def run_analysis(input_f, ip_to_qname_map, usage_map):

    entry_list = []

    with open(input_f, 'r') as fd:
        entry_list = fd.readlines()

    # lets go
    for entry in entry_list:
        e = entry.split('\t')
        print(e)
        src_ip, dst_ip, used_bytes, epoch = e[21], e[22], int(e[-3]), float(e[-1].rstrip("\n"))
     
        # which one is not not princeton ip? in or out?
        ip_to_check, is_incoming_bool = check_ip_and_direction(src_ip, dst_ip)

        # get qname and used bytes
        qname = get_qname(ip_to_check, epoch, ip_to_qname_map)

        # update
        new_val = tuple()
        if qname in usage_map:
            in_map_val = usage_map[qname]
            new_val = (in_map_val[0] + used_bytes, in_map_val[1] + 1)
        else:
            new_val = (used_bytes, 1)
        usage_map[qname] = new_val

        # Update total
        new_tot_val = tuple()
        if "Total" in usage_map:
            tot_in_map = usage_map["Total"]
            new_tot_val = (tot_in_map[0] + used_bytes, tot_in_map[1] + 1)
        else:
            new_tot_val = (used_bytes, 1)
        usage_map["Total"] = new_tot_val

def run_analysis_dir(input_dir, ip_to_qname_map, usage_map):

    files = os.listdir(input_dir)
    for f in files:
        if f.endswith(".csv"):
            print("Processing {}...".format(input_dir+f))
            run_analysis(input_dir+f, ip_to_qname_map, usage_map)


def save_data_as_pickle(data, filename, output_dir):
    print ('\nSaving Result: %s\n' %(str(filename) + '.p'))
    pickle_fd = open(str(output_dir) + str(filename) + '.p','wb')
    pickle.dump(data,pickle_fd)
    pickle_fd.close()


def sort_map_by_value(the_map):

  # list of tuples (key, value)
  sorted_tup = sorted(the_map.items(), key=operator.itemgetter(1), reverse=True)

  # Returns a list of tuples [(key, value),]
  return sorted_tup


def main(): 
    parser = argparse.ArgumentParser(description='Script for qname-ip mapping')
    parser.add_argument('-i', dest='input_f', action='store', required=True,
                        help='Input directory where the CSV files are')
    parser.add_argument('-p', dest='input_pickle', action='store', required=True,
                        help='Pickled file that has ip-qname mapping')
    parser.add_argument('-o', dest='output_pickle', action='store', required=True,
                        help='Output pickle file')

    # Parse
    args = parser.parse_args()

    # Check number of arguments. 
    if len(sys.argv[1:])!=6:
        print ("\nERROR: Wrong number of parameters. \n")
        parser.print_help()
        sys.exit(-1)

    # Load ip-qname_epoch dictionary
    ip_to_qname_map = {}
    with open(args.input_pickle,'rb') as pickle_fd:
        ip_to_qname_map = pickle.load(pickle_fd)
  
    usage_map = {} # { qname: (bytes, num_packets) }
    usage_map["Total"] = (0,0)
    if os.path.isfile(args.input_f):        # If input is file,
        run_analysis(args.input_f, ip_to_qname_map, usage_map)
    elif os.path.isdir(args.input_f):       # If input is directory,
        input_dir = check_directory_and_add_slash(args.input_f)
        run_analysis_dir(input_dir, ip_to_qname_map, usage_map)
    else:                                   # If none of above, something is wrong.
        print("Either file or directory is incorrect. Abort.\n")
        sys.exit(-1)

    # Sort by num_packets
    if usage_map:

        # Save result
        save_data_as_pickle(usage_map, args.output_pickle, "./")

        # print
        sorted_x = sorted(usage_map.items(), key=operator.itemgetter(1))
        for s in sorted_x:
            print(s)

if __name__ == '__main__':
    main()

