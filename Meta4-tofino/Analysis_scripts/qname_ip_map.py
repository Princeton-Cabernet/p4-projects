################################################################################
# Python script for qname-ip mappting
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
#import time,pytz, calendar
import json
#from scapy.all import *

def make_dictionary(input_file):

    # dictionary { ip : (set_of_qnames, set_of_int(epochs)) }
    ip_qname_map = {}

    # Read file
    fd = open(input_file, 'r')
    entries = fd.readlines()

    # Go through file
    for e in entries:
        epoch, qname, ip_list = "","",""
        splitted = e.split("\t")
        if len(splitted) == 3:
            epoch, qname, ip_list = [str(i) for i in splitted]
        else:
            print("Weird entry. Print and ignore: ", splitted)
            continue

        # Get IP list. Make epoch to int.
        ip_list = ip_list.rstrip("\n").split(",")
        epoch = int(float(epoch))

        # Go through IPs
        for ip in ip_list:
            if ip in ip_qname_map:
                val_in_map_tuple = ip_qname_map[ip]
#                if qname != val_in_map_tuple[0]:
#                    print ("Mismatch present: {}:{},{}".format(ip,qname, val_in_map_tuple[0]))

                # add this qname to qname set 
                qname_set = val_in_map_tuple[0]
                qname_set.add(qname)

                # add this epoch to epoch set
                epoch_set = val_in_map_tuple[1]
                epoch_set.add(epoch)

                # update 
                val_tuple = (qname_set,epoch_set)
                ip_qname_map[ip] = val_tuple
            else:
                val_tuple = (set([qname]),set([epoch]))
                ip_qname_map[ip] = val_tuple
        
#    for e in ip_qname_map:
#        print (e,ip_qname_map[e])

    return ip_qname_map


def save_data_as_pickle(data, filename, output_dir):
    print ('\nSaving Result: %s\n' %(str(filename) + '.p'))
    pickle_fd = open(str(output_dir) + str(filename) + '.p','wb')
    pickle.dump(data,pickle_fd)
    pickle_fd.close()


def main(): 
    parser = argparse.ArgumentParser(description='Script for qname-ip mapping')
    parser.add_argument('-i', dest='input_file', action='store', required=True,
                        help='tshark script output file')
    parser.add_argument('-o', dest='output_pickle', action='store', required=True,
                        help='Output pickle file')

    # Parse
    args = parser.parse_args()

    # Check number of arguments. 
    if len(sys.argv[1:])!=4:
        print ("\nERROR: Wrong number of parameters. \n")
        parser.print_help()
        sys.exit(-1)

    # Check validity of option values
    if os.path.isfile(args.input_file) is False:
        print ("\nERROR: Specifid file does not exist. Abort.\n")
        parser.print_help()
        sys.exit(-1)

    # Make dictionary
    ip_qname_map = make_dictionary(args.input_file)
    save_data_as_pickle(ip_qname_map, args.output_pickle, "./")


if __name__ == '__main__':
    main()


