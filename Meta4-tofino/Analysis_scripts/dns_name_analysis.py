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
import plot_lib
import ipwhois
from pathlib import Path
#from scapy.all import *


def sort_map_by_value(the_map):

  # list of tuples (key, value)
  sorted_tup = sorted(the_map.items(), key=operator.itemgetter(1), reverse=True)

  # Returns a list of tuples [(key, value),]
  return sorted_tup



def dns_analysis_2(ip_to_qname_map, pickle_fname, output_dir):

    all_domains_set = set()
    domain_to_ndomains_map = {}

    pickle_file = Path(pickle_fname)
    if pickle_file.is_file():
        print("Pickled domain_to_ndomains_map exists. Read it.")
        with open(pickle_file,'rb') as pickle_fd:
            domain_to_ndomains_map = pickle.load(pickle_fd)
    else: 
        print("Pickled domain_to_ndomains_map does not exist. Create.")
        # For through IPs
        for ip in ip_to_qname_map:
            # Skip localhost IPs (blacklists by spam filters, like spamhaus)
            if ipaddress.ip_address(ip) in ipaddress.ip_network('127.0.0.0/24'):
                continue

            # get domain set for the iP    
            domain_set = ip_to_qname_map[ip][0]
            all_domains_set.update(domain_set)

        print("Number of unique domains: {}".format(len(all_domains_set)))

        # Go through all domains
        for d in all_domains_set:
            # Go through all IPs
            for ip in ip_to_qname_map:
                domain_set = ip_to_qname_map[ip][0]
                if d in domain_set:
                    if d in domain_to_ndomains_map:
                        domain_to_ndomains_map[d] = max(domain_to_ndomains_map[d], len(domain_set))
                    else:
                        domain_to_ndomains_map[d] = len(domain_set)
 

        # Save
        with open(pickle_fname, 'wb') as f:
            pickle.dump(domain_to_ndomains_map, f)

    # Number of domains list.       
    number_of_domains = list(domain_to_ndomains_map.values())
    #print(number_of_domains)
    print("Number of unique domains: {}".format(len(domain_to_ndomains_map)))

    # Get CDF    
    x, y = plot_lib.get_cdf2(number_of_domains)

    print("Plotting...")

    # Plot
    plot_lib.plot_singleline(x, y, output_dir, "cdf_xdomains2.png", xlabel_name="Number of domains", ylabel_name="CDF",
                             title="CDF: Number of domains that appear with a domain", xlogscale=True,ylogscale=False,pointdot=True,ccdf=False)



def dns_analysis(ip_to_qname_map, output_dir):
    n_domains_list = []
    n_domains_dict = {}

    # For through IPs
    for ip in ip_to_qname_map:
        # Skip localhost IPs (blacklists by spam filters, like spamhaus)
        if ipaddress.ip_address(ip) in ipaddress.ip_network('127.0.0.0/24'):
            continue

        # get domain set for the iP    
        domain_set = ip_to_qname_map[ip][0]
        n_domains_list.append(len(domain_set))

        # Save the number of unique domains
        n_domains_dict[ip] = len(domain_set)

    # Sort by number of domains
    sorted_tup = sort_map_by_value(n_domains_dict)

    # Go through the sorted list
    for i in range(50):
        ip_str = sorted_tup[i][0]
        unique_domain_list = list(ip_to_qname_map[ip_str][0])

        whois = ipwhois.IPWhois(ip_str)
        whois_name = ""
        whois_desc = ""
        if whois:
            lookup = whois.lookup_whois()
            if lookup and "nets" in lookup:
                whois_name = whois.lookup_whois()["nets"][0]["name"]
                whois_desc = whois.lookup_whois()["nets"][0]["description"]

        print("{}:\t{},{}:\t{}".format(sorted_tup[i], whois_name, whois_desc, unique_domain_list[:5]))


    # Get CDF    
    x, y = plot_lib.get_cdf2(n_domains_list)

    # Plot
    plot_lib.plot_singleline(x, y, output_dir, "ccdf_dns.png", xlabel_name="Number of domains", ylabel_name="Fraction of IPs with $\it{x}$ or more domains",
                             title="", xlogscale=True,ylogscale=True,pointdot=True,ccdf=True)

    #plot_singleline(x_ax, y_ax, output_dir, filename, xlabel_name, ylabel_name, title, xlogscale=False, ylogscale=False, pointdot=False):


def main(): 
    parser = argparse.ArgumentParser(description='Script for qname-ip mapping')
    parser.add_argument('-i', dest='input_pickle', action='store', required=True,
                        help='Pickled file that has ip-qname mapping')
    parser.add_argument('-p', dest='map_pickle', action='store', required=True,
                        help='Pickled file that has domains to ndomains mapping')
    parser.add_argument('-o', dest='output_dir', action='store', required=True,
                        help='Output directory')

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
  

    print(len(ip_to_qname_map))
    #
    dns_analysis(ip_to_qname_map, args.output_dir)
#    dns_analysis_2(ip_to_qname_map, args.map_pickle, args.output_dir)


if __name__ == '__main__':
    main()

