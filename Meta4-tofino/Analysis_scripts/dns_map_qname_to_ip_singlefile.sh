#!/bin/bash
# Joon (joonk@princeton.edu)

printf "\n=== Script to extract DNS information from pcap file. FYI, this is a bash script. ===\n"

# Check number of arguments
if [ $# -ne 2 ]
then
    printf "\nNot enough arguments. Give two arguments: (1) input pcap file, and (2) name of output file to store results.\n\n"
    exit
fi

# do the work
printf "\nExtracting...\n"
tshark -r $1 -T fields -e frame.time_epoch -e dns.qry.name -e dns.a -Y "dns and dns.flags.response eq 1 and dns.qry.name and dns.a" > $2

printf "Done.\n\n"
