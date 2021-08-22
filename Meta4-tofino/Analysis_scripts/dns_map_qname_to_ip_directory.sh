#!/bin/bash
# Joon (joonk@princeton.edu)

printf "\n=== Script to extract DNS information from pcap files in directory. FYI, this is a bash script. ===\n"

# Check number of arguments
if [ $# -ne 2 ]
then
    printf "\nNot enough arguments. Give two arguments: (1) Directory that contains pcap files, and (2) name of output file to store results.\n\n"
    exit
fi

# Check output file so that we don't mess up.
if [ -s $2 ]
then
    printf "\nOutput file is not empty. It already has some content in it.\n"
    printf "NOTE!!! The script *appends* results to the output file. Should I remove the existing output file first? (y/n): "
    read answer
    if [ $answer == "y" ]
    then 
        rm $2
    elif [ $answer != "n" ]
    then
        printf "The answer is either y or n. I don't undertand you. Aborting.\n\n"
        exit
    fi
fi

# Get pcap files in given directory and go through them sequentially.
#ls -ltr | awk '{print $9}'}
#FILES=$1/*.pcap*
#FILES=`ls -ltr $1/*.pcap* | awk '{print $9}'`
FILES=`ls -l $1/*.pcap* | awk '{print $9}'`
for f in $FILES
do
    printf "Processing $f file...\n"
    tshark -r $f -T fields -e frame.time_epoch -e dns.qry.name -e dns.a -Y "dns and dns.flags.response eq 1 and dns.qry.name and dns.a" >> $2
done

# Done
printf "Done.\n\n"
