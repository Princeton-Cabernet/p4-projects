#################################################
# (c) Copyright 2014 Hyojoon Kim
# All Rights Reserved 
# 
# email: deepwater82@gmail.com
#################################################

import os
from optparse import OptionParser
import python_api
import plot_lib
import sys
import pickle

def plot_the_data(the_map, output_dir, saveAsFileName, plot_title):
    xa = []
    ymap = {}
    
    #### Do your stuff

    plot_lib.plot_multiline(xa, ymap, output_dir, saveAsFileName, plot_title)
#    plot_lib.plot_distribution(xa, ymap, output_dir, saveAsFileName, plot_title)

    return   

def main():
    desc = ( 'Plotting data' )
    usage = ( '%prog [options]\n'
                          '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--inputfile', '-i', action="store", \
                   dest="input_file", help = "Pickled data")
    
    op.add_option( '--outputdir', '-o', action="store", \
                   dest="output_dir", help = "Directory to store plots")

    # Parsing and processing args
    options, args = op.parse_args()
    args_check = sys.argv[1:]
    if len(args_check) != 4:
        print 'Something wrong with paramenters. Please check.'
        print op.print_help()
        sys.exit(1)

    # Check and add slash to directory if not there.
    output_dir = python_api.check_directory_and_add_slash(options.output_dir)

    # Check file, open, read
    if os.path.isfile(options.input_file) is True:
        fd = open(options.input_file, 'r')
        data = pickle.load(fd)
        fd.close()

    # Plot
    saveAsFileName = ''  # Add file extension yourself.
    plot_title = ''
    plot_the_data(data, output_dir, saveAsFileName, plot_title)


######        
if __name__ == '__main__':
    main()
