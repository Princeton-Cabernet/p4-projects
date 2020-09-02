"ConQuest project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json
import jinja2
import math
import random

parser = argparse.ArgumentParser(description="ConQuest P4 code generator")

parser.add_argument("template_filename", metavar="template_filename", type=str,
                    help="Filename for input Jinja/P4 template.")

parser.add_argument("P4_filename", metavar="P4_filename", type=str,
                    help="Filename for output P4 data plane program.")

parser.add_argument('-H',
                    default=4,
                    type=int,
                    choices=[4,8,16,32],
                    help='Number of snapshots')
parser.add_argument('-R',
                    default=2,
                    type=int,
                    choices=[1,2,3,4],
                    help='Number of rows (arrays) in each snapshot Count-Min Sketch.')
parser.add_argument('-C',
                    default=256,
                    type=int,
                    choices=[2**i for i in range(5,17)],
                    help='Number of columns (size of register array) in each snapshot Count-Min Sketch.')
parser.add_argument('-T',
                    default=16384,
                    type=int,
                    choices=[2**i for i in range(4,22)],
                    help='Duration of a snapshot time window (in nanoseconds). Should be max queuing delay divided by H. ')

parser.add_argument("--count_packets", action="store_true", help="Estimate number of packets instead of bytes using snapshots.")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")

args = parser.parse_args()

with open(args.template_filename,'r') as f:
    template_txt=f.read()
if args.verbose:
    print("Loaded template, %d lines"%(len(template_txt.split("\n"))))
t = jinja2.Template(template_txt,  trim_blocks=True, lstrip_blocks=True)

def get_seed():
    wid=random.randint(3,6)
    num=random.randint(0,2**wid-1)
    return f"{wid}w{num}"

LOG_CQ_H=int(math.log2(args.H))
LOG_CQ_R=int(math.log2(args.R))
LOG_CQ_C=int(math.log2(args.C))
LOG_CQ_T=int(math.log2(args.T))

output = (t.render(  
    LOG_CQ_H=LOG_CQ_H,
    CQ_H=2**LOG_CQ_H,
    LOG_CQ_R=LOG_CQ_R,
    CQ_R=2**LOG_CQ_R,
    LOG_CQ_C=LOG_CQ_C,
    CQ_C=2**LOG_CQ_C,
    LOG_CQ_T=LOG_CQ_T,
    CQ_T=2**LOG_CQ_T,
    COUNT_PACKETS=args.count_packets,
    get_seed=get_seed 
                  ))
with open(args.P4_filename, 'w') as f:
    f.write(output)
if args.verbose:
    print("Generated P4 source, %d lines. Successfully saved to %s"%(len(output.split("\n")),args.P4_filename))
    