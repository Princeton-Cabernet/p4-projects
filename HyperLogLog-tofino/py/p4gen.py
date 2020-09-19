"HyperLogLog tofino, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json
import jinja2
import math
import random

parser = argparse.ArgumentParser(description="HyperLogLog P4 code generator")

parser.add_argument("template_filename", metavar="template_filename", type=str,
                    help="Filename for input Jinja/P4 template.")

parser.add_argument("P4_filename", metavar="P4_filename", type=str,
                    help="Filename for output P4 data plane program.")

parser.add_argument('-M',
                    default=64,
                    type=int,
                    choices=[2**i for i in range(4,17)],
                    help='Number of independent estimators.')
parser.add_argument('--scaling',
                    default=20,
                    type=int,
                    choices=range(4,32),
                    help='Scaling used for storing inversed probabilities.')

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

output = (t.render(  
    M=args.M,
    LOG_M=int(math.log2(args.M)),
    SCALING=args.scaling,
    log=math.log,
    get_seed=get_seed
                  ))
with open(args.P4_filename, 'w') as f:
    f.write(output)
if args.verbose:
    print("Generated P4 source, %d lines. Successfully saved to %s"%(len(output.split("\n")),args.P4_filename))
    