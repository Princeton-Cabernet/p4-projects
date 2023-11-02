#!/usr/bin/python
"SmartCookie project, © Sophia Yoo, Xiaoqi Chen @ Princeton University. License: AGPLv3"

from bcc import BPF
import pyroute2
import time
import sys

if len(sys.argv)<2:
  print("Usage:   python3 "+sys.argv[0]+" if_name")
  print("Example: python3 "+sys.argv[0]+" enp3s0f1")
  sys.exit(-1)

device =sys.argv[1]
offload_device = None

flags = 0

mode = BPF.SCHED_CLS 

with open('egress.c','r') as f:
    bpf_src=f.read()

# load BPF program
b = BPF(text = bpf_src,
  device=offload_device,
  cflags=['-Ofast','-I./include/']
)
fn = b.load_func("tc_egress", mode, offload_device)

ip = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ip)
idx = ipdb.interfaces[device].index
ip.tc("add", "clsact", idx)
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)

print("SmartCookie Server Agent: TC egress program is loaded, hit CTRL+C to stop.")
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("\nRemoving filter from device")
        break

ip.tc("del", "clsact", idx)
ipdb.release()
