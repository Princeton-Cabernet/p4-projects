#!/usr/bin/python
"SmartCookie project, © Sophia Yoo, Xiaoqi Chen @ Princeton University. License: AGPLv3"

from bcc import BPF
import time
import sys
mode = BPF.XDP

if len(sys.argv)<2:
  print("Usage:   python3 "+sys.argv[0]+" if_name")
  print("Example: python3 "+sys.argv[0]+" enp3s0f1")
  sys.exit(-1)

device =sys.argv[1]
offload_device = None

#flags = 0
#generic mode 
XDP_FLAGS_SKB_MODE = 1 << 1
#native mode 
XDP_FLAGS_DRV_MODE = 1 << 2
#offload mode 
XDP_FLAGS_HW_MODE = 1 << 3

flags=XDP_FLAGS_DRV_MODE

mode = BPF.XDP

with open('ingress.c','r') as f:
    bpf_src=f.read()

# load BPF program
b = BPF(text = bpf_src,
  device=offload_device,
  cflags=['-Ofast','-I./include/']
)
fn = b.load_func("xdp_ingress", mode, offload_device)
b.attach_xdp(device, fn, flags)


print("SmartCookie Server Agent: XDP ingress program is loaded, hit CTRL+C to stop.")
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("\nRemoving filter from device")
        break

b.remove_xdp(device, flags)
