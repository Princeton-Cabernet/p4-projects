# p4app Driver code, for starting a vanilla topology for debugging
# usage: p4app run AES.p4app
import os
os.environ["GC_INITIAL_HEAP_SIZE"]="20G"
os.environ["GC_MAX_HEAP_SIZE"]="50G"

from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo

topo = SingleSwitchTopo(2)
net = P4Mininet(program='AES.p4', topo=topo)
net.start()

print("Minined started")

from mininet.cli import CLI
CLI(net)
