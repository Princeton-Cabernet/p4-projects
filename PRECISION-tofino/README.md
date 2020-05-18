
# Tofino implementation of the PRECISION heavy-hitter algorithm

This directory hosts a P4 implementation of PRECISION running on the Barefoot Tofino programmable switch.

PRECISION is a heavy-hitter detection algorithm that uses *Partial Recirculation* to estimate flow sizes for the heaviest flows in the network, recirculating only a small percentage of packets to minimize throughput impact. For more detail, including a discussion for how to tailor stateful algorithm design for Tofino hardware, please refer to our paper: [Designing Heavy-Hitter Detection Algorithms for Programmable Switches](https://doi.org/10.1109/TNET.2020.2982739). 

### Setup
The P4 data plane program uses *d*=2-way associative hashing. Each incoming packet is mapped to a 128-bit flow ID, which is stored in four 32-bit partitions. The current version uses flow 5-tuple (source/destination IP address, source/destination ports, protocol) plus VLAN ID as the flow ID.

The current version of the data plane program is designed for processing tapped traffic stream (in the [P4Campus](https://p4campus.cs.princeton.edu/) setup), thus does not include routing functionality. The program outputs an estimated flow size for a packet's flow ID (if matched with an existing counter) into `hdr.ethernet.dst_addr`.

The control plane component is responsible for reading from and purging the registers, and generating a periodic report for heavy-hitter flows. The control plane script will be made available in a future release.

### Citing PRECISION
If you find this PRECISION implementation or the discussions in our paper useful, please consider citing:

    @article{basat2020precision,
        title={Designing Heavy-Hitter Detection Algorithms for Programmable Switches},
        author={Basat, Ran Ben and Chen, Xiaoqi and Einziger, Gil and Rottenstreich, Ori},
        journal={IEEE/ACM Transactions on Networking},  
        volume={28},
        number={3},
        year={2020},
        publisher={IEEE}
    }

Authors of the PRECISION algorithm:
- Ran Ben Basat, Harvard University
- Xiaoqi Chen, Princeton University
- Gil Einziger, Ben Gurion University
- Ori Rottenstreich, Technion

### License

Copyright 2019 Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's P4 source code under AGPLv3.)

