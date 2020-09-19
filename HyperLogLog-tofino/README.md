
# Tofino implementation of HyperLogLog data structure 

This directory includes a P4 implementation of the [HyperLogLog](https://en.wikipedia.org/wiki/HyperLogLog/) approximate distinct counting data structure, running on the Barefoot Tofino programmable switch. 

HyperLogLog uses a random hash function to split the input stream into multiple sub-streams, and record the number of consecutive zeros seen in the hash function to infer the number of distinct elements seen in each estimator. Its output is the harmonic mean of all estimators.

### Technical Overview

The P4 program does the following:
- Calculating a random hash value, and use TCAM matching rules to get the number of trailing zeros. The leading slice of the value is used for choosing an estimator.
- Use a stateful register to maintain each estimator's number of zeros
- Calculate inverse of probability variables (an estimate of the number of elements seen by each estimator), and maintain their sum using a stateful register
- Calculate the final estimate, which is the inverse of the sum, using approximating floating points in the data plane

We note that HyperLogLog's output is more accurate than the approximated arithmetics in the data plane. Hence, for applications requiring good accuracy, they should work directly with the sum (the geometric mean) before the final inverse operation.

For very small counts, HyperLogLog is not accurate, and Linear Counting is used instead.

### Compiling

HyperLogLog uses `M` estimators, and we represent each estimator's estimate as a scaled and inversed probability (with parameter `scaling`).

Please use the code generator to instantiate the P4 template into a full P4 program, via the following command:
`python3 py/p4gen.py p4src/hyperloglog.p4template hyperloglog.p4  [--verbose --M=64 --scaling=20]`

(You might need to install python dependencies like jinja2, via `python3 -m pip install -r py/requirements.txt`)

Subsequently, you can run `bf-p4c hyperloglog.p4` to compile.

### Running

The prototype maintains a single instance of HyperLogLog to count the number of unique IPv4 SrcIP-DstIP pairs. You can feed it a packet trace, or use the following command to send packets with many unique IPs:
`sendp([(Ether()/IP(src='0.0.%d.%d'%(i,j))/UDP()) for i in range(256) for j in range(16)], iface="veth0")`

Please replace `veth0` with your actual interface name when running on hardware switches.

### Citing

This P4 implementation is a byproduct of the BeauCoup project, which implements multiple approximate distinct counters in the data plane using limited memory access. If you find this implementation useful, please consider citing:

    @article{chen2020beaucoup,
        title={BeauCoup: Answering Many Network Traffic Queries, One Memory Update at a Time},
        author={Chen, Xiaoqi and Feibish, Shir Landau and Braverman, Mark and Rexford, Jennifer},
        journal={ACM SIGCOMM 2020},
        year={2020},
        publisher={ACM}
    }

# License

Copyright 2020 Xiaoqi Chen, Princeton University.

The project source code, including the P4 data plane program template, is released under the **[GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html)**. 

If you modify the code and make the functionality of the code available to users interacting with it remotely through a computer network, for example through a P4 program, you must make the modified source code freely available under the same AGPLv3 license.
