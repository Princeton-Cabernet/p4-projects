# SmartCookie

This repository contains the prototype source code for our USENIX Security'24 paper [SmartCookie: Blocking Large-Scale SYN Floods with a Split-Proxy Defense on Programmable Data Planes](#).

## Contents

* `p4src/` includes the Switch Agent program that calculates SYN cookie using HalfSipHash.
	* `p4src/benchmark/` contains variants of the Switch Agent, for benchmarking max hashing rate using different hash functions (AES or CRC).
* `ebpf/` includes the Server Agent programs that process cookie-verified new connection handshake and false positive packets.
	* `ebpf/benchmark/` contains a XDP-based SYN cookie generator, for benchmarking max hashing rate of a server-only solution.

## Usage

### Loading the Server Agent

Prerequisite: please use kernel 5.10 or newer and install the entire `bcc` toolkit.
(For Ubuntu, you may run `sudo apt-get install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)`)

Use the provided python scripts to compile and load the eBPF programs to the interface connected to the programmable switch:

1. `sudo python xdp_load.py *if_name*` for ingress path
2. `sudo python tc_load.py *if_name*` for egress path

### Loading the Switch Agent

Prerequisite: please use `bf-sde` version 9.7.1 or newer to compile the P4 program. Then, the program can be deployed via `$SDE/run_switchd.sh -p SmartCookie-HalfSipHash`.

### Benchmarking hash rate

All variants of the Switch Agent will respond to any incoming SYN packet from all non-server ports. To measure maximum hash rate, simply direct your packet generator to generate any TCP packet with TCP flags set to `0x02`, and increase sending rate (observe response packet rate) until loss is observed.

Note: for AES variant, please first run the controller script to load an arbitrary key; this is required to set up recirculation rounds correctly. 


## Citing
If you find this implementation or our paper useful, please consider citing:

    @inproceedings{yoo2023smartcookie,
        title={SmartCookie: Blocking Large-Scale SYN Floods with a Split-Proxy Defense on Programmable Data Planes},
        author={Yoo, Sophia and Chen, Xiaoqi and Rexford, Jennifer},
        booktitle={33rd USENIX Security Symposium (USENIX Security 24)},
        year={2024},
        publisher={USENIX Association}
    }

## License

Copyright 2023 Sophia Yoo & Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's source code under AGPLv3.)
