# Tofino implementation of HalfSipHash

This directory hosts P4 implementation of the HalfSipHash keyed hash function on the Barefoot Tofino programmable switch. For more details, please refer to our paper: [Secure Keyed Hashing on Programmable Switches](https://doi.org/10.1145/3472873.3472881) (Published in *SIGCOMM 2021 Workshop on Secure Programmable network INfrastructure (SPIN 2021)*).

### Compiling and running P4 code

You can compile the P4 code using Barefoot's P4 compiler: `bf-p4c p4src/halfsiphash24_ingressegress.p4`. Please be patient! 

To run the P4 code using tofino-model:
* `p4-build.sh p4src/halfsiphash24_ingressegress.p4`
* `$SDE/run_switchd.sh -p halfsiphash24_ingressegress`
* `$SDE/run_tofino_model.sh -p halfsiphash24_ingressegress`

By default, the program takes in a 16-byte input (as 4x 32-bit words). You can change the `NUM_WORDS` macro variable to change the hash function's input length.

### Hash key

Currently, the hash key is encoded as part of the source code. You can add a P4 match-action table and specify a new key as the action data. 

We note that the key is only used at the beginning of the hash calculation to initialize the internal state before any SipHash rounds. The C reference implementation performs one additional XOR to `v2` and `v3`.

### Usage

When receiving a UDP packet with destination port 5555 and a payload  of `4*NUM_WORDS` bytes, the P4 program calculates the payload's HalfSipHash-2-4 value and output it as the first 4 bytes of the payload, erasing other bytes.

You can run the following command in Scapy to send a test packet, with payload 0x`00112233445566778899aabbccddeeff`:
`sendp(Ether()/IP()/UDP(sport=1234,dport=5555)/("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"), iface="veth0")`

The switch will bounce back a UDP packet with payload 0x`df8f3346` with padding zeros to the same port. You can examine the output by running the following command in Scapy:
`sniff(iface="veth0",count=2)`


### Citing
If you find this HalfSipHash implementation or the discussions in our paper useful, please consider citing:

    @article{2021siphash,
        title={Secure Keyed Hashing on Programmable Switches},
        author={Yoo, Sophia and Chen, Xiaoqi},
        journal={ACM SIGCOMM 2021 Workshop on Secure Programmable Network Infrastructure (SPIN 2021)},
        year={2021},
        publisher={ACM}
    }

### License

Copyright 2021 Sophia Yoo, Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's P4 source code under AGPLv3.)