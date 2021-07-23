
# Tofino implementation of AES encryption

This directory hosts P4 implementation of the AES encryption algorithm running on the Barefoot Tofino programmable switch. 

We used an optimization technique that blends lookup table and adding encryption key, to make the implementation more friendly to the switch hardware. For more details, please refer to our paper: [Implementing AES Encryption on Programmable Switches via Scrambled Lookup Tables](https://doi.org/10.1145/3405669.3405819) (Published in *SIGCOMM 2020 Workshop on Secure Programmable network INfrastructure (SPIN 2020)*).

### Compiling and running P4 code

You can compile the P4 code using Barefoot's P4 compiler: `bf-p4c p4src/aes_tworound.p4`. Please use a more recent version of the compiler (e.g., 9.6.0) for faster compilation.

To run the P4 code using tofino-model:
* `p4-build.sh p4src/aes_tworound.p4`
* `$SDE/run_switchd.sh -p aes_tworound`
* `$SDE/run_tofino_model.sh -p aes_tworound`

### Installing encryption key

When the P4 program is properly installed and loaded into the switch driver, you can run the accompanied control script to configure an encryption key. The script translates an AES-128 encryption key into match-action table rules for the Scrambled Lookup Tables.

After the switch driver has started, you can run the following command to load an encryption key:
`python control/aes_tworound.py 0x000102030405060708090a0b0c0d0e0f`

### Usage

When receiving a UDP packet with 16-byte payload and destination port 5555, the P4 program encrypts the payload using the installed key, and sends back the packet to the original incoming port.

You can run the following command in Scapy to send a test packet, with payload 0x`00112233445566778899aabbccddeeff`:
`sendp(Ether()/IP()/UDP(sport=1234,dport=5555)/("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"), iface="veth0")`

The switch will bounce back a UDP packet with payload 0x`69c4e0d86a7b0430d8cdb78070b4c55a`. You can examine the output by running the following command in Scapy:
`sniff(iface="veth0",count=2)`

The example presented above is the official AES-128 encryption test vector specified in [FIPS-197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).


### Citing
If you find this AES implementation or the discussions in our paper useful, please consider citing:

    @article{chen2020aes,
        title={Implementing AES Encryption on Programmable Switches via Scrambled Lookup Tables},
        author={Chen, Xiaoqi},
        journal={ACM SIGCOMM 2020 Workshop on Secure Programmable Network Infrastructure (SPIN 2020)},
        year={2020},
        publisher={ACM}
    }

### License

Copyright 2019 Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's P4 source code under AGPLv3.)

