# AES encryption P4 implementation

This P4 program implements AES-128 (10 rounds Rinjdael algorithm) using P4. It only uses look up tables and XORs, which are more readily available on programmable switch targets.

There are 5 different lookup tables each having 256 entries, totalling about 4KB. However, when compiled to target, each table is placed into multiple copies, so it takes about 160KB of table memory.

This implementation works on the BMV2 behavioral model. Please check out [AES-tofino](../AES-tofino/) for an implementation on the Barefoot Tofino programmable switch hardware.

## Compiling the code

You may use [`p4app`](https://github.com/p4lang/p4app/) to quickly set up envorinment and run P4 code: use the `wire` example (1 switch, 2 hosts example) and replace the P4 program.

Note that currently the official `p4c` compiler for BMV2 backend (`p4c-bm2-ss`) will take ~20GB memory and ~1 hour when compiling this code. Consider turning off the constant table entries to make compiling more efficient, and add back the look up table values into the match-action tables in run time.

The vanilla version of the code is unoptimized and won't easily fit into known P4 hardware targets, however you can reduce the 10 rounds into fewer (at least 2) rounds and obtain a weaker version of encryption.

A more optimized version is work in the progress. Feel free to open an issue for discussion.

## Usage

Please send a packet with etherType 0x9999 with at least 128+16bit payload, ending with `0xffff`. The P4 switch should reply a packet with the 128 bit plaintext replaced by its encrypted ciphertext. The switch will drop all other packets.

For example, you can run the following code in scapy: `srp1(Ether(type=0x9999)/("\x00"*16+"\xff\xff"))`

## Encryption key update

This version of P4 program is initialized with a 128-bit key `0x01010101020202020303030304040404`.

To update the key, you need to first run Rijndael key schedule on your 128-bit key to obtain round keys for the next 10 rounds (11 keys in total), and put the 11 keys as the action value into the `mask_key_round_X` tables.

TODO: add a python script to automate this computation.

## License

Copyright 2019 Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's P4 source code under AGPLv3.)
