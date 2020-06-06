
# Tofino implementation of TCP RTT Measurement

This directory hosts P4 implementation of TCP RTT measurement running on the Barefoot Tofino programmable switch. 

We used register arrays to implement a hash table, with each entry saving a record for an outgoing TCP packet with its expected acknowledgment number and a timestamp. When the incoming ACK packet arrived, we fetch the entry and calculate the time difference. The entries in the table are *lazily expired*: they are consider expired when the timestamp is too old, but only overwritten upon hash collisions.

For more details, please refer to our paper: [Measuring TCP Round-Trip Time in the Data Plane](#) (To appear in SIGCOMM'20 SPIN workshop).

This version of the implementation posted here uses a single-stage hash table. We will release one using multi-stage hash table in a future version.

### Setup

The P4 program receives mirrored bi-directional traffic and automatically guesses if a packet is a data packet or ACK response, based on packet size. For data packet, no output will be given. For ACK packet, if it matched with an earlier record, we successfully produce a RTT sample, and it will be written in the payload section of the output report.

The output report is in IPv4+UDP format, with the original packet appended after the report.

### Compiling

To compile, run `bf-p4c p4src/RTT.p4`.
Please use `bf-p4c` version 9.1.0 or higher to compile the program. 

### Citing
If you find this implementation or the discussions in our paper useful, please consider citing:

    @article{chen2020rtt,
        title={Measuring TCP Round-Trip Time in the Data Plane},
        author={Chen, Xiaoqi and Kim, Hyojoon and Aman, Javed M and Chang, Willie and Lee, Mack and Rexford, Jennifer},
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


