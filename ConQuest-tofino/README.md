
# Tofino implementation of ConQuest data structure 

This directory includes a P4 implementation of the ConQuest round-robin snapshots data structure for fine-grained queue measurement, running on the Barefoot Tofino programmable switch. 

We use multiple count-min sketches to estimate the size of individual network flow inside the switch's queuing buffer, allowing real-time reactions to bursty flows that occupy significant fraction of queuing buffer. Please refer to our CoNEXT'19 paper: [Fine-Grained Queue Measurement in the Data Plane](https://doi.org/10.1145/3359989.3365408).

This implementation is translated from P4_14 with no guarantee on feature parity, and does no include the "tapping mode" which processes mirrored ingress and egress traffic from legacy devices. It is provided mostly for teaching and reference purpose.

### Compiling

ConQuest uses `H` snapshots, each recording a time window of `T` nanoseconds using a Count-Min Sketch with `R` rows and `C` columns. For more detail about these data structure parameters, please refer to Section 3 and Appendix B of the paper.

Please use the code generator to instantiate the P4 template into a full P4 program, via the following command:
`python3 ConQuest/py/p4gen.py ConQuest/p4src/conquest.p4template conquest.p4  [--verbose --H=4 --R=2 --C=2048 --T=16384]`

(You might need to install python dependencies like jinja2, via `python3 -m pip install -r ConQuest/py/requirements.txt`)

Subsequently, you can run `bf-p4c conquest.p4` to compile.

### Configuration

To configure the prototype implementation, please add the following table rules.
* Ingress: please add routing rules to `tb_route_ipv4`
* Egress: this prototype implementation runs on a single egress port. Please specify this port number in table `tb_gatekeeper`
* Action: please specify queue management actions (based on estimated flow size and queue length) in `tb_per_flow_action`

#### Example queue management actions
* Indiscriminate ECN: ignore flow-size estimation and random bits, range match on queue length
* Indiscriminate randomized ECN: ignore flow-size estimation, range match on queue length, range match on random bits
* Flow-based probabilistic ECN: range match on flow size and queue length, range match on random bits

This documentation is not complete yet. You're welcomed to open a pull request!

### Citing
If you find this data structure implementation or the discussions in our paper useful, please consider citing:

    @article{chen2019conquest,
        title={Fine-Grained Queue Measurement in the Data Plane},
        author={Chen, Xiaoqi and Feibish, Shir Landau and Koral, Yaron and Rexford, Jennifer and Rottenstreich, Ori and Monetti, Steven A and Wang, Tzuu-Yi},
        booktitle={Proceedings of the 15th International Conference on Emerging Networking Experiments And Technologies (CoNEXT'19)},
        year={2019},
        publisher={ACM}
    }

### License

Copyright 2020 Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's P4 source code under AGPLv3.)
