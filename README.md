# Open source P4 implementations

This repository is used to host the open-source P4 implementations of some of our research projects. 

## Projects
- [AES](AES.p4app/): AES encryption on BMV2 model
- [AES-tofino](AES-tofino/): AES encryption on Tofino switch
- [ConQuest-tofino](ConQuest-tofino/): ConQuest queue analysis on Tofino switch
- [ONTAS](ONTAS/): Traffic anonymization on BMV2 / Tofino
- [PRECISION-tofino](PRECISION-tofino/): The PRECISION heavy-hitter algorithm on Tofino switch
- [RTT-tofino](RTT-tofino/): TCP Round-Trip Time measurement on Tofino switch
- [SipHash-tofino](SipHash-tofino/): Secure keyed hash function on Tofino switch
- [Meta4-tofino](Meta4-tofino/): Analyzing Internet Traffic by Domain Name on Tofino switch 

Please refer to individual project sub-folders for open-source licenses.

## Related repositories

Below is a non-exhaustive list of other repositories hosting open-sourced P4 programs. 
(Please add to this list -- pull requests welcomed!)

### Tofino P4-16
- [BeauCoup](https://github.com/Princeton-Cabernet/BeauCoup): Run multiple distinct-counting queries on Tofino
- [MicroP4](https://github.com/cornell-netlab/MicroP4): Modularized data-plane programming

### Tofino P4-14
- [ATP](https://github.com/in-ATP/ATP): Provide in-network aggregation service to accelerate deep learning training in multi-tenant settings
- [ATP-SwitchML](https://github.com/in-ATP/switchML): Provide in-network aggregation service to accelerate deep learning training
- [Cheetah](https://github.com/harvard-cns/cheetah-release): Use Tofino to accelerate Spark queries
- [Chipmunk](https://github.com/chipmunk-project/chipmunk-tofino): Use program synthesis to generate P4 code
- [NetLock](https://github.com/netx-repo/NetLock): Using P4 switch for lock management
- [Mantis](https://github.com/eniac/Mantis): Generates reactive P4 program and C++ agent
- [SP-PIFO](https://github.com/nsg-ethz/SP-PIFO): Enabling programmable scheduling in Tofino

### BMV2
- [NetCache](https://github.com/netx-repo/netcache-p4): Using P4 switch as cache for key-value store
- [NetChain](https://github.com/netx-repo/netchain-p4): Using P4 switch for coordination service
- [NetHCF](https://github.com/NetHCF/NetHCF): Employing programmable switches for spoofed IP traffic filtering
- [PINT](https://github.com/ProbabilisticINT/Mininet-PINT): Probabilistic In-band Network Telemetry
- [PRECISION-bmv2](https://github.com/p4lang/p4-applications/tree/master/research_projects/PRECISION): The PRECISION heavy-hitter algorithm on BMV2 switch
- [QPipe](https://github.com/netx-repo/QPipe/): Quantile sketch in data plane
- [Speedlight](https://github.com/eniac/Speedlight): Synchronized Network Snapshots  
- [Tutorial](https://github.com/p4lang/tutorials):  The official P4 tutorial has many example P4 programs (under the solution folders)
- [P4-Guide](https://github.com/jafingerhut/p4-guide/blob/master/README-demos.md): More example P4 programs
- [SP-PIFO](https://github.com/nsg-ethz/SP-PIFO): Enabling programmable scheduling in P4 switches
