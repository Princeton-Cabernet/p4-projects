
# Tofino implementation of the Fridge unbiased estimation data structure 

This directory includes a P4 implementation of the *Fridge* data structure used for unbiased delay measurement, running on the Barefoot Tofino programmable switch. 

To mitigate the measurement bias caused by hash collisions, the *Fridge* tracks the number of insertions and use it to calculate the probability of each entry suffering from hash collisions. Subsequently, each successful query can be corrected with its survivorship bias. This helps more accurately measure pairwise delay distributions compared with naive methods.

For more detail, please refer to our APoCS'22 paper: [Unbiased Delay Measurement in the Data Plane](#TBD).

### Compiling

Please specify both the number of entries stored in the fridge `REG_SIZE`, and the entry probability `p` (a power of two, by specifing `ENTRY_PROB_LOG2`)

These constants can be defined at compile-time using command line arguments. For example, you can run `bf-p4c -D REG_SIZE=1024 -D ENTRY_PROB_LOG2=4 UnbiasedRtt.p4` to define a fridge with 1024 entries and an entry probability of `p`=1/(2^4)=1/16.

### Reconstructing the distribution

Note that each report contains both a delay sample and an insertion count `x`. The insertion count can be translated to a survivorship bias correction factor `w=p^-1(1-1/REG_SIZE)^-x`.

The overall delay distribution is the weighted sum of all delay samples, with each sample weighted by `w`. Care should be taken to ensure the correction process uses parameters that match the data-plane program.

### Citing
If you find this data structure implementation or the discussions in our paper useful, please consider citing:

    @inproceedings{zheng2022unbiased,
        title={Unbiased Delay Measurement in the Data Plane},
        author={Zheng, Yufei and Chen, Xiaoqi and Braverman, Mark and Rexford, Jennifer},
        booktitle={Symposium on Algorithmic Principles of Computer Systems (APOCS)},
        year={2022},
        organization={SIAM}
    }

### License

Copyright 2021 Xiaoqi Chen, Princeton University.

The project's source code are released here under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
- You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
- You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.

(TL;DR: you should also open-source your derivative work's P4 source code under AGPLv3.)
