# P40f: OS fingerprinting in the data plane
This is the P40f source code that compiles and runs on the Intel/Barefoot Tofino programmable switch. It is implemented with P4-16.

### Compiling and running P4 code

You can compile the P4 code using Intel's P4 SDE compiler: `$ bf-p4c -g p40f_tofino.p4`

Note: 
  - Please be patient! The compilation can take up to several hours, but it eventually succeeds. We hope our future code and a more optimized compiler will shorten this duration. 
  - We verified that this P4 program compiles with the following versions of Intel/Barefoot SDE: v9.3.1, v9.4.0, and v9.7.1.

