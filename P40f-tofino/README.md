# P40f: OS fingerprinting in the data plane
This is the P40f source code that compiles and runs on the Intel/Barefoot Tofino programmable switch. It is implemented with P4-16.

### Compiling and running P4 code

You can compile the P4 code using Barefoot's P4 compiler: `bf-p4c p40f_tofino.p4`. 

Please be patient! The compilation normally takes several hours...

The program was verifieid to compile and run with Intel/Barefoot SDE v9.3.1 and v9.4.0. 

