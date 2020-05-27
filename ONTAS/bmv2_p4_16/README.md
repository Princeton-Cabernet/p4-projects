# ONTAS: Flexible and Scalable Online Network Traffic Anonymization System
This is the ONTAS source code for BMv2. It is implemented with P4-16. 

**Note**: Basic testing shows this ONTAS source code version for BMv2  works correctly (P4-16). But note that it was not tested as rigorously as the one for Barefoot Tofino (P4-14), which is the version used in [our paper](https://dl.acm.org/citation.cfm?id=3342208).

## To Run ONTAS in Mininet with BMv2
1. Download the P4 Tutorial VM. The download link can be found from the [P4 Developer Day 2019 website](https://p4.org/events/2019-04-30-p4-developer-day/).
    - If you cannot find the VM download link there, this is it: [P4 Tutorial 2019-04-25.ova (5.2G)](https://drive.google.com/uc?id=1lYF4NgFkYoRqtskdGTMxy3sXUV0jkMxo&export=download)
1. Install tcpreplay
    - `sudo apt-get update`
    - `sudo apt-get install tcpreplay`
1. Clone this repo in the VM.
1. Go to `./src` directory. Then run command `make`. 
    - This will emulate a simple netowrk in Mininet with two hosts and one switch:  `h1 --- Bmv2_Switch --- h2`
    - Default anonymization policy will be installed. You can customize the policy by modifying the `s1-runtime.json` file.
1. Open host1 (h1) and host2 (h2) terminals
    - `mininet> xterm h1`
    - `mininet> xterm h2`
1. In h2's terminal, run tcpdump:
    - `tcpdump -i h2-eth0 -nnnne`
1. In h1's terminal, replay five packets from smallFlows.pcap with tcpreplay. Feel free to replay more packets. 
    - `tcpreplay -i h1-eth0 -L 5 ../smallFlows.pcap`
    - The sample capture file smallFlows is from the the [Tcpreplay website](http://tcpreplay.appneta.com/wiki/captures.html). 
1. Compare orignal packet trace and the traffic captured in h2. 
    - To see the original packet trace, you can use tcpdump: `tcpdump -r ../smallFlows.pcap -c 5 -nnnne`
     
## License

Copyright 2019 Hyojoon Kim, Princeton University.

The project's source code are released here under the [Apache License v2]
(https://www.apache.org/licenses/LICENSE-2.0).
