# Meta4
**Analyzing Internet Traffic by Domain Name in the Data Plane<br/>**


known_domains_v1.txt: known domain list used for Meta4 traffic volume measurement tests<br/>
allowed_dns_dst.txt: list of client IP addresses we allow to make DNS requests (in Princeton network)<br/>
banned_dns_dst.txt list of client IP addresses making DNS requests that we ignore (in Princeton network)<br/>


**P4:**<br/>
netassay_v4_j6.p4: traffic volume measurement version of Meta4 (Note: compiles with SDE v9.2.0) <br/>
netassay_iot_j6.p4: IoT fingerprinting version of Meta4<br/>
netassay_tunnel_j7.p4: DNS tunneling detection version of Meta4<br/>
knownlist_v4_j6.py: used for creating match action rules for netassay_v4_j6.p4<br/>
knownlist_iot.py: used for creating match action rules for metassay_iot_j6.p4<br/>
ctr_p4netassay_tunnel.py: control plane script for netassay_tunnel_j7.p4<br/>

**Python Simulation:**<br/>
combined_sim_v1.py: testing simulation for varied memory/stage configurations of Meta4<br/>
combined_sim_v2.py: testing simulation for varied parsing/timeout configurations plus a simulation of Meta4 with no limitations.<br/>
netassay_python_preprocess.py: used to preprocess pcap files to make them compatible with the simulation scripts.<br/>


