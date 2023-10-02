/*
    SmartCookie: Blocking Large-Scale SYN Floods with a Split-Proxy Defense on Programmable Data Planes
    
    Copyright (C) 2023 Sophia Yoo, Xiaoqi Chen, Princeton University
    sy6 [at] princeton.edu
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <smartcookie.h>

//time event 2^16 ns
#define COOKIE_PERIOD 4096
#define MAX_COOKIE_AGE 3 


#ifndef DEBUG
#define DEBUG 0
#endif


static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

struct pkt_ippair {
  __be32 src_ip;
  __be32 dst_ip;
} __attribute__((packed));

struct pkt_5tuple {
  __be32 seq;
  __be32 ack; 
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));


const int key0 = 0x33323130;
const int key1 = 0x42413938;
const int c0 = 0x70736575;
const int c1 = 0x6e646f6d;
const int c2 = 0x6e657261;
const int c3 = 0x79746573;

static inline uint32_t rol(uint32_t word, uint32_t shift){
	return (word<<shift) | (word >> (32 - shift));
}

#define SIPROUND \
	do { \
	v0 += v1; v2 += v3; v1 = rol(v1, 5); v3 = rol(v3,8); \
	v1 ^= v0; v3 ^= v2; v0 = rol(v0, 16); \
	v2 += v1; v0 += v3; v1 = rol(v1, 13); v3 = rol(v3, 7); \
	v1 ^= v2; v3 ^= v0; v2 = rol(v2, 16); \
	} while (0)

static uint32_t get_hash(uint32_t src, uint32_t dst, uint16_t src_port, uint16_t dst_port, uint32_t seq_no){
	
	//initialization 
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1; 
	
	//first message 
	v3 = v3 ^ ntohl(src);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(src); 

	//second message 
	v3 = v3 ^ ntohl(dst);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(dst); 

	//third message
	uint32_t ports = (uint32_t) dst_port << 16 | (uint32_t) src_port;  
	v3 = v3 ^ ntohl(ports);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(ports); 

	//fourth message 
	v3 = v3 ^ ntohl(seq_no);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ ntohl(seq_no); 
	
	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	uint32_t hash = (v0^v1)^(v2^v3);
        return hash; 	
}

int xdp_ingress(struct xdp_md *ctx) {
//    if(DEBUG)bpf_trace_printk("ENTERING INGRESS!"); 	
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;
    //by default let the packet through 
    int rc = XDP_PASS; 
    
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth)  > data_end)
         goto DROP; 
    
    h_proto = eth->h_proto;

    if (h_proto != htons(ETH_P_IP))
         return rc;  

    struct iphdr *ip = data + sizeof(*eth);

    if ((void*)&ip[1] > data_end)
         goto DROP; 
    
    struct pkt_ippair ippair;
    struct pkt_5tuple pkt;
    
    ippair.src_ip=pkt.src_ip = ip->saddr;
    ippair.dst_ip=pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;
    if (ip->protocol == IPPROTO_TCP) {
       
        if(DEBUG)bpf_trace_printk("XDP_INGRESS: packet is TCP: src_ip 0x%x, dst_ip 0x%x", pkt.src_ip, pkt.dst_ip);
        struct tcphdr *tcp = NULL;
        tcp=data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
            goto DROP;               
        unsigned short* tcp_seg  = NULL;
        //point to start of tcp   
	tcp_seg=data + sizeof(*eth) + sizeof(*ip);
       	pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
	pkt.seq = tcp->seq; 
	pkt.ack = tcp->ack_seq; 
        if(DEBUG){
	bpf_trace_printk("src_ip 0x%x, orig src_ip 0x%x", pkt.src_ip, ip->saddr);
        bpf_trace_printk("SYN flag 0x%x", tcp->syn);
        bpf_trace_printk("ACK flag 0x%x", tcp->ack);
        bpf_trace_printk("ECE flag 0x%x", tcp->ece);
        /*bpf_trace_printk("doff flag 0x%x", tcp->doff);
        bpf_trace_printk("res1 flag 0x%x", tcp->res1);
        bpf_trace_printk("cwr flag 0x%x", tcp->cwr);
        bpf_trace_printk("ece flag 0x%x", ntohl(tcp->ece));
        bpf_trace_printk("urg flag 0x%x", ntohl(tcp->urg));
        bpf_trace_printk("ack flag 0x%x", ntohl(tcp->ack));
        bpf_trace_printk("psh flag 0x%x", ntohl(tcp->psh));
        bpf_trace_printk("rst flag 0x%x", ntohl(tcp->rst));
        bpf_trace_printk("syn flag 0x%x", ntohl(tcp->syn));
        bpf_trace_printk("fin flag 0x%x", ntohs(tcp->fin));
	*/ 

	}
	bool is_tagged = 0; 
	if (tcp->ece == 0x1){
		is_tagged = 1; 
	}
	//BPF map lookup to check if pkt info in map (struct)
	map_key_t map_key = {pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port};
       	//look up key in map, return pointer to its value if it exists, else NULL
	map_val_t *map_val_ptr = nonpercpu_bpf_map.lookup(&map_key);
        map_val_t map_val; 	
	uint32_t old_ack_seq_n; 

	//connection not in map 
	if(map_val_ptr == NULL){
		//if packet is untagged, perform cookie check
		if(!is_tagged){
		if(DEBUG)bpf_trace_printk("XDP_INGRESS: We have ourselves an UNTAGGED packet!");	


		//NOTE: xdp does not have access to any epoch time/wall clock, just monotonic and boottime clocks  
		//return time elapsed since system boot, in ns 
        	//get middle 32 bits 
		uint32_t new_count = (uint32_t) (bpf_ktime_get_ns() >> 16)/(COOKIE_PERIOD);
		uint32_t diff = new_count - (ntohl(pkt.ack) - 1) - get_hash(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, tcp->seq);

		//if cookie is not good, drop  
		if(diff >= MAX_COOKIE_AGE){
			return XDP_DROP; 
		}
		}
		
		//packet is tagged OR has passed cookie check, create map entry, begin handshake  
		    if(DEBUG)bpf_trace_printk("XDP_INGRESS: We have ourselves a TAGGED packet!"); 
		    //store initial ack value to get delta later 
		    if(DEBUG)bpf_trace_printk("Ingress: orig c + 1 in network order: 0x%x",tcp->ack_seq); 
		    if(DEBUG)bpf_trace_printk("Ingress: orig c + 1 in host order: 0x%x", ntohl(tcp->ack_seq)); 
		    map_val.delta = ntohl(tcp->ack_seq); 
		    if(DEBUG)bpf_trace_printk("current map val, stored in host order? 0x%x", map_val.delta); 
		    map_val.ip_id = ntohs(ip->id); 
		    map_val.map_state = ST_SYN_SENT; 
		    nonpercpu_bpf_map.insert(&map_key, &map_val); 

		    //check if packet is tagged ACK packet with no payload (i.e., from proxy), convert to SYN packet   
    		   if( is_tagged && tcp->ack == 0x1 && tcp->syn == 0 && ntohs(ip->tot_len) == 0x28){
			if(DEBUG)bpf_trace_printk("XDP_INGRESS: We have ourselves a TAGGED ACK packet!");
			//convert ACK packet to SYN packet 
			old_ack_seq_n = tcp->ack_seq;
		        //reset just ack_no to zero 
		        tcp->ack_seq = 0;
                        //lower 16 bits 
       		         tcp->check = compute_incr_tcp_checksum(tcp->check,(uint16_t)(old_ack_seq_n&0xFFFF), (uint16_t)(tcp->ack_seq&0xFFFF));
                	//upper 16 bits 
                	tcp->check = compute_incr_tcp_checksum(tcp->check,(uint16_t)((old_ack_seq_n>>16)&0xFFFF), (uint16_t)((tcp->ack_seq>>16)&0xFFFF));
		
			//incremental checksum update on changed flags 
                      uint16_t* casted_ptr=(uint16_t*) tcp;
                      uint16_t old_flags_n = casted_ptr[6];
		    if(DEBUG)bpf_trace_printk("XDP_INGRESS: current flags are 0x%x", ntohs(old_flags_n)); 
			//set flags (do we need to reset any other flags?)	
			tcp->ack = 0; 
	       		tcp->syn = 1;
			tcp->ece = 0; 
		        uint16_t new_flags_n = casted_ptr[6];
			//incremental checksum update
                	tcp->check = compute_incr_tcp_checksum(tcp->check,old_flags_n, new_flags_n);
	    		if(DEBUG)bpf_trace_printk("XDP_INGRESS: updated flags are 0x%x", ntohs(new_flags_n)); 
    		        rc = XDP_PASS;  
		   }//endif tagged ACK packet 


		    //TODO: packet is tagged data packet, convert to SYN packet 
		    else{
			if(DEBUG)bpf_trace_printk("Ingress: not in map, tagged DATA packet (not tagged ACK)");
    			//tcp->ack = 0; 
			//tcp->syn = 1; 
		    }//end else tagged data packet 	


	}



	//connection exists in map 
	else{
	if(DEBUG)bpf_trace_printk("INGRESS: Connection exists in map!");	

	int map_val_check = bpf_probe_read_kernel(&map_val, sizeof(map_val), map_val_ptr); 
	if(map_val_check !=0){
		return -1; 
	} 
	
	//update deltas for all non-hs packets 
	if(map_val.map_state != ST_SYN_SENT){
		old_ack_seq_n = tcp->ack_seq; 
	        tcp->ack_seq = htonl(ntohl(old_ack_seq_n) - map_val.delta);
        	//incremental checksum update
                //lower 16 bits 
       		tcp->check = compute_incr_tcp_checksum(tcp->check,(uint16_t)(old_ack_seq_n&0xFFFF), (uint16_t)(tcp->ack_seq&0xFFFF));
                //upper 16 bits 
                tcp->check = compute_incr_tcp_checksum(tcp->check,(uint16_t)((old_ack_seq_n>>16)&0xFFFF), (uint16_t)((tcp->ack_seq>>16)&0xFFFF));
		
	}//end if delta update 

	//might not need this switch statement 
	switch(map_val.map_state){ 
		/*case ST_SYN_SENT: 
		    //put something more meaningful here? combine with next case?
		    rc = XDP_PASS;   
		    break;
		case ST_ACK_SENT: 
		    rc=XDP_PASS; 
		    break; 
		    */
		case ST_NOTIFY_PROXY: 
		    if(!is_tagged){
		       map_val.map_state = ST_ONGOING; 
		       nonpercpu_bpf_map.update(&map_key, &map_val); 
		    }
		    break; 
		default:
		    break; 
	}//end switch map_state 


	}//end else connection exists in map 	


    } //endif TCP 
     
     else if (ip->protocol == IPPROTO_UDP){    
        
            struct udphdr *udp = NULL;
            udp=data + sizeof(*eth) + sizeof(*ip);
            //if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
              // goto DROP; 

            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
  //          if(DEBUG)bpf_trace_printk("XDP_INGRESS: packet is UDP: src_ip 0x%x, dst_ip 0x%x", pkt.src_ip, pkt.dst_ip);
        }
    
    return rc; 
   
	DROP:
    	return XDP_DROP;
}
