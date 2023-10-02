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

#ifndef IFINDEX
#define IFINDEX 3
#endif

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

	//if SYN packet 
	if(tcp->syn==0x1 && tcp->ack == 0x0){
	 	if(DEBUG)bpf_trace_printk("XDP_INGRESS: We have ourselves a SYN packet!");	
		
		//generate cookie 
		uint32_t cookie = get_hash(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, tcp->seq);

		//swap src and dst ip addr and port numbers 
                __be32 tmp_ip = pkt.src_ip;
                pkt.src_ip = pkt.dst_ip;
                pkt.dst_ip = tmp_ip;
                ip->saddr = pkt.src_ip;
                ip->daddr = pkt.dst_ip;
                __be16 tmp_port = pkt.src_port;
                pkt.src_port = pkt.dst_port;
                pkt.dst_port = tmp_port;
                tcp->source = pkt.src_port;
                tcp->dest = pkt.dst_port;
                //also swap src dst mac address
                unsigned char *mac_srcp = NULL;
                mac_srcp = eth->h_source;
                unsigned char *mac_dstp = NULL;
                mac_dstp = eth->h_dest;
                unsigned char tmp;
                int p = 0;
                int q = 6;
                for(p = 0; p < q; p++){
                    tmp = *mac_srcp;
                    *mac_srcp = *mac_dstp;
                    *mac_dstp = tmp;
                    mac_srcp++;
                    mac_dstp++;
                }

                //set flags 
                tcp->ack = 0x1;
                tcp->syn = 0x1;

                //get rid of options by changing tcplen
                tcp->doff = 0x5;

                //set proper seq and ack numbers
                tcp->ack_seq = htonl(ntohl(tcp->seq) + 0x1);
                tcp->seq= htonl(cookie);

                        //recompute complete tcp checksum after packet processing complete
                        unsigned short* tcp_seg_full  = NULL;
                        //point to start of tcp segment
                        tcp_seg_full =data + sizeof(*eth) + sizeof(*ip);
                        if(DEBUG)bpf_trace_printk("original tcp cksum before update is 0x%x", ntohs(tcp->check));
                        tcp->check = eg_compute_full_tcp_checksum(ip, tcp_seg_full, data, data_end);
                        if(DEBUG)bpf_trace_printk("INGRESS: updated tcp checksum for packet after processing is 0x%x", ntohs(tcp->check));

			/*
			uint32_t old_ack_seq_n = tcp->ack_seq;
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
			*/
			
			//xdp automatically redirects to egress 
	                return bpf_redirect(IFINDEX, 0);
	}//endif SYN packet 



    } //endif TCP 
     

    return rc; 
   
	DROP:
    	return XDP_DROP;
}
