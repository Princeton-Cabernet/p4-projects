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

#define PIN_GLOBAL_NS 2 
//#define IFINDEX 2 
#define IFINDEX 8
#define TS_UDP_PORT 5555
#define IP_CSUM_OFF offsetof(struct iphdr, check) 
#define IP_TOTLEN_OFF offsetof(struct iphdr, tot_len) 

#ifndef DEBUG
#define DEBUG 0 
#endif

#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <smartcookie.h>

struct pkt_ippair {
  __be32 src_ip;
  __be32 dst_ip;
} __attribute__((packed));

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

int tc_egress(struct __sk_buff *skb)
{

    if(DEBUG)bpf_trace_printk("ENTERING EGRESS!"); 
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    uint16_t h_proto;  
    int key = 0, *ifindex; 

    if (data + sizeof(*eth) > data_end)
	goto DROP; //terminate processing and drop packet 
    
    h_proto = eth->h_proto;
    /* Non-IP packets, terminate processing and allow packet to proceed */
    if (h_proto != htons(ETH_P_IP))
         return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);

    if ((void*)&ip[1] > data_end)
         goto DROP;
    struct pkt_ippair ippair;
    struct pkt_5tuple pkt;
    ippair.src_ip=pkt.src_ip = ip->saddr;
    ippair.dst_ip=pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    if (ip->protocol == IPPROTO_UDP) {
        if(DEBUG)bpf_trace_printk("TC_EGRESS: UDP PACKET %x", ip->protocol);
	
        struct udphdr *udp = NULL;
        udp=data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
            goto DROP;

        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
    	if(DEBUG)bpf_trace_printk("egress src port  %d", ntohs(udp->source)); 
    	if(DEBUG)bpf_trace_printk("egress dst port %d", ntohs(pkt.dst_port)); 
    	

		
	//check if dst udp port is TS_UDP_PORT = 5555, then add ts 
        if(ntohs(pkt.dst_port) == TS_UDP_PORT){
        	//get middle 32 bits 
		uint32_t ts = (uint32_t) (bpf_ktime_get_ns() >> 16);
		if(DEBUG)bpf_trace_printk("EGRESS 32b SYS TIME 0x%x", ts);
		uint32_t * udp_seg = NULL; 
		udp_seg = data + sizeof(*eth) + sizeof(*ip); 
                //ensure pointer doesn't go outside of packet 
		if(udp_seg + 3 > (uint32_t *)data_end || udp_seg < (uint32_t *)data){
			return TC_ACT_SHOT; 
		}
		//point to end of udp hdr 
		udp_seg+=2;
		//add ts there 
		*udp_seg = htonl(ts);
		udp->dest = htons(TS_UDP_PORT); 
		//TODO: redo udp checksum, and also ip checksum? 	
	}
  	return TC_ACT_OK;
    }//endif UDP 

    if (ip->protocol == IPPROTO_TCP) {
        if(DEBUG)bpf_trace_printk("TC_EGRESS: TCP PACKET %x", ip->protocol);
        struct tcphdr *tcp = NULL;
        tcp=data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end){
		if(DEBUG)bpf_trace_printk("Dropping TCP packet"); 
    		goto DROP;
	}

        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
        if(DEBUG){
		bpf_trace_printk("Egress: SYN flag 0x%x", tcp->syn);
        	bpf_trace_printk("Egress: ACK flag 0x%x", tcp->ack);
        	bpf_trace_printk("Egress: ECE flag 0x%x", tcp->ece);
	}
	int ret;

        //BPF map lookup to check if pkt info in map (struct), note that tuple order is swapped for lookup since in other direction 
        map_key_t map_key = {pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port};
        //look up key in map, return pointer to its value if it exists, else NULL
        map_val_t *map_val_ptr = nonpercpu_bpf_map.lookup(&map_key);
        map_val_t map_val;
        //connection not in map 
        if(map_val_ptr == NULL){
		//this should not happen, but if it does, drop 
		//goto DROP; 
		//for now pass 
		if(DEBUG)bpf_trace_printk("EGRESS: connection does NOT exist"); 
		return TC_ACT_OK; 
	}//connection exists in map 
        else{
        if(DEBUG)bpf_trace_printk("EGRESS: Connection exists in map!");
  
          int map_val_check = bpf_probe_read_kernel(&map_val, sizeof(map_val), map_val_ptr);
       if(map_val_check !=0){
                return -1;
        }
	
	if(DEBUG){
		bpf_trace_printk("EGRESS current map_state: %d ", map_val.map_state);
		bpf_trace_printk("EGRESS current ip_id: 0x%x ", map_val.ip_id);
		bpf_trace_printk("EGRESS current delta: 0x%x ", map_val.delta);
	}
        //if packet is outbound SYN-ACK, convert to ACK and switch src/dst port and ip addr 
        if( tcp->ack == 0x1 && tcp->syn == 1){

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

                //convert SYN-ACK packet to ACK packet 
                //set flags (do we need to reset any other flags?)      
                tcp->ack = 0x1;
                tcp->syn = 0x0;

                //get rid of options by changing tcplen 
                tcp->doff = 0x5;

			
                        //set proper seq and ack numbers  
                        uint32_t old_ack_seq;
                        old_ack_seq = ntohl(tcp->ack_seq);
                        tcp->ack_seq = htonl(ntohl(tcp->seq) + 0x1);
                        tcp->seq= htonl(old_ack_seq);

                        //ip->id = htons(map_val.ip_id + 0x1);
                        //bpf_trace_printk("NEW ID 0x%x", ntohs(ip->id));

                        tcp->window = htons(0x1F6);

                        //write delta to map for future seq_no translate 
			old_ack_seq = map_val.delta;
                        if(DEBUG)bpf_trace_printk("ORIG COOKIE + 1 IS 0x%x", old_ack_seq);
                        //delta = c - y 
                        if(DEBUG)bpf_trace_printk("y + 1 is 0x%x", ntohl(tcp->ack_seq));
                        map_val.delta = old_ack_seq - ntohl(tcp->ack_seq);

                        if(DEBUG)bpf_trace_printk("EGRESS: delta is 0x%x", map_val.delta);
                        
			map_val.map_state = ST_ACK_SENT;
                        //overwrite previous value associated with key 
                        nonpercpu_bpf_map.update(&map_key, &map_val);


                        //recompute complete tcp checksum after packet processing complete 
                        unsigned short* tcp_seg_full  = NULL;
                        //point to start of tcp segment 
                        tcp_seg_full =data + sizeof(*eth) + sizeof(*ip);
			if(DEBUG)bpf_trace_printk("original tcp cksum before update is 0x%x", ntohs(tcp->check));
                        tcp->check = eg_compute_full_tcp_checksum(ip, tcp_seg_full, data, data_end);
                        if(DEBUG)bpf_trace_printk("TC_EGRESS: updated tcp checksum for packet after processing is 0x%x", ntohs(tcp->check));
			
			
			//update ip total length to reflect shorter packet, len = 40  
			uint16_t old_ip_len_n = ip->tot_len; 
			uint16_t new_ip_len_n = htons(0x28); 
			//perform incremental ip csum update 
			if(DEBUG)bpf_trace_printk("ip csum offset is 0x%x", IP_CSUM_OFF); 
			ret = bpf_l3_csum_replace(skb, sizeof(*eth)+IP_CSUM_OFF, old_ip_len_n, new_ip_len_n, sizeof(new_ip_len_n)); 
			if(ret<0){
				if(DEBUG)bpf_trace_printk("bpf_l3_csum_replace failed");
				goto DROP;
			}
			//write the new total_len to packet 
			if(DEBUG)bpf_trace_printk("ip total len offset is 0x%x", IP_TOTLEN_OFF); 
			ret = bpf_skb_store_bytes(skb, sizeof(*eth)+IP_TOTLEN_OFF, &new_ip_len_n, sizeof(new_ip_len_n), 0);

		//return bpf_redirect(IFINDEX,BPF_F_INGRESS); 
		// could find better way to do this. but for now, find ifindex with "ip a" and place in first arg, BPF_F_INGRESS flag specifies redirect to ingress  
        	bpf_clone_redirect(skb, IFINDEX, BPF_F_INGRESS);  
		//tag the clone, and allow that to pass out to the proxy 
		//must first redo checks 	
		void *data_end = (void *)(long)skb->data_end;
    		void *data = (void *)(long)skb->data;
    		if((data + 14 + 20 + 20)>data_end)
         	   goto DROP;

    		struct ethhdr *eth = data;
    		struct iphdr *ip = data + sizeof(*eth);
    		struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);

		
	
	    //lower 4 bits give size of field being updated, leave mask 
	    uint8_t cksum_flags = 0x10; 

    	    uint16_t * old_flags_ptr;
	    old_flags_ptr = data + sizeof(*eth) + sizeof(*ip) + 12;
	    if(DEBUG)bpf_trace_printk("orig chksum value is 0x%x", ntohs(tcp->check)); 
	    if(DEBUG)bpf_trace_printk("old flags *value is 0x%x", ntohs(*old_flags_ptr));

	    //doff=5,ece=1 
	    uint16_t new_flags_n = htons(0x5040);

    	    //try updating checksum with bpf helper,offset gives location of tcp cksum in hdr 
            ret = bpf_l4_csum_replace(skb, sizeof(*eth)+sizeof(*ip)+16, *old_flags_ptr, new_flags_n, cksum_flags | sizeof(new_flags_n));
            if(ret<0){
                if(DEBUG)bpf_trace_printk("bpf_l4_csum_replace failed");
                goto DROP;
            }

            //test using bpf_skb_store_bytes to write to packet
            ret = bpf_skb_store_bytes(skb, 14+20+12, &new_flags_n, sizeof(new_flags_n),0);
            if(ret<0){
                if(DEBUG)bpf_trace_printk("store bytes failed");
                goto DROP;
            }
            if(DEBUG)bpf_trace_printk("new value should be written to packet: 0x%x", ntohs(new_flags_n));
	

	}//endif SYN-ACK 


	else{
	    //lower 4 bits give size of field being updated, leave mask 
	    uint8_t cksum_flags = BPF_F_PSEUDO_HDR; //0x10 

	    //apply delta update on outgoing sequence number for all non-hs pkt

	    if(DEBUG)bpf_trace_printk("In map, non-SYN-ACK packet"); 
	    if(DEBUG)bpf_trace_printk("Current map state is 0x%x", map_val.map_state);
    	    uint32_t old_seq_n = tcp->seq;
	    if(DEBUG)bpf_trace_printk("orig chksum value is 0x%x", htons(tcp->check)); 
	    if(DEBUG)bpf_trace_printk("old seq value is 0x%x", htonl(old_seq_n)); 
	    uint32_t new_seq_n = htonl(ntohl(tcp->seq) + map_val.delta);
/*
    	    //try updating checksum with bpf helper
	    if(DEBUG)bpf_trace_printk("size of new_seq_n 0x%x", sizeof(new_seq_n));
	    ret = bpf_l4_csum_replace(skb, sizeof(*eth)+sizeof(*ip)+16, old_seq_n, new_seq_n, cksum_flags | sizeof(new_seq_n));
            if(ret<0){
                if(DEBUG)bpf_trace_printk("bpf_l4_csum_replace failed");
                goto DROP;
            }


  */          //test using bpf_skb_store_bytes to write to packet
            ret = bpf_skb_store_bytes(skb, 14+20+4, &new_seq_n, sizeof(new_seq_n),BPF_F_RECOMPUTE_CSUM);
            if(ret<0){
                if(DEBUG)bpf_trace_printk("store bytes failed");
                goto DROP;
            }
            if(DEBUG)bpf_trace_printk("new value should be written to packet: 0x%x", htonl(new_seq_n));


	    //update map state as needed
	    switch(map_val.map_state){
		case ST_ACK_SENT: 
		   map_val.map_state = ST_NOTIFY_PROXY; 
		   nonpercpu_bpf_map.update(&map_key, &map_val);
		   break;
		case ST_ONGOING: 
		   //if see a FIN packet 
		   //map_val.map_state = ST_CLOSED; 
		   //nonpercpu_bpf_map.update(&map_key, &map_val); 
		   break; 
		default:
		   break; 
	    }
        if(DEBUG)bpf_trace_printk("EGRESS UPDATED map_state: %d", map_val.map_state);
	
	
	}//end else non-SYN-ACK packets 	

       }//endif connection exists in map 

	
    }//endif IPPROTO_TCP 
	
    	return TC_ACT_OK;//default allow packet to pass out  
	
	DROP: 
	return TC_ACT_SHOT; 

}
