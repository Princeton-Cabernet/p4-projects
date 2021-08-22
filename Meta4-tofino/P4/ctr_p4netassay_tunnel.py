import ptf
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
#from csiphash import siphash24
import itertools
import time
import grpc
import bfrt_grpc.bfruntime_pb2_grpc as bfruntime_pb2_grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

import Queue
import os
import logging
import threading
import json
import sys
import random
import math
import socket
import struct
import signal

import google.rpc.status_pb2 as status_pb2
import google.rpc.code_pb2 as code_pb2

from collections import namedtuple
import netifaces

from ipaddress import ip_address

INTERVAL_SECONDS = 30
COUNTER_OVER_N_IS_DNS_TUNNEL = 5

def rand_mac():
	return "%02x:%02x:%02x:%02x:%02x:%02x" % (
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255)
		)

def rand_port():
	return random.randint(0, 65535)


def rand_int():
	return random.randint(0, 1024)

def flush_table(table, target):
	ks = []
	x = table.entry_get(target)
	for i in x: 
		# print i
		ks.append(i[1])
	if None in ks: ks.remove(None)
	table.entry_del(target, ks)


	












#flush_table(dns_total_missed, target)

#flow_table = bfrt_info.table_get("SwitchIngress.flow_match")



#tb = [None] * 3
#tb_re = [None] * 3
#tb[0] = bfrt_info.table_get("SwitchIngress.get_otp_part1")
#tb[1] = bfrt_info.table_get("SwitchIngress.get_otp_part2")
#tb[2] = bfrt_info.table_get("SwitchIngress.get_otp_part3")
#
#svr_table_6 = bfrt_info.table_get("SwitchIngress.get_svr_addr6")
#svr_table_6.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
#
#svr_table_4 = bfrt_info.table_get("SwitchIngress.get_svr_addr4")
#
#
#learn_filter = bfrt_info.learn_get("SwitchIngressDeparser.digest")
#
#
#
#try:
#	flush_table(tb[0], target)
#	flush_table(tb[1], target)
#	flush_table(tb[2], target)
#	# flush_table(tb_re[0], target)
#	# flush_table(tb_re[1], target)
#	# flush_table(tb_re[2], target)
#
#except Exception as e:
#	print str(e)
#	pass
#
#try:
#	flush_table(forward_table, target)
#except:
#	pass
#
#try:
#	flush_table(svr_table_6, target)
#except:
#	pass
#
#try:
#	flush_table(svr_table_4, target)
#except:
#	pass
#
#try:
#	flush_table(flow_table, target)
#except:
#	pass
#
#rec_port = 68
#client_port = 0
#server_port = 1
#KEY = b'\x00' * 16
#
#def forward_update(is_mod=False):
#	key_list = [forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', client_port)]), 
#	forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', server_port)]),
#	forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', rec_port)])]
#	data_list = [forward_table.make_data([gc.DataTuple('port', server_port)], "SwitchIngress.hit"),
#	forward_table.make_data([gc.DataTuple('port', client_port)], "SwitchIngress.hit"),
#	forward_table.make_data([gc.DataTuple('port', server_port)], "SwitchIngress.hit")]
#	
#	if is_mod:
#		forward_table.entry_mod(target, key_list, data_list)
#	else:
#		forward_table.entry_add(target, key_list, data_list)
#
#
#def server_addr_update():
#	dns_ips = {
#		"8.8.8.8": u"2001:4860:4860:0:0:0:0:8888", # Google
#		"8.8.4.4": u"2001:4860:4860:0:0:0:0:8844",
#		"1.1.1.1": u"2606:4700:4700:0:0:0:0:1111", # CloudFlare 
#		"1.0.0.1": u"2606:4700:4700:0:0:0:0:1001",
#		"9.9.9.9": u"2620:fe::fe", # QUAD9
#		"149.112.112.112": u"2620:fe::9",
#		"208.67.222.222": u"2620:119:35::35", # OpenDNS
#		"208.67.220.220": u"2620:119:53::53",
#		"185.228.168.9": u"2a0d:2a00:1::2", # CleanBrowsing
#		"185.228.169.9": u"2a0d:2a00:2::2",
#		"64.6.64.6": u"2620:74:1b::1:1", # Verisign
#		"64.6.65.6": u"2620:74:1c::2:2",
#		"198.101.242.72": u"2001:4800:780e:510:a8cf:392e:ff04:8982", # AlternateDNS
#		"23.253.163.53": u"2001:4801:7825:103:be76:4eff:fe10:2e49",
#		"172.217.8.196": u"2607:f8b0:4009:812::2004"
#	}
#
#	for ipv4 in dns_ips:
#		# ipv4 = "8.8.8.8"
#		ipv4 = str(ipv4)
#		print ipv4, dns_ips[ipv4]
#		ipv6 = ip_address(dns_ips[ipv4]).packed
#		ipv6_prx = bytearray(ipv6[:8])
#		ipv6_sub = bytearray(ipv6[8:12])
#		ipv6_addr = bytearray(ipv6[12:16])
#
#		ipv4_b = bytearray(ip_address(u"%s" % ipv4).packed)
#
#		
#
#		key_list = [svr_table_6.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', ipv4)])]
#		data_list = [svr_table_6.make_data([gc.DataTuple('prex', ipv6_prx), gc.DataTuple('sub', ipv6_sub), gc.DataTuple('addr', ipv6_addr)], "SwitchIngress.get_ipv6_addr")]
#		svr_table_6.entry_add(target, key_list, data_list)
#
#		key_list = [svr_table_4.make_key([gc.KeyTuple('hdr.ipv6.src_prex', ipv6_prx), gc.KeyTuple('hdr.ipv6.src_sub', ipv6_sub), gc.KeyTuple('hdr.ipv6.src_addr', ipv6_addr)])]
#		data_list = [svr_table_4.make_data([gc.DataTuple('addr', ipv4_b)], "SwitchIngress.get_ipv4_addr")]
#		svr_table_4.entry_add(target, key_list, data_list)
#
#
#def enc_init(is_mod=False):
#	try: 
#		for idx in xrange(3):
#			key_list = []
#			data_list = []
#			for i in xrange(1024):
#				_k = tb[idx].make_key([gc.KeyTuple('ig_md.nonce'+str(idx+1), i)])
#				
#				tmp = siphash24(KEY, str(i))
#				#!!! need to increase key
#				bt = bytearray(tmp)
#				_d = tb[idx].make_data([gc.DataTuple('otp_tmp', bt[0:3])], "SwitchIngress.gen_otp")
#				
#				key_list.append(_k)
#				data_list.append(_d)
#			print idx, len(key_list)
#			if is_mod:
#				tb[idx].entry_mod(target, key_list, data_list)
#			else:
#				tb[idx].entry_add(target, key_list, data_list)
#			
#	except Exception as e:
#		print "!!!!!!!!", str(e)
#		try:
#			flush_table(tb[0], target)
#			flush_table(tb[1], target)
#			flush_table(tb[2], target)
#		except Exception as e:
#			# print "error", str(e)
#			pass
#
#server_addr_update()
#forward_update()
#enc_init()
#
#
#print "start listen"
#while True:
#	try:
#		digest = interface.digest_get()
#		data_list = learn_filter.make_data_list(digest)
#		data_dict = data_list[0].to_dict()
#		print data_dict
#		tmp = siphash24(KEY, str(time.time()))
#		#!!! need to increase key
#		bt = bytearray(tmp)
#		print "checkpoint 0"
#
#		k = [flow_table.make_key([gc.KeyTuple('hdr.tcp.src_port', data_dict[u'src_port']), 
#			gc.KeyTuple('hdr.tcp.dst_port', data_dict[u'dst_port']),
#			gc.KeyTuple('hdr.ipv4.src_addr', data_dict[u'src_addr']),
#			gc.KeyTuple('hdr.ipv4.dst_addr', data_dict[u'dst_addr'])])]
#		print "checkpoint 1"
#		v = [flow_table.make_data([gc.DataTuple('nonce', bt[0:3])], "SwitchIngress.hitf")]
#		print "checkpoint 2"
#
#		try:
#			print "add", data_dict
#			flow_table.entry_add(target, k, v)
#		except:
#			print "mod", data_dict
#			flow_table.entry_mod(target, k, v)
#
#
#		# break
#	# else:
#	#   pass
#	except Exception as e:
#		print "exception!", str(e)
#	#   continue



def get_index_and_value(entry_list, value_name, output_file):

    output_str = ""

    for entry in entry_list:
        key = entry[1]
        value = entry[0]

        key_val = str(key.to_dict()["$REGISTER_INDEX"]["value"])
        entry_val = str(value.to_dict()[value_name])

        output_str += (":".join([key_val, entry_val]) + "\n")
    
    # cut last newline
    output_str = output_str[:-1]

    fd = open(output_file, "w+")
    fd.write(output_str)
    fd.close()

def get_index_and_value_tunnel(entry_list, value_name1, value_name2):

    value_tuple_list = []

    for entry in entry_list:
        key = entry[1]
        value = entry[0]

        key_val = str(key.to_dict()["$REGISTER_INDEX"]["value"])
        entry_val_1 = str(value.to_dict()[value_name1][1])
        entry_val_2 = str(value.to_dict()[value_name2][1])

#        output_str += (":".join([key_val, entry_val]) + "\n")
 
        if entry_val_1 != '0' and int(entry_val_2) > COUNTER_OVER_N_IS_DNS_TUNNEL:
            value_tuple = (entry_val_1,entry_val_2)
            value_tuple_list.append(value_tuple)

    # cut last newline
    #output_str = output_str[:-1]

#    fd = open(output_file, "w+")
#    fd.write(output_str)
#    fd.close()

    return value_tuple_list

def main():
    print("Starting...")


    grpc_addr = 'localhost:50052'
    client_id = 1
    is_master = False
    p4_name = "netassay_tunnel_j8"
    
    interface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=0, is_master=is_master)
    interface.bind_pipeline_config(p4_name)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    bfrt_info = interface.bfrt_info_get(p4_name)
 
    def signal_handler(sig, frame):
        print('You pressed Ctrl+C! Tearing down gRPC connection...')
        interface._tear_down_stream()
    
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while 1:
        # pull regsiters 1
        client_reg_pair_1 = bfrt_info.table_get("SwitchEgress.client_reg_pair_1")
        entries_list = client_reg_pair_1.entry_get(target)
        ip_count_pair_list_1 = get_index_and_value_tunnel(entries_list, "SwitchEgress.client_reg_pair_1.cip", "SwitchEgress.client_reg_pair_1.counter")

        # pull regsiters 2
        client_reg_pair_2 = bfrt_info.table_get("SwitchEgress.client_reg_pair_2")
        entries_list = client_reg_pair_2.entry_get(target)
        ip_count_pair_list_2 = get_index_and_value_tunnel(entries_list, "SwitchEgress.client_reg_pair_2.cip", "SwitchEgress.client_reg_pair_2.counter")

        # combine
        ip_count_pair_list_all = ip_count_pair_list_1 + ip_count_pair_list_2

        # print
        print("Suspected clients using DNS tunneling...(w/ counter value):")
        for i in ip_count_pair_list_all:
            ip_addr = socket.inet_ntoa(struct.pack("!I", int(i[0])))
            print("- {}: {}".format(str(ip_addr),str(i[1])))

        print("\n\n")

        # sleep
        time.sleep(INTERVAL_SECONDS)

    # Tear down.
    interface._tear_down_stream()
    exit()
    interface._tear_down_stream()



if __name__ == "__main__":
    main()

