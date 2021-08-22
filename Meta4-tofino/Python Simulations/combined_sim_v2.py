from sys import argv
import dpkt
import csv
import socket
import ipaddress
import pickle
import zlib
import numpy as np
import statistics

# Data structure and global variables
allowed_ips = []
banned_ips = []

known_domains = []

unlimitedNetTable = {}
unlimitedKnownDict = {}

netassayTables_parser = [] # Key is concatentation of server IP/client IP. Value is a knownlist domain name
knownlistDicts_parser = [] # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes

netassayTables_timeout = {}
knownlistDicts_timeout = {}

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet, ts):
    # Check if it is in the allowed or banned IP lists
    clientIP = socket.inet_ntoa(ip_packet.dst)
    cip_object = ipaddress.ip_network(clientIP)
    allowed = False
    for ip in allowed_ips:
        if is_subnet_of(cip_object, ip):
            allowed = True
            break

    if (not allowed):
        return

    for ip in banned_ips:
        if is_subnet_of(cip_object, ip):
            return


    try:
        dns = dpkt.dns.DNS(ip_packet.data.data)
    except:
        return
    answers = dns.an

    if len(answers) <= 0:
        return
    domain = answers[0].name
    domain_name = domain.split('.')

    for d in known_domains:
        if (matchDomain(d, domain)):
            
            for rr in answers:
                if (rr.type != 1):
                    continue
                if (rr.type == 1): #DNS.A
                    entry = unlimitedKnownDict[d]
                    unlimitedKnownDict[d][0] = unlimitedKnownDict[d][0] + 1
                    
                    serverIP = socket.inet_ntoa(rr.rdata)

                    key = clientIP + serverIP

                    unlimitedNetTable[key] = d
                    break
            break

    for t in range(0, 630, 30):
        # Parser limitations
        parser_test = True
        if (len(domain_name) > 4):
            parser_test = False
            continue
        for part in domain_name:
            if (len(part) > 15):
                parser_test = False
                break
        if (parser_test == False):
            continue
        
        for d in known_domains:
            if (matchDomain(d, domain)):
                

                for rr in answers:
                    if (rr.type != 1):
                        continue
                    if (rr.type == 1): #DNS.A
                        entry = knownlistDicts_timeout[t][d]
                        knownlistDicts_timeout[t][d][0] = knownlistDicts_timeout[t][d][0] + 1
                        
                        serverIP = socket.inet_ntoa(rr.rdata)

                        key = clientIP + serverIP

                        netassayTables_timeout[t][key] = [d, ts]
                        break
                break

    for i in range(0, 31):
    # Parser limitations

        parser_test = True
        if (len(domain_name) > 4):
            parser_test = False
            continue
        for part in domain_name:
            if (len(part) > i):
                parser_test = False
                break
        if (parser_test == False):
            continue

        for d in known_domains:
            if (matchDomain(d, domain)):
                

                for rr in answers:
                    if (rr.type != 1):
                        continue
                    if (rr.type == 1): #DNS.A
                        entry = knownlistDicts_parser[i][d]
                        knownlistDicts_parser[i][d][0] = knownlistDicts_parser[i][d][0] + 1
                        
                        serverIP = socket.inet_ntoa(rr.rdata)

                        key = clientIP + serverIP

                        netassayTables_parser[i][key] = d
                        break
                break
        

def parse_tcp(packet_len, ip_packet, ts):
    source = socket.inet_ntoa(ip_packet['src']) #server
    dest = socket.inet_ntoa(ip_packet['dst']) #client
    
    key = dest + source

    if key in unlimitedNetTable:
            d = unlimitedNetTable[key]
            unlimitedKnownDict[d][1] = unlimitedKnownDict[d][1] + 1
            unlimitedKnownDict[d][2] = unlimitedKnownDict[d][2] + packet_len


    serverIP32 = np.uint64(int.from_bytes(socket.inet_aton(source), byteorder='big'))
    clientIP32 = np.uint64(int.from_bytes(socket.inet_aton(dest), byteorder='big'))

    for t in range(0, 630, 30):
        if key in netassayTables_timeout[t]:
            if netassayTables_timeout[t][key][1] + t >= ts:
                netassayTables_timeout[t][key][1] = ts
                d = netassayTables_timeout[t][key][0]
                knownlistDicts_timeout[t][d][1] = knownlistDicts_timeout[t][d][1] + 1
                knownlistDicts_timeout[t][d][2] = knownlistDicts_timeout[t][d][2] + packet_len


    for i in range(0, 31):
        if key in netassayTables_parser[i]:
            d = netassayTables_parser[i][key]
            knownlistDicts_parser[i][d][1] = knownlistDicts_parser[i][d][1] + 1
            knownlistDicts_parser[i][d][2] = knownlistDicts_parser[i][d][2] + packet_len
        


def matchDomain(known, domain):
    knownparts = known.split('.')
    domainparts = domain.split('.')
    if len(knownparts) != len(domainparts):
        return False
    
    for i in range(0, len(knownparts)):
        if (knownparts[i] == '*'):
            continue
        if (knownparts[i] != domainparts[i]):
            return False
    return True


# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 5:
        print('usage: python netassay_python3_p4sim.py pickleFile knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt')
        exit(-1)
    
    # Parse allowed IP and banned IP files
    allowed_ip_file = open(argv[3], 'r')
    allowed_ip_list = allowed_ip_file.read().split()
    allowed_ip_file.close()
    for ip in allowed_ip_list:
        allowed_ips.append(ipaddress.ip_network(ip))

    banned_ip_file = open(argv[4], 'r')
    banned_ip_list = banned_ip_file.read().split()
    banned_ip_file.close()
    for ip in banned_ip_list:
        banned_ips.append(ipaddress.ip_network(ip))

    # Create knownlist
    knownlist = open(argv[2], 'r')
    known_domains = knownlist.read().split()
    knownlist.close()

    for d in known_domains:
            unlimitedKnownDict[d] = [0, 0, 0, 0, 0, 0]

    for i in range(0, 31):
        knownlistDict_i = {}
        for d in known_domains:
            knownlistDict_i[d] = [0, 0, 0, 0, 0, 0]
        knownlistDicts_parser.append(knownlistDict_i)
        netassayTables_parser.append({})

    for t in range(0, 630, 30):
        knownlistDict_t = {}
        for d in known_domains:
            knownlistDict_t[d] = [0, 0, 0, 0, 0, 0]
        knownlistDicts_timeout[t] = knownlistDict_t
        netassayTables_timeout[t] = {}


    f = open(argv[1], 'rb')
    pcap_obj = pickle.load(f)
    f.close()

    num_packets = len(pcap_obj)
    packet_count = 0.0

    for p in pcap_obj:
        ts = p[0]
        dns_code = p[1]
        ip = p[2]

        # For each packet parse the dns responses
        if (dns_code == -1):
            #try:
            parse_dns_response(ip, ts)
            '''except Exception as e:
                print(e)
                continue'''
        else:
            parse_tcp(dns_code, ip, ts)

        packet_count += 1
        if (packet_count % 1000 == 0):
            print(packet_count / num_packets)


    outfile_t = open('timeout_limits.txt', 'w')

    for t in range(0, 630, 30):
        
        with open('timeout_limit' + str(t) + '.csv', 'w') as csvfile:
            w = csv.writer(csvfile)
            w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

            for j in knownlistDicts_timeout[t].keys():
                num_packets = knownlistDicts_timeout[t][j][1]
                num_bytes = knownlistDicts_timeout[t][j][2]
                num_missed = knownlistDicts_timeout[t][j][3]
                num_dns = knownlistDicts_timeout[t][j][0]
                if (num_dns > 0 and num_missed < num_dns):
                    knownlistDicts_timeout[t][j][4] = num_packets / (1 - (num_missed / num_dns))
                    knownlistDicts_timeout[t][j][5] = num_bytes / (1 - (num_missed / num_dns))
                w.writerow([j, num_dns, num_missed, num_packets, num_bytes, knownlistDicts_timeout[t][j][4], knownlistDicts_timeout[t][j][5]])

        total_dns = 0
        total_packets = 0
        total_bytes = 0
        for m in knownlistDicts_timeout[t].items():
            total_dns += m[1][0]
            total_packets += m[1][1]
            total_bytes += m[1][2]
        outfile_t.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+'\n')

    outfile_t.close()

    outfile = open('parse_limits.txt', 'w')

    for i in range(0, 31):
        
        with open('parse_limit' + str(i * 4) + '.csv', 'w') as csvfile:
            w = csv.writer(csvfile)
            w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

            for j in knownlistDicts_parser[i].keys():
                num_packets = knownlistDicts_parser[i][j][1]
                num_bytes = knownlistDicts_parser[i][j][2]
                num_missed = knownlistDicts_parser[i][j][3]
                num_dns = knownlistDicts_parser[i][j][0]
                if (num_dns > 0 and num_missed < num_dns):
                    knownlistDicts_parser[i][j][4] = num_packets / (1 - (num_missed / num_dns))
                    knownlistDicts_parser[i][j][5] = num_bytes / (1 - (num_missed / num_dns))
                w.writerow([j, num_dns, num_missed, num_packets, num_bytes, knownlistDicts_parser[i][j][4], knownlistDicts_parser[i][j][5]])

        total_dns = 0
        total_packets = 0
        total_bytes = 0
        for m in knownlistDicts_parser[i].items():
            total_dns += m[1][0]
            total_packets += m[1][1]
            total_bytes += m[1][2]
        outfile.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+'\n')

    outfile.close()


    for i in unlimitedKnownDict.keys():
        num_packets = unlimitedKnownDict[i][1]
        num_bytes = unlimitedKnownDict[i][2]
        num_missed = unlimitedKnownDict[i][3]
        num_dns = unlimitedKnownDict[i][0]
        if (num_dns > 0 and num_missed < num_dns):
            unlimitedKnownDict[i][4] = num_packets / (1 - (num_missed / num_dns))
            unlimitedKnownDict[i][5] = num_bytes / (1 - (num_missed / num_dns))


    with open('unlimited_15min.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

        for i in unlimitedKnownDict.items():
            w.writerow([i[0], i[1][0], i[1][3], i[1][1], i[1][2], i[1][4], i[1][5]])

            


