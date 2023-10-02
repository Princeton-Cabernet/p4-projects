import ipaddress
import os

globalID = 0
globalPriority = 1
#INPUT_DIR_WITH_CSVS = '/home/hyojoonk/Work/p4netassay/iot_domains/'
INPUT_DIR_WITH_CSVS = '/u/hyojoonk/Work/p4netassay/iot_domains/'

def dictSetUp():
    partsDict = {
        "headers.q1_part1.part": [0, 0],
        "headers.q1_part1.valid": [0, 0],
        "headers.q1_part2.part": [0, 0],
        "headers.q1_part2.valid": [0, 0],
        "headers.q1_part4.part": [0, 0],
        "headers.q1_part4.valid": [0, 0],
        "headers.q1_part8_1.part": [0, 0],
        "headers.q1_part8_1.valid": [0, 0],
        "headers.q1_part8_2.part": [0, 0],
        "headers.q1_part8_2.valid": [0, 0],
        "headers.q2_part1.part": [0, 0],
        "headers.q2_part1.valid": [0, 0],
        "headers.q2_part2.part": [0, 0],
        "headers.q2_part2.valid": [0, 0],
        "headers.q2_part4.part": [0, 0],
        "headers.q2_part4.valid": [0, 0],
        "headers.q2_part8_1.part": [0, 0],
        "headers.q2_part8_1.valid": [0, 0],
        "headers.q2_part8_2.part": [0, 0],
        "headers.q2_part8_2.valid": [0, 0],
        "headers.q3_part1.part": [0, 0],
        "headers.q3_part1.valid": [0, 0],
        "headers.q3_part2.part": [0, 0],
        "headers.q3_part2.valid": [0, 0],
        "headers.q3_part4.part": [0, 0],
        "headers.q3_part4.valid": [0, 0],
        "headers.q3_part8_1.part": [0, 0],
        "headers.q3_part8_1.valid": [0, 0],
        "headers.q3_part8_2.part": [0, 0],
        "headers.q3_part8_2.valid": [0, 0],
        "headers.q4_part1.part": [0, 0],
        "headers.q4_part1.valid": [0, 0],
        "headers.q4_part2.part": [0, 0],
        "headers.q4_part2.valid": [0, 0],
        "headers.q4_part4.part": [0, 0],
        "headers.q4_part4.valid": [0, 0],
        "headers.q4_part8_1.part": [0, 0],
        "headers.q4_part8_1.valid": [0, 0],
        "headers.q4_part8_2.part": [0, 0],
        "headers.q4_part8_2.valid": [0, 0]
    }
    return partsDict

    
# Outputs a reversed, 5 digit, binary representation
def toReversedBinary(num):
    num1 = bin(num)[2::] # cut out 0b prefix
    if len(num1) >= 5:
        num1 = num1[len(num1)-5:len(num1):]
    else:
        for i in range(0, 5-len(num1)):
            num1 = '0' + num1
    return num1[::-1]

def addPart1ToDict(part, partsDict):

    if (part == '*'):
        partsDict["headers.q1_part1.valid"] = [0, 0]
        partsDict["headers.q1_part2.valid"] = [0, 0]
        partsDict["headers.q1_part4.valid"] = [0, 0]
        partsDict["headers.q1_part8_1.valid"] = [0, 0]
        partsDict["headers.q1_part8_2.valid"] = [0, 0]
        partsDict["headers.q1_part1.part"] = [0, 0]
        partsDict["headers.q1_part2.part"] = [0, 0]
        partsDict["headers.q1_part4.part"] = [0, 0]
        partsDict["headers.q1_part8_1.part"] = [0, 0]
        partsDict["headers.q1_part8_2.part"] = [0, 0]
        return partsDict

    part1Spec = toReversedBinary(len(part))

    charIndex = 0
    if part1Spec[0] == '1':
        partsDict["headers.q1_part1.part"] = [int(part[charIndex].encode('utf-8').hex(), 16), 255]
        charIndex = charIndex + 1
        partsDict["headers.q1_part1.valid"] = [1, 1]
    if part1Spec[1] == '1':
        partsDict["headers.q1_part2.part"] = [int(part[charIndex:charIndex+2].encode('utf-8').hex(), 16), 65535]
        charIndex = charIndex + 2
        partsDict["headers.q1_part2.valid"] = [1, 1]
    if part1Spec[2] == '1':
        partsDict["headers.q1_part4.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part4.valid"] = [1, 1]
    if part1Spec[3] == '1':
        partsDict["headers.q1_part8_1.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part8_2.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part8_1.valid"] = [1, 1]
        partsDict["headers.q1_part8_2.valid"] = [1, 1]
        
    return partsDict

def addPart2ToDict(part, partsDict):

    if (part == '*'):
        partsDict["headers.q2_part1.valid"] = [0, 0]
        partsDict["headers.q2_part2.valid"] = [0, 0]
        partsDict["headers.q2_part4.valid"] = [0, 0]
        partsDict["headers.q2_part8_1.valid"] = [0, 0]
        partsDict["headers.q2_part8_2.valid"] = [0, 0]
        partsDict["headers.q2_part1.part"] = [0, 0]
        partsDict["headers.q2_part2.part"] = [0, 0]
        partsDict["headers.q2_part4.part"] = [0, 0]
        partsDict["headers.q2_part8_1.part"] = [0, 0]
        partsDict["headers.q2_part8_2.part"] = [0, 0]
        return partsDict

    part2Spec = toReversedBinary(len(part))

    charIndex = 0
    if part2Spec[0] == '1':
        partsDict["headers.q2_part1.part"] = [int(part[charIndex].encode('utf-8').hex(), 16), 255]
        charIndex = charIndex + 1
        partsDict["headers.q2_part1.valid"] = [1, 1]
    if part2Spec[1] == '1':
        partsDict["headers.q2_part2.part"] = [int(part[charIndex:charIndex+2].encode('utf-8').hex(), 16), 65535]
        charIndex = charIndex + 2
        partsDict["headers.q2_part2.valid"] = [1, 1]
    if part2Spec[2] == '1':
        partsDict["headers.q2_part4.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part4.valid"] = [1, 1]
    if part2Spec[3] == '1':
        partsDict["headers.q2_part8_1.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part8_2.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part8_1.valid"] = [1, 1]
        partsDict["headers.q2_part8_2.valid"] = [1, 1]
    return partsDict

def addPart3ToDict(part, partsDict):

    if (part == '*'):
        partsDict["headers.q3_part1.valid"] = [0, 0]
        partsDict["headers.q3_part2.valid"] = [0, 0]
        partsDict["headers.q3_part4.valid"] = [0, 0]
        partsDict["headers.q3_part8_1.valid"] = [0, 0]
        partsDict["headers.q3_part8_2.valid"] = [0, 0]
        partsDict["headers.q3_part1.part"] = [0, 0]
        partsDict["headers.q3_part2.part"] = [0, 0]
        partsDict["headers.q3_part4.part"] = [0, 0]
        partsDict["headers.q3_part8_1.part"] = [0, 0]
        partsDict["headers.q3_part8_2.part"] = [0, 0]
        return partsDict

    part3Spec = toReversedBinary(len(part))

    charIndex = 0
    if part3Spec[0] == '1':
        partsDict["headers.q3_part1.part"] = [int(part[charIndex].encode('utf-8').hex(), 16), 255]
        charIndex = charIndex + 1
        partsDict["headers.q3_part1.valid"] = [1, 1]
    if part3Spec[1] == '1':
        partsDict["headers.q3_part2.part"] = [int(part[charIndex:charIndex+2].encode('utf-8').hex(), 16), 65535]
        charIndex = charIndex + 2
        partsDict["headers.q3_part2.valid"] = [1, 1]
    if part3Spec[2] == '1':
        partsDict["headers.q3_part4.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part4.valid"] = [1, 1]
    if part3Spec[3] == '1':
        partsDict["headers.q3_part8_1.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part8_2.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part8_1.valid"] = [1, 1]
        partsDict["headers.q3_part8_2.valid"] = [1, 1]
    return partsDict

def addPart4ToDict(part, partsDict):

    if (part == '*'):
        partsDict["headers.q4_part1.valid"] = [0, 0]
        partsDict["headers.q4_part2.valid"] = [0, 0]
        partsDict["headers.q4_part4.valid"] = [0, 0]
        partsDict["headers.q4_part8_1.valid"] = [0, 0]
        partsDict["headers.q4_part8_2.valid"] = [0, 0]
        partsDict["headers.q4_part1.part"] = [0, 0]
        partsDict["headers.q4_part2.part"] = [0, 0]
        partsDict["headers.q4_part4.part"] = [0, 0]
        partsDict["headers.q4_part8_1.part"] = [0, 0]
        partsDict["headers.q4_part8_2.part"] = [0, 0]
        return partsDict

    part4Spec = toReversedBinary(len(part))

    charIndex = 0
    if part4Spec[0] == '1':
        partsDict["headers.q4_part1.part"] = [int(part[charIndex].encode('utf-8').hex(), 16), 255]
        charIndex = charIndex + 1
        partsDict["headers.q4_part1.valid"] = [1, 1]
    if part4Spec[1] == '1':
        partsDict["headers.q4_part2.part"] = [int(part[charIndex:charIndex+2].encode('utf-8').hex(), 16), 65535]
        charIndex = charIndex + 2
        partsDict["headers.q4_part2.valid"] = [1, 1]
    if part4Spec[2] == '1':
        partsDict["headers.q4_part4.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part4.valid"] = [1, 1]
    if part4Spec[3] == '1':
        partsDict["headers.q4_part8_1.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part8_2.part"] = [int(part[charIndex:charIndex+4].encode('utf-8').hex(), 16), 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part8_1.valid"] = [1, 1]
        partsDict["headers.q4_part8_2.valid"] = [1, 1]
    return partsDict

def addDictToBfrt(dict_t, bfrt):
    global globalID
    global globalPriority
    globalID = globalID + 1

    bfrt.netassay_iot_j6.pipe.SwitchIngress.known_domain_list.add_with_match_domain(
        #q1_part1_valid, q1_part1_valid_mask
    q1_part1_part=dict_t['headers.q1_part1.part'][0],q1_part1_part_mask=dict_t['headers.q1_part1.part'][1],
    q1_part2_part=dict_t['headers.q1_part2.part'][0],q1_part2_part_mask=dict_t['headers.q1_part2.part'][1],
    q1_part4_part=dict_t['headers.q1_part4.part'][0],q1_part4_part_mask=dict_t['headers.q1_part4.part'][1],
    q1_part8_1_part=dict_t['headers.q1_part8_1.part'][0],q1_part8_1_part_mask=dict_t['headers.q1_part8_1.part'][1],
    q1_part8_2_part=dict_t['headers.q1_part8_2.part'][0],q1_part8_2_part_mask=dict_t['headers.q1_part8_2.part'][1],
    q2_part1_part=dict_t['headers.q2_part1.part'][0],q2_part1_part_mask=dict_t['headers.q2_part1.part'][1],
    q2_part2_part=dict_t['headers.q2_part2.part'][0],q2_part2_part_mask=dict_t['headers.q2_part2.part'][1],
    q2_part4_part=dict_t['headers.q2_part4.part'][0],q2_part4_part_mask=dict_t['headers.q2_part4.part'][1],
    q2_part8_1_part=dict_t['headers.q2_part8_1.part'][0],q2_part8_1_part_mask=dict_t['headers.q2_part8_1.part'][1],
    q2_part8_2_part=dict_t['headers.q2_part8_2.part'][0],q2_part8_2_part_mask=dict_t['headers.q2_part8_2.part'][1],
    q3_part1_part=dict_t['headers.q3_part1.part'][0],q3_part1_part_mask=dict_t['headers.q3_part1.part'][1],
    q3_part2_part=dict_t['headers.q3_part2.part'][0],q3_part2_part_mask=dict_t['headers.q3_part2.part'][1],
    q3_part4_part=dict_t['headers.q3_part4.part'][0],q3_part4_part_mask=dict_t['headers.q3_part4.part'][1],
    q3_part8_1_part=dict_t['headers.q3_part8_1.part'][0],q3_part8_1_part_mask=dict_t['headers.q3_part8_1.part'][1],
    q3_part8_2_part=dict_t['headers.q3_part8_2.part'][0],q3_part8_2_part_mask=dict_t['headers.q3_part8_2.part'][1],
    q4_part1_part=dict_t['headers.q4_part1.part'][0],q4_part1_part_mask=dict_t['headers.q4_part1.part'][1],
    q4_part2_part=dict_t['headers.q4_part2.part'][0],q4_part2_part_mask=dict_t['headers.q4_part2.part'][1],
    q4_part4_part=dict_t['headers.q4_part4.part'][0],q4_part4_part_mask=dict_t['headers.q4_part4.part'][1],
    q4_part8_1_part=dict_t['headers.q4_part8_1.part'][0],q4_part8_1_part_mask=dict_t['headers.q4_part8_1.part'][1],
    q4_part8_2_part=dict_t['headers.q4_part8_2.part'][0],q4_part8_2_part_mask=dict_t['headers.q4_part8_2.part'][1],
    q1_part1_valid=dict_t['headers.q1_part1.valid'][0],q1_part1_valid_mask=dict_t['headers.q1_part1.valid'][1],
    q1_part2_valid=dict_t['headers.q1_part2.valid'][0],q1_part2_valid_mask=dict_t['headers.q1_part2.valid'][1],
    q1_part4_valid=dict_t['headers.q1_part4.valid'][0],q1_part4_valid_mask=dict_t['headers.q1_part4.valid'][1],
    q1_part8_1_valid=dict_t['headers.q1_part8_1.valid'][0],q1_part8_1_valid_mask=dict_t['headers.q1_part8_1.valid'][1],
    q1_part8_2_valid=dict_t['headers.q1_part8_2.valid'][0],q1_part8_2_valid_mask=dict_t['headers.q1_part8_2.valid'][1],
    q2_part1_valid=dict_t['headers.q2_part1.valid'][0],q2_part1_valid_mask=dict_t['headers.q2_part1.valid'][1],
    q2_part2_valid=dict_t['headers.q2_part2.valid'][0],q2_part2_valid_mask=dict_t['headers.q2_part2.valid'][1],
    q2_part4_valid=dict_t['headers.q2_part4.valid'][0],q2_part4_valid_mask=dict_t['headers.q2_part4.valid'][1],
    q2_part8_1_valid=dict_t['headers.q2_part8_1.valid'][0],q2_part8_1_valid_mask=dict_t['headers.q2_part8_1.valid'][1],
    q2_part8_2_valid=dict_t['headers.q2_part8_2.valid'][0],q2_part8_2_valid_mask=dict_t['headers.q2_part8_2.valid'][1],
    q3_part1_valid=dict_t['headers.q3_part1.valid'][0],q3_part1_valid_mask=dict_t['headers.q3_part1.valid'][1],
    q3_part2_valid=dict_t['headers.q3_part2.valid'][0],q3_part2_valid_mask=dict_t['headers.q3_part2.valid'][1],
    q3_part4_valid=dict_t['headers.q3_part4.valid'][0],q3_part4_valid_mask=dict_t['headers.q3_part4.valid'][1],
    q3_part8_1_valid=dict_t['headers.q3_part8_1.valid'][0],q3_part8_1_valid_mask=dict_t['headers.q3_part8_1.valid'][1],
    q3_part8_2_valid=dict_t['headers.q3_part8_2.valid'][0],q3_part8_2_valid_mask=dict_t['headers.q3_part8_2.valid'][1],
    q4_part1_valid=dict_t['headers.q4_part1.valid'][0],q4_part1_valid_mask=dict_t['headers.q4_part1.valid'][1],
    q4_part2_valid=dict_t['headers.q4_part2.valid'][0],q4_part2_valid_mask=dict_t['headers.q4_part2.valid'][1],
    q4_part4_valid=dict_t['headers.q4_part4.valid'][0],q4_part4_valid_mask=dict_t['headers.q4_part4.valid'][1],
    q4_part8_1_valid=dict_t['headers.q4_part8_1.valid'][0],q4_part8_1_valid_mask=dict_t['headers.q4_part8_1.valid'][1],
    q4_part8_2_valid=dict_t['headers.q4_part8_2.valid'][0],q4_part8_2_valid_mask=dict_t['headers.q4_part8_2.valid'][1],
    match_priority=globalPriority,id=globalID)

    globalPriority = globalPriority + 1

# If len(parts)==1
def oneparts(parts, bfrt):

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addDictToBfrt(dict_t, bfrt)

# If len(parts)==2
def twoparts(parts, bfrt):

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addPart2ToDict(parts[1], dict_t)
    addDictToBfrt(dict_t, bfrt)

# If len(parts)==3
def threeparts(parts, bfrt):

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addPart2ToDict(parts[1], dict_t)
    addPart3ToDict(parts[2], dict_t)
    addDictToBfrt(dict_t, bfrt)

# If len(parts)==4
def fourparts(parts, bfrt):

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addPart2ToDict(parts[1], dict_t)
    addPart3ToDict(parts[2], dict_t)
    addPart4ToDict(parts[3], dict_t)
    addDictToBfrt(dict_t, bfrt)

def addDomainToTable(domain, bfrt):
    parts = domain.split('.')
    numParts = len(parts)
    if numParts > 4:
        print("error: " + domain)
        return -1
    if numParts == 1:
        oneparts(parts, bfrt)
    elif numParts == 2:
        twoparts(parts, bfrt)
    elif numParts == 3:
        threeparts(parts, bfrt)
    elif numParts == 4:
        fourparts(parts, bfrt)

def addBannedIpToTable(ip, bfrt):
    ipList = ip.split('/')
    if (len(ipList) == 2):
        mask = int(ipList[1])
    elif (len(ipList) == 1):
        mask = 32
    else:
        exit(-1)
    ipaddr = int(ipaddress.IPv4Address(ipList[0]))
    bfrt.netassay_iot_j6.pipe.SwitchIngress.banned_dns_dst.add_with_match_banned_dns_dst(dst=ipaddr,dst_p_length=mask)

def addAllowedIpToTable(ip, bfrt):
    ipList = ip.split('/')
    if (len(ipList) == 2):
        mask = int(ipList[1])
    elif (len(ipList) == 1):
        mask = 32
    else:
        exit(-1)
    ipaddr = int(ipaddress.IPv4Address(ipList[0]))
    bfrt.netassay_iot_j6.pipe.SwitchIngress.banned_dns_dst.add_with_NoAction(dst=ipaddr,dst_p_length=mask)
    

def parse_csv(entry_list, domain_map):
    for e in entry_list[1:]:
        line_split = e.split(',')
        domain, device_cat = line_split[0], line_split[1]

        domain_map[domain.rstrip('.')] = device_cat


def get_iot_domains():

    # Map
    domain_map = {}

    if os.path.isdir(INPUT_DIR_WITH_CSVS):
        for filename in os.listdir(INPUT_DIR_WITH_CSVS):
            if not filename.endswith(".csv"):
                continue
            with open(os.path.join(INPUT_DIR_WITH_CSVS, filename), 'r') as fd:
                entry_list = fd.readlines()
            parse_csv(entry_list, domain_map)

    return domain_map


def main(bfrt):
    global globalID
    global globalPriority

    domain_map = get_iot_domains()
    domains = list(domain_map.keys())

    id_n = 1
    for d in domains:
        addDomainToTable(d, bfrt)  
        if (len(d.split("."))<5):
            print(id_n,d)
            id_n += 1
#    sys.exit(1)

    bannedip = []
    for ip in bannedip:
        addBannedIpToTable(ip, bfrt)

    allowedip = []
    if (len(allowedip) > 0):
        addBannedIpToTable('0.0.0.0/0', bfrt)
    for ip in allowedip:
        addAllowedIpToTable(ip, bfrt)

