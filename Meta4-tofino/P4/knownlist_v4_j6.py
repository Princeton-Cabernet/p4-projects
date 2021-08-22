import ipaddress

globalID = 0
globalPriority = 1

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

    bfrt.netassay_v4_j6.pipe.SwitchIngress.known_domain_list.add_with_match_domain(
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
    bfrt.netassay_v4_j6.pipe.SwitchIngress.banned_dns_dst.add_with_match_banned_dns_dst(dst=ipaddr,dst_p_length=mask)

def addAllowedIpToTable(ip, bfrt):
    ipList = ip.split('/')
    if (len(ipList) == 2):
        mask = int(ipList[1])
    elif (len(ipList) == 1):
        mask = 32
    else:
        exit(-1)
    ipaddr = int(ipaddress.IPv4Address(ipList[0]))
    bfrt.netassay_v4_j6.pipe.SwitchIngress.banned_dns_dst.add_with_NoAction(dst=ipaddr,dst_p_length=mask)
    
def main(bfrt):
    global globalID
    global globalPriority

    '''domains = [
        'collector.brandmetrics.com',
        'www.google.com',
'calendar.google.com',
'pxml10.4publishers.com',
's1.4publishers.com',
'ssl.gstatic.com',
'*.skype.com',
'*.live.com',
'messenger.hotmail.com',
'*.*.msn.com',
'*.msn.com',
'cp.intl.match.com',
'www.gowindowslive.com',
'view.atdmt.com',
'*.smartadserver.com',
'*.salesforce.com',
'*.*.salesforce.com',
'*',
'*.*',
'*.*.*',
'*.*.*.*'
    ]'''
    domains = ['*.gather.town',
'gather.town',
'*.gatherly.io',
'gatherly.io',
'api.teams.skype.com',
'img.teams.skype.com',
'teams.microsoft.com',
'teams.microsoft.us',
'teams.skype.com',
'ciscopark.com',
'webex.com',
'lync.com',
'skype.akadns.net',
'skype.com',
'skypeassets.com',
'skypedata.akadns.net',
'skypeecs-prod-use-0-b.cloudapp.net',
'skypeecs-prod-usw-0.cloudapp.net',
'skypeforbusiness.com',
'hangouts.google.com',
'*.steamcontent.com',
'*.*.steamcontent.com',
'*.xboxlive.com',
'*.epicgames.com',
'*.*.epicgames.com',
'*.icloud-content.com',
'*.oca.nflxvideo.net',
'outlook.office365.com',
'*.outlook.office365.com',
'*.cdninstagram.com',
'*.*.cdninstagram.com',
'*.cdn-apple.com',
'*.*.cdn-apple.com',
'*.reddit.com',
'*.*.reddit.com',
'*.googlevideo.com',
'*.microsoft.com',
'www.google.com',
'*.www.google.com',
'www.youtube.com',
'*.www.youtube.com',
'zoom.us',
'*.zoom.us',
'*.*.zoom.us',
'*.*.amazonaws.com',
'www.apple.com',
'*.www.apple.com',
'play.google.com',
'*.play.google.com',
'mail.google.com',
'*.mail.google.com',
'www.facebook.com',
'*.www.facebook.com',
'*.*.nytimes.com',
'*.hardlightgames.com',
'*.*.hardlightgames.com',
'facebook.com',
'www.gstatic.com',
'*.www.gstatic.com',
'itunes.apple.com',
'*.apple.com',
'*.icloud.com',
'*.*.icloud.com',
'*.nytimes.com',
'*.gstatic.com',
'*.*.gstatic.com',
'*.facebook.com',
'*.princeton.edu',
'*.*.princeton.edu',
'*.google.com',
'www.bloomberg.com',
'*.www.bloomberg.com',
'*.groupme.com',
'*.*.groupme.com',
'www.bing.com',
'*.www.bing.com',
'*.l.google.com',
'www.linkedin.com',
'*.www.linkedin.com',
'www.messenger.com',
'*.www.messenger.com',
'web.whatsapp.com',
'*.web.whatsapp.com',
'*.live.com',
'*.itunes.apple.com',
'www.nps.gov',
'*.www.nps.gov',
'piazza.com',
'*.*.piazza.com',
'*.piazza.com',
'slack.com',
'*.*.slack.com',
'google.com',
'www.overleaf.com',
'*.www.overleaf.com',
'www.netflix.com',
'*.www.netflix.com',
'*.clemson.cloudlab.us',
'www.hulu.com',
'*.www.hulu.com',
'*.hulu.com',
'*.*.hulu.com',
'www.gradesaver.com',
'*.www.gradesaver.com',
'config.edge.skype.com',
'www.naver.com',
'*.www.naver.com',
'*.target.com',
'*.*.target.com',
'*.akamaihd.net',
'*.*.akamaihd.net',
'www.cdc.gov',
'*.www.cdc.gov',
'www.bestbuy.com',
'*.www.bestbuy.com',
'www.adobe.com',
'*.www.adobe.com',
'www.outlook.com',
'*.www.outlook.com',
'www.instagram.com',
'*.www.instagram.com',
'www.tumblr.com',
'*.www.tumblr.com',
'*.*.microsoft.com',
'www.constitution.org',
'*.www.constitution.org',
'i.instagram.com',
'*.i.instagram.com',
'v.redd.it',
'*.v.redd.it',
'*.media-amazon.com',
'*.*.media-amazon.com',
'www.googleapis.com',
'*.www.googleapis.com',
'*.googleapis.com',
'*.*.googleapis.com',
'*.vzuu.com',
'*.*.vzuu.com',
'*.giphy.com',
'*.*.giphy.com',
'*.umaryland.edu',
'*.*.umaryland.edu',
'i.imgur.com',
'*.i.imgur.com',
'*.twimg.com',
'*.*.twimg.com',
'*.*.googlevideo.com',
'*.*.steamstatic.com',
'www.carmera.com',
'*.www.carmera.com',
'*.*.fbcdn.net',
'*.cdn.office.net',
'*.*.akamai.net',
'*.facebook.net',
'*.*.facebook.net',
'*.freecodecamp.org',
'*.*.freecodecamp.org',
'www.youtube-nocookie.com',
'*.www.youtube-nocookie.com',
'*.gmail.com',
'*.*.gmail.com',
'*.akamaized.net',
'*.*.akamaized.net',
'*.yahoo.com',
'*.*.aaplimg.com',
'*.*.adobe.com',
'*.*.icloud-content.com',
'princeton.service-now.com',
'*.princeton.service-now.com',
'princeton.instructure.com',
'*.princeton.instructure.com',
'outlook.office.com',
'*.outlook.office.com',
'*.*.google.com',
'*.windowsupdate.com',
'*.*.windowsupdate.com',
'*.slack-edge.com',
'*.*.slack-edge.com',
'*.teads.tv',
'*.*.teads.tv',
'*.googleusercontent.com',
'*.*.googleusercontent.com',
'*.evernote.com',
'*.*.evernote.com',
'www.budgetsaresexy.com',
'*.www.budgetsaresexy.com',
'*.cnn.com',
'*.*.cnn.com',
'download.mcafee.com',
'*.download.mcafee.com',
'*.eecs.berkeley.edu',
'*.wikimedia.org',
'*.*.wikimedia.org',
'*.nflxext.com',
'*.*.nflxext.com',
'*.*.llnwd.net',
'*.mhyunbo.com',
'*.*.mhyunbo.com',
'api.alliancelslabs.com',
'*.api.alliancelslabs.com',
'*.tokbox.com',
'*.*.tokbox.com',
'*.*.apple-dns.net',
'*.adobe.com',
'*.hulustream.com',
'*.*.hulustream.com',
'api.twitter.com',
'*.api.twitter.com',
'*.*.facebook.com',
'*.instagram.com',
'*.*.instagram.com',
'*.*.office.com',
'*.amazon.com',
'*.*.amazon.com',
'www.googletagservices.com',
'*.www.googletagservices.com',
'www.google-analytics.com',
'*.www.google-analytics.com',
's.imgur.com',
'*.s.imgur.com',
'*.discordapp.com',
'*.*.discordapp.com',
'*.windows.com',
'*.*.windows.com',
'*.slack.com',
'*.*.slack.com',
'*.dell.com',
'*.*.dell.com',
'*.microsoftonline.com',
'*.*.microsoftonline.com',
'www.googleadservices.com',
'*.www.googleadservices.com',
'*.wsj.net',
'*.*.wsj.net',
'*.cambridge.org',
'*.*.cambridge.org',
'*.bing.com',
'*.*.bing.com',
'*.*.skype.com',
'*.skype.com',
'*.nyt.com',
'*.*.nyt.com',
'*.twitchcdn.net',
'*.*.twitchcdn.net',
'*.*.apple.com',
'*.*.yahoo.com',
'*.comcast.net',
'*.*.comcast.net',
'*.amazonaws.com',
'*.apple.news',
'*.*.apple.news',
'*.aol.com',
'*.*.aol.com',
'*.msn.com',
'*.*.msn.com',
'*.twitter.com',
'*.*.twitter.com',
'*.*.dropbox.com',
'*.dropbox.com',
'*.douyucdn.cn',
'*.*.douyucdn.cn',
'*.download05.com',
'*.*.download05.com',
'*.whatsapp.net',
'*.*.whatsapp.net',
'*.msedge.com',
'*.*.msedge.com',
'*.cloudfront.net',
'*.*.cloudfront.net',
'*.redditmedia.com',
'*.*.redditmedia.com',
'*.dartmouth.edu',
'*.*.dartmouth.edu',
'*.yale.edu',
'*.*.yale.edu',
'*.office.net',
'*.*.office.net',
'*.craigslist.org',
'*.*.craigslist.org',
'*.blackboard.com',
'*.*.blackboard.com',
'*.twitch.tv',
'*.*.live.com',
'*.googleadservices.com',
'*.*.googleadservices.com',
'*.dropboxapi.com',
'*.*.dropboxapi.com',
'*.overleaf.com',
'*.*.overleaf.com',
'*.*.twitch.tv',
'*.*.xboxlive.com',
'*.*.samsung.com',
'*.smartadserver.com',
'*.*.smartadserver.com',
'*.com',
'*.*.com',
'*.*.*.com',
'*.net',
'*.*.net',
'*.*.*.net',
'*.gov',
'*.*.gov',
'*.*.*.gov',
'*.edu',
'*.*.edu',
'*.*.*.edu',
'*.org',
'*.*.org',
'*.*.*.org',
'*',
'*.*',
'*.*.*',
'*.*.*.*']

    for d in domains:
        addDomainToTable(d, bfrt)

    bannedip = ['128.112.36.65',
'128.112.22.215',
'128.112.148.84',
'128.112.194.222',
'128.112.227.181',
'128.112.26.52',
'128.112.229.203',
'10.8.122.41',
'128.112.129.116',
'128.112.109.249',
'128.112.180.113',
'128.112.60.67',
'128.112.192.184',
'10.8.43.147',
'128.112.31.215']

    for ip in bannedip:
        addBannedIpToTable(ip, bfrt)

    allowedip = ['128.112.0.0/16',
'140.180.0.0/16',
'204.153.48.0/23',
'66.180.176.0/24',
'66.180.177.0/24',
'66.180.180.0/22',
'10.24.0.0/15',
'10.8.0.0/15']

    if (len(allowedip) > 0):
        addBannedIpToTable('0.0.0.0/0', bfrt)
    for ip in allowedip:
        addAllowedIpToTable(ip, bfrt)

