import os

# reading file input and converting to a list
def readFile(filePath):
    fileLines = []
    with open(filePath, "r") as file:
        print("Reading file at: ", filePath)
        for line in file:
            fileLines.append(line.replace('\n',''))
    return fileLines

# matching the ip address with one in acl statement based on mask
def matcher(ip, aclIp, mask):
    if aclIp == 'any':
        return True
    
    ipParts = ip.split(".")
    aclIpParts = aclIp.split(".")
    maskParts = mask.split(".")

    for index in range(len(ipParts)):
        if maskParts[index] == '0' and ipParts[index] != aclIpParts[index]:
            return False
    
    return True

# assuming only eq, neq, gt, lt, range
def checkPorts(portToCheck, operator, ports):
    if operator == None:
        return True
    elif operator == 'eq':
        return portToCheck == ports[0]
    elif operator == 'neq':
        return portToCheck != ports[0]
    elif operator == 'gt':
        return portToCheck > ports[0]
    elif operator == 'lt':
        return portToCheck < ports[0]
    else:
        return portToCheck >= ports[0] and portToCheck <= ports[1]

def isOperator(operator):
    operatorList = ['neg', 'eq', 'gt', 'lt', 'range']
    return operator in operatorList

# source cases
# .... sip mask [port] ....
# .... sip mask [port] ....
# .... any [port] dip ....
# .... any [port] any ....

def extractSourceInfo(aclParts):
    sourceInfo = []
    ipAddr = aclParts[4]
    mask = aclParts[5]

    operatorIndex = 6

    # source is any
    if aclParts[4] == 'any':
        ipAddr = 'any'
        mask = '255.255.255.255'
        operatorIndex = 5
    
    sourceInfo.append(ipAddr)
    sourceInfo.append(mask)
    if isOperator(aclParts[operatorIndex]):
        portList = []
        portList.append(aclParts[operatorIndex])
        portList.extend(aclParts[operatorIndex+1].split('-'))
        sourceInfo.append(portList)
    else:
        sourceInfo.append(None)
    return sourceInfo

# destination cases
# .... any eq port
# .... any range start end
# .... dip mask eq port
# .... dip mask range start end
# ....  any
# .... dip mask
def extractDestinationInfo(aclParts):
    operatorIndex = -2
    destinationInfo = []
    
    # no ports
    if aclParts[-1] == 'any':
        operatorIndex=0

    ipAddr = aclParts[operatorIndex-2]
    mask = aclParts[operatorIndex-1]

    if aclParts[operatorIndex-1] == 'any':
        ipAddr = 'any'
        mask = '255.255.255.255'

    destinationInfo.append(ipAddr)
    destinationInfo.append(mask)
    
    if isOperator(aclParts[operatorIndex]): 
        portInfo = []
        portInfo.append(aclParts[operatorIndex])
        portInfo.extend(aclParts[-1].split('-'))
        destinationInfo.append(portInfo)
    else:
        destinationInfo.append(None)
    return destinationInfo


def printOutput(sourceIp, sourcePort, destinationIp, destinationPort, action):
    fromString = "Packet from {}".format(sourceIp)
    portString = " on port {}"
    toString = " to {}".format(destinationIp)

    output = fromString
    if sourcePort != None:
        output += portString.format(sourcePort)
    output += toString
    if destinationPort != None:
        output += portString.format(destinationPort)
    
    if action == 'permit':
        output += " permitted"
    else:
        output += " denied"
    print(output)



def processAcl(aclStatements, ipList):
    for ips in ipList:
        ipParts = ips.split(' ')
        sourceIp = ipParts[0]
        sourcePort = None
        if '.' in ipParts[1]:
            sourcePort = None
        else:
            sourcePort = int(ipParts[1])
        destIp = ipParts[-2:-1][0]
        destPort = int(ipParts[-1:][0])

        found = False

        for aclLine in aclStatements:
            aclParts = aclLine.split(' ')

            if aclParts[0] != "access-list":
                break

            action = aclParts[2]
            protocol = aclParts[3]
            
            sourceInfo = extractSourceInfo(aclParts)
            fromIp = sourceInfo[0]
            fromMask = sourceInfo[1]
            sourcePortOperator = None
            sourcePorts = []
            if sourceInfo[2] != None:
                sourcePortOperator = sourceInfo[2][0]
                sourcePorts = [int(val) for val in sourceInfo[2][1:]]
            
            destinationInfo = extractDestinationInfo(aclParts)
            toIp = destinationInfo[0]
            toMask = destinationInfo[1]
            destinationPortOperator = None
            destinationPorts = []
            if destinationInfo[2] != None:
                destinationPortOperator = destinationInfo[2][0]
                destinationPorts = [int(val) for val in destinationInfo[2][1:]]
            
            if matcher(sourceIp, fromIp, fromMask) and matcher(destIp, toIp, toMask) and checkPorts(sourcePort, sourcePortOperator, sourcePorts) and checkPorts(destPort, destinationPortOperator, destinationPorts ):
                printOutput(sourceIp, sourcePort, destIp, destPort, action)
                found = True
                break
        
        if not found:
            printOutput(sourceIp, sourcePort, destIp, destPort, "deny")

if __name__ == "__main__":
    print("Starting standard ACL processor script")
    currentPath = os.path.dirname(__file__)
    
    # give relative path of the extended acl statements file
    aclFile = "extended_acl_input.txt"
    aclPath = os.path.join(currentPath, aclFile)
    print(aclPath)

    # give relative path of the list of ip addresses file
    ipFile = "extended_acl_ip_addresses.txt"
    ipPath = os.path.join(currentPath, ipFile)
    print(ipPath)

    aclStatements = readFile(aclPath)
    ipList = readFile(ipPath)

    print("==================================")
    processAcl(aclStatements, ipList)