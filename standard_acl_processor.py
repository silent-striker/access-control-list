import os

def readFile(filePath):
    fileLines = []
    with open(filePath, "r") as file:
        print("Reading file at: ", filePath)
        for line in file:
            fileLines.append(line.replace('\n',''))
    return fileLines

def matcher(ip, sourceIp, mask):
    if sourceIp == 'any':
        return True
    
    ipParts = ip.split(".")
    sourceIpParts = sourceIp.split(".")
    maskParts = mask.split(".")

    for index in range(len(ipParts)):
        if maskParts[index] == '0' and ipParts[index] != sourceIpParts[index]:
            return False
    
    return True


def processAcl(aclStatements, ipList):
    for ip in ipList:
        output = "Packet from {} {}"
        denied = 'denied'
        permitted = 'permitted'
        for acl in aclStatements:
            aclParts = acl.split(' ')
            # for end of access-list statements
            if aclParts[0] != 'access-list':
                print(output.format(ip, denied))
                break
            
            action = aclParts[2]
            sourceIp = aclParts[3]
            mask = '255.255.255.255'
            if sourceIp != 'any':
                mask = aclParts[4]
            
            if matcher(ip, sourceIp, mask):
                if action == 'deny':
                    print(output.format(ip, denied))
                else:
                    print(output.format(ip, permitted))
                break


if __name__ == "__main__":
    print("Starting standard ACL processor script")
    currentPath = os.path.dirname(__file__)
    
    aclFile = "standard_acl_input.txt"
    aclPath = os.path.join(currentPath, aclFile)
    print(aclPath)

    ipFile = "standard_acl_ip_addresses.txt"
    ipPath = os.path.join(currentPath, ipFile)
    print(ipPath)

    aclStatements = readFile(aclPath)
    ipList = readFile(ipPath)

    print("==================================")
    processAcl(aclStatements, ipList)