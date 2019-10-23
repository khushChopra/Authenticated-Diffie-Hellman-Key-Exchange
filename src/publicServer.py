import socket, sys, threading, json

PORT = 10009

publicKeys = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('localhost',PORT))

# region utility functions
def dictToBinary(inputDict):
    tempJSON = json.dumps(inputDict)
    return str.encode(tempJSON)

def binaryToDict(inputBinary):
    tempJSON = inputBinary.decode()
    return json.loads(tempJSON)
# endregion

while True:
    data, recvAddress = sock.recvfrom(4096)
    dataDict = binaryToDict(data)
    recvPort = recvAddress[1]

    if dataDict["type"]=="register":
        # receives {"type": "register", "signaturePublicKey":/key/, "name":/name/}
        publicKeys[recvPort]=dataDict["signaturePublicKey"]
        print("Receives public key from", dataDict["name"],", address -",recvPort)
        print(publicKeys)              # debugging
    if dataDict["type"]=="verify":
        # receives {"type": "verify", "entityAddress": /address/}
        print("Received verification request from", recvPort)
        messageDict = {"type":"receiveSignaturePublicKey", "signaturePublicKey":publicKeys[dataDict["entityAddress"]]}
        sock.sendto(dictToBinary(messageDict),('localhost',recvPort))
        print("Response given -", messageDict)
        print()
