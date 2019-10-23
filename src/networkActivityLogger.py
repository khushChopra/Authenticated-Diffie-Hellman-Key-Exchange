import socket, sys, threading, json, pickle
from pprint import pprint

PORT = 10010

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(('localhost',PORT))
print("Logges started at port -",PORT)

# region utility functions
def binaryToDict(inputBinary):
    # tempJSON = inputBinary.decode()
    return pickle.loads(inputBinary)
# endregion

while True:
    data, recvAddress = sock.recvfrom(4096)
    dataDict = binaryToDict(data)
    recvPort = recvAddress[1]
    print("From -",recvPort)
    print("Message ->")
    pprint(dataDict)
    print()