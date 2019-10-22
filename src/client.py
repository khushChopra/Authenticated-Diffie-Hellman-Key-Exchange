import socket, sys, threading, json
from DH import DH

class Client:
    def __init__(self, myPort, mySecretKey, myName):
        self.myName = myName
        self.myPort = myPort
        self.mySecretKey = mySecretKey
        self.connections = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('localhost',self.myPort))
        self.receiveThread = threading.Thread(target=self.receiveThreadFunction, name=self.myName)
        self.receiveThread.start()

    def receiveThreadFunction(self):
        while True:
            data, recvAddress = self.sock.recvfrom(4096)
            dataJSON = data.decode()
            dataDict = json.loads(dataJSON)
            recvPort = recvAddress[1]
            # address in connections
            if recvPort in self.connections:
                print(data, recvAddress)
            else:
                # receive new connection
                newDH = DH(self.mySecretKey)
                newDH.computeSharedKey(dataDict['publicKey'])
                self.connections[recvPort] = {"name":dataDict["name"], "dh": newDH}
                messageDict = {"name": self.myName, "publicKey": newDH.getPublicKey()}
                messageJSON = json.dumps(messageDict)
                self.sock.sendto(str.encode(messageJSON),recvAddress)
                print("Log - new connection",dataDict["name"],"added")

    # make new conn
    def addConnection(self, connectionPort):
        self.connections[connectionPort] = {"name":None, "dh": DH(self.mySecretKey)}
        self.sendKeyToAll()
        print("Added connection",connectionPort)

    # send shared key to all
    def sendKeyToAll(self):
        for conn in self.connections:
            messageDict = {"name": self.myName, "publicKey": self.connections[conn]["dh"].getPublicKey()}
            messageJSON = json.dumps(messageDict)
            self.sock.sendto(str.encode(messageJSON),('localhost',conn))
    

    # receive new connection

    # receive old connection key

    # send en message

    # receive en message
