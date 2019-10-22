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

    def messageReceived(self, connectionPort, dataDict):
        if self.connections[connectionPort]["dh"].getSharedKey():
            print("Message - my key =",self.connections[connectionPort]["dh"].getSharedKey(), "recv m=", dataDict["message"])               ## TODO Actually decrypt
        else:
            print("Error - Key not available to decrypt")

    def keyReceived(self, connectionPort, dataDict):
        if connectionPort in self.connections:
            if self.connections[connectionPort]["dh"].getSharedKey() is None:
                pass       ## TODO        
            if dataDict["requestKey"]:
                # other needs key
                self.sendKeyToConnection(connectionPort)
        else:            
            # receive new connection
            self.connections[connectionPort] = {"name":dataDict["name"], "dh": DH(self.secretKey, dataDict["publicKey"])}
            if dataDict["requestKey"]:
                self.sendKeyToConnection(connectionPort)
            print("Log - new connection",dataDict["name"],"added")


    def receiveThreadFunction(self):
        while True:
            data, recvAddress = self.sock.recvfrom(4096)
            dataDict = self.binaryToDict(data)
            recvPort = recvAddress[1]

            if dataDict["type"]=="message":
                self.messageReceived(recvPort, dataDict)
            if dataDict["type"]=="key":
                self.keyReceived(recvPort, dataDict)



            # address in connections
            if recvPort in self.connections:
                print(data, recvAddress)
            else:

                if dataDict["type"]=="key":
                    # receive new connection
                    self.connections[recvPort] = {"name":dataDict["name"], "dh": DH(self.secretKey, dataDict["publicKey"])}
                    if dataDict["requestKey"]:
                        self.sendKeyToConnection(recvPort)
                    print("Log - new connection",dataDict["name"],"added")

    # make new conn
    def addConnection(self, connectionPort, receivedKey=None):
        if receivedKey:
            self.connections[connectionPort] = {"name":None, "dh": DH(self.mySecretKey)}
            self.connections[connectionPort]["dh"].computeSharedKey(receivedKey)
            self.sendKeyToConnection(connectionPort, False)
        else:
            self.connections[connectionPort] = {"name":None, "dh": DH(self.mySecretKey)}
            self.sendKeyToConnection(connectionPort, True)
        print("Added connection",connectionPort)

    # send shared key to all
    def sendKeyToConnection(self, connectionPort, requestKey=False):
        messageDict = {"type": "key", "name": self.myName, "publicKey": self.connections[connectionPort]["dh"].getPublicKey(), "requestKey": requestKey}
        self.sock.sendto(self.dictToBinary(messageDict),('localhost',connectionPort))

    # send en message
    def sendMessage(self, connectionPort, message):
        if self.connections[connectionPort]["dh"].getSharedKey() is None:
            # shared key not available
            print("Error - channel not protected")
        else:
            # shared key available
            encryptedMessage = self.connections[connectionPort]["dh"].getSharedKey()+message             ## TODO Actually encrypt
            messageDict = {"type": "message","name": self.myName, "message": encryptedMessage}
            self.sock.sendto(self.dictToBinary(messageDict),('localhost',connectionPort))

    # receive new connection

    # receive old connection key

    # utilities
    def dictToBinary(self, inputDict):
        tempJSON = json.dumps(inputDict)
        return str.encode(tempJSON)
    
    def binaryToDict(self, inputBinary):
        tempJSON = inputBinary.decode()
        return json.loads(tempJSON)


    # receive en message
