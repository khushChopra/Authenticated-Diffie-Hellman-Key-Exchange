import socket, sys, threading, json
from DH import DH
from encrypter import *
from keyController import *

import pickle

class Client:
    def __init__(self, myPort, mySecretKey, myName, addressOfPublicServer=10009):
        self.myName = myName
        self.myPort = myPort
        self.mySecretKey = mySecretKey
        self.addressOfPublicServer = addressOfPublicServer
        self.signaturePublicKey, self.signaturePrivateKey = getKeys()          ## as strings
        self.connections = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('localhost',self.myPort))
        self.registerToNetwork()
        self.receiveThread = threading.Thread(target=self.receiveThreadFunction, name=self.myName)
        self.receiveThread.start()
        self.currentNewConnectionPublicKey = None

    # registers to network // sends public key to public
    def registerToNetwork(self):
        print("Registering to network")
        messageDict = {"type": "register", "signaturePublicKey":self.signaturePublicKey, "name": self.myName}
        self.sock.sendto(self.dictToBinary(messageDict), ("localhost",self.addressOfPublicServer))
        print("Done")

    # get signaturePublicKey
    def getPublicKeyForNewConnection(self, connectionPort):
        receiverThread = threading.Thread(target=self.receiveFromPublicThreadFunction, name="signature receiver thread")
        receiverThread.start()
        messageDict = {"type": "verify", "entityAddress": connectionPort}
        self.sock.sendto(self.dictToBinary(messageDict), ('localhost',self.addressOfPublicServer))
        receiverThread.join()

    def receiveFromPublicThreadFunction(self):
        while True:
            data, recvAddress = self.sock.recvfrom(4096)
            dataDict = self.binaryToDict(data)
            if dataDict["type"]=="receiveSignaturePublicKey":
                self.currentNewConnectionPublicKey = dataDict["signaturePublicKey"]
                break

    # receive encrypted message
    def messageReceived(self, connectionPort, dataDict):
        if self.connections[connectionPort]["dh"].getSharedKey():
            print("Message from",self.connections[connectionPort]["name"],"-",decrypt(dataDict["message"],self.connections[connectionPort]["dh"].getSharedKey()))
        else:
            print("Error - Key not available to decrypt")

    # receive key
    def keyReceived(self, connectionPort, dataDict):
        digitalSignature = dataDict["digitalSignature"]
        self.getPublicKeyForNewConnection(connectionPort)
        publicKey = dataDict["publicKey"]

        #print("Key received from -", connectionPort, ", digitalSignature -",digitalSignature, ", public key -", publicKey,", signaturePublicKey -", self.currentNewConnectionPublicKey)
        print("for debug " ,decryptor(digitalSignature, self.currentNewConnectionPublicKey),connectionPort)

        if decryptor(digitalSignature, self.currentNewConnectionPublicKey) != connectionPort:
            print("Error - unexpected behaviour")    
            return                       

        if connectionPort in self.connections:
            # connection port in dictionary
            self.connections[connectionPort]["dh"].computeSharedKey(dataDict["publicKey"])
            self.connections[connectionPort]["name"] = dataDict["name"]
            if dataDict["requestKey"]:
                # other needs key
                self.sendKeyToConnection(connectionPort)
        else:            
            # connection port not in dictionary
            # receive new connection
            self.connections[connectionPort] = {"name":dataDict["name"], "dh": DH(self.mySecretKey, dataDict["publicKey"])}
            if dataDict["requestKey"]:
                self.sendKeyToConnection(connectionPort)
            print("Log - new connection",dataDict["name"],"added")

    # thread that receives messages by listening to connection
    def receiveThreadFunction(self):
        while True:
            data, recvAddress = self.sock.recvfrom(4096)
            dataDict = self.binaryToDict(data)
            recvPort = recvAddress[1]
            # routing request appropriatly
            if dataDict["type"]=="message":
                self.messageReceived(recvPort, dataDict)
            if dataDict["type"]=="key":
                self.keyReceived(recvPort, dataDict)

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
        digitalSignature = self.generateDigitalSignature(self.myPort)
        messageDict = {"type": "key", "name": self.myName, "publicKey": self.connections[connectionPort]["dh"].getPublicKey(), "requestKey": requestKey, "digitalSignature":digitalSignature}
        
        for _ in messageDict.keys():
            print(type(messageDict[_]))
        
        self.sock.sendto(self.dictToBinary(messageDict),('localhost',connectionPort))

    # send encrypted message
    def sendMessage(self, connectionPort, message):
        if type(connectionPort) is str:
            for conn in self.connections:
                if self.connections[conn]==connectionPort:
                    connectionPort = conn
                    break
        if self.connections[connectionPort]["dh"].getSharedKey() is None:
            # shared key not available
            print("Error - channel not protected")
        else:
            # shared key available
            encryptedMessage = encrypt(message, self.connections[connectionPort]["dh"].getSharedKey())
            messageDict = {"type": "message","name": self.myName, "message": encryptedMessage}
            self.sock.sendto(self.dictToBinary(messageDict),('localhost',connectionPort))

    # region utility functions
    def generateDigitalSignature(self, connectionPort):
        return encryptor(connectionPort, self.signaturePrivateKey)

    def connectionsStatus(self):
        print("No. of connections -", len(self.connections))
        for conn in self.connections:
            print("    Connection name -",self.connections[conn]["name"], end=", ")
            self.connections[conn]["dh"].toString()
            
    def dictToBinary(self, inputDict):
        tempJSON = pickle.dumps(inputDict)
        return tempJSON
    
    def binaryToDict(self, inputBinary):
        # tempJSON = inputBinary.decode()
        return pickle.loads(inputBinary) 
    # endregion