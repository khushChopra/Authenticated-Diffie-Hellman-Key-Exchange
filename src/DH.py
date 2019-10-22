class DH:
    def __init__(self, secretKey, receivedKey=None):
        self.sharedPrime = 564
        self.sharedBase = 78
        self.secretKey = secretKey
        self.sharedKey = None
        if receivedKey:
            self.computeSharedKey(receivedKey)

    def getPublicKey(self):
        return (self.sharedBase**self.secretKey)%self.sharedPrime
    
    def computeSharedKey(self, receivedKey):
        self.sharedKey = (receivedKey**self.secretKey)%self.sharedPrime
    
    def getSharedKey(self):
        return self.sharedKey

    def toString(self):
        print("secret key -", self.secretKey, ", shared key -", self.sharedKey)