class DH:
    def __init__(self, secretKey):
        self.sharedPrime = 564
        self.sharedBase = 78
        self.secretKey = secretKey
        self.sharedKey = None

    def getPublicKey(self):
        return (self.sharedBase**self.secretKey)%self.sharedPrime
    
    def computeSharedKey(self, receivedKey):
        self.sharedKey = (receivedKey**self.secretKey)%self.sharedPrime
    
    def getSharedKey(self):
        return self.sharedKey
