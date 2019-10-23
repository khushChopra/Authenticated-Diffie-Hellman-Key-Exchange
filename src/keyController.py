#Importing necessary modules
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
import base64

# int to serializable using serialized keys
def encryptor(message, key):
    key = RSA.import_key(key)
    cipher = PKCS1_OAEP.new(key=key)
    cipher_text = cipher.encrypt(str(message).encode())
    return base64.encodebytes(cipher_text)

# serializable to int using serialized keys
def decryptor(message, key):
    key = RSA.import_key(key)
    decryptObj = PKCS1_OAEP.new(key=key)
    # print(message)
    # message = message[2:][:-1]
    # print(message)
    decrypted_message = decryptObj.decrypt(message.decode('ascii'))
    return int(decrypted_message.decode())    

# serializable keys
def getKeys():
    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()
    privateKey = privateKey.export_key().decode()
    publicKey = publicKey.export_key().decode()
    return (privateKey, publicKey)