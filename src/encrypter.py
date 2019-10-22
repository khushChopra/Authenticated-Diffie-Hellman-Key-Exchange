def encrypt(input, key):
    res = ""
    for a in input:
        res += chr((ord(a)+key)%128)
    return res

def decrypt(input, key):
    res = ""
    for a in input:
        res += chr(((ord(a)-key)%128+128)%128)
    return res