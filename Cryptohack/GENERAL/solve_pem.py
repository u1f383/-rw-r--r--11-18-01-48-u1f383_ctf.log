#!/usr/bin/python3

from Crypto.PublicKey import RSA

data = open('pem.pem', 'r').read()
key = RSA.importKey(data)

#print(key.n)
#print(key.e)
print(key.d)
