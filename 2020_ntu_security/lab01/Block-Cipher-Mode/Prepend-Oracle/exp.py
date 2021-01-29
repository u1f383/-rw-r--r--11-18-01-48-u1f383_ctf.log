#!/usr/bin/env python3
import os
import binascii
import string
from Crypto.Cipher import AES
from pwn import *

#KEY = os.urandom(16)
#FLAG = open('./flag', 'rb').read()

r = remote('127.0.0.1', 20001)

def pad(m):
    padlen = -len(m) % 16
    print(padlen)
    return m + bytes([0] * padlen)

def main():
    aes = AES.new(KEY, AES.MODE_ECB)
    
    while True:
        message = bytes.fromhex(input('message = ').strip())
        cipher = aes.encrypt(pad(message + FLAG))
        print(f'cipher = {cipher.hex()}')

def get_enc(text):
    r.sendline(text)
    r.recvuntil('cipher = ')
    return r.recvline().replace(b'\n', b'')


"""
aa => len 1 + padding 12 % 16 => flag len == 16*0+3 (3) or 16*1+3 (19)
"""

wordlist = string.printable[:-6]
flag = b''
for i in range(19):
    padding = (b'A'*(31-i)).hex()
    enc = get_enc(padding)
    for j in wordlist:
        c = binascii.hexlify(j.encode('utf-8'))
        if get_enc(padding.encode('utf-8') + flag.hex().encode('utf-8') + c)[32:64] == enc[32:64]:
            flag += chr(int(c, 16)).encode('utf-8')
            break
    print(flag)
