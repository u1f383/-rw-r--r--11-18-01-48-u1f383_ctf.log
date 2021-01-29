#!/usr/bin/env python3
import os
from Crypto.Cipher import AES
from pwn import *

key = os.urandom(16)
"""
with open('flag', 'rb') as f:
    flag = f.read()
"""
flag = b'CTF{XXXXXXXX}'

class PaddingError(Exception):
    pass

def pad(data):
    padlen = 16 - len(data) % 16
    # 補上 1 + (padlen*8-1) 的 0, 並轉成二進位, 即為 2^(len*8)
    # padlen = 1 ==> 2^7,   1000 0000
    # padlen = 2 ==> 2^15,  1000 0000 0000 0000
    return data + int('1' + '0' * (padlen * 8 - 1), 2).to_bytes(padlen, 'big')

def unpad(data):
    for i in range(len(data) - 1, len(data) - 1 - 16, -1):
        if data[i] == 0x80:
            return data[:i]
        elif data[i] != 0x00:
            raise PaddingError
    raise PaddingError


def xor(a, b):
    return bytes([i^j for i,j in zip(a,b)])

r = remote('140.112.31.97', 30000)
r.recvuntil('cipher = ')
enc = bytes.fromhex(r.recvline().replace(b'\n', b'').decode('utf-8'))
assert len(enc) == 48

def oracle(text):
    r.sendline(text.hex())
    c = r.recvline()
    if b'YES' in c:
        return True
    else:
        return False

flag = b''
#for i in range(32, len(enc), 16):
for i in range(32, len(enc), 16):
    ans = b'\x00\x00\x00\x00\x00\x00\x00\x00' # 第二輪
    #ans = b''
    iv = enc[i-16:i] # e.g. 71e32b962e8eafdd62a9c55a4af44ce5
    block = enc[i:i+16] # e.g 0eb793e55975dca193e8ca93853bb21c
    print(iv.hex(), block.hex()) 
    for j in range(len(ans),16): # 長度為 16 的 ciphertext
        for k in range(256): # 00 ~ ff
            if bytes([k]) == iv[-j]:
                continue
            payload = iv[:15-j] + bytes([k]) # origin[-j] + 替換的
            # e.g. 71e32b962e8eafdd62a9c55a4af44c 00 for j = 0
            payload += xor(xor(ans, iv[-j:]), bytes( [0]*j )) # 讓後面的幾位數與 block xor 為 00
            # xor(ans, iv[-j:]) 會得到密文 (decrypt)
            payload += block
            if oracle(payload):
                ans = bytes([k ^ 0x80 ^ iv[15-j]]) + ans
                print(ans)
                break
    flag += ans

print(flag)
            
"""
71e32b962e8eafdd62a9c55a4af44c e5 ==> 替換成其他的, e.g. 00, 01, ...
如果不是 e5, 則嘗試送 payload 過去確定是否符合標準
使得 dec xor payload 為 0x80
"""
