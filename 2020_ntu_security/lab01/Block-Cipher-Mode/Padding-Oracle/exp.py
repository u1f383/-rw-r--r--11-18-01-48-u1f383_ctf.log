#!/usr/bin/env python3
import os
from Crypto.Cipher import AES
from pwn import *
"""
KEY = os.urandom(16)
IV = os.urandom(16)
FLAG = open('./flag', 'rb').read()
"""
def pad(data):
    p = 16 - len(data) % 16
    return data + bytes([p]) * p

def unpad(data):
    if not all([x == data[-1] for x in data[-data[-1]:]]):
        raise ValueError
    return data[:-data[-1]]

def main():
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    cipher = aes.encrypt(pad(FLAG))
    print(f'flag = {(IV + cipher).hex()}')

    while True:
        cipher = bytes.fromhex(input('cipher = ').strip())
        iv, cipher = cipher[:16], cipher[16:]
        try:
            aes = AES.new(KEY, AES.MODE_CBC, iv)
            plain = unpad(aes.decrypt(cipher))
            print('PADDING CORRECT!!!')
        except ValueError:
            print('PADDING ERROR!!!')


r = remote('127.0.0.1', 20000)

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

def oracle(c):
    r.sendlineafter('cipher = ', c.hex())
    
    if b'ERROR' in r.recvline():
        return False
    else:
        return True

r.recvuntil('flag = ')
enc = bytes.fromhex(r.recvline().replace(b'\n', b'').decode('utf-8'))

flag = b''
for i in range(16, 48, 16):
    iv = enc[i-16:i]
    block = enc[i:i+16]
    print(f"i: {i}, iv: {iv}, block: {block}")
    
    ans = b''
    for j in range(16):
        for k in range(256):
            payload = iv[:15-j]+bytes([k])+xor(bytes([j+1]*j), xor(iv[-j:], ans))+block
            print(payload)
            """
                # 前面的密文 + 第 j+1 個要被 try 的
                iv[:16 - 1 - j] + bytes([k]) +
                # j 個空格都要為 j+1, 這樣才會有 j+1 個 j+1 (padding)
                # 要與明文 xor, 這樣在解密時又與密文做 xor 後才會取的明文
                xor(bytes([j+1]*j), xor(iv[-j:], ans)) +
                block
            """
            if oracle(payload):
                ans = bytes([ (j+1) ^ k ^ iv[15-j] ]) + ans
                print(ans)
                break
    flag += ans
print(flag)
