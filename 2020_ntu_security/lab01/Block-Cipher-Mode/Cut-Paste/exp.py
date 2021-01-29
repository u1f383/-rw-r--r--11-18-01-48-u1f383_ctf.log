#!/usr/bin/env python3
import os
from Crypto.Cipher import AES

KEY = os.urandom(16)
FLAG = open('./flag').read()

def pad(m):
    padlen = -len(m) % 16
    return m + bytes([0] * padlen)

def main():
    aes = AES.new(KEY, AES.MODE_ECB)
    
    # encrypt token
    user = input('user = ').strip()
    user = 'AAAAAAAAAAA6666666666666666AAAAAAA'
    if ':;' in user:
        raise ValueError
    token = f'user:{user};money:10;'.encode()
    print(f'token = {pad(token)}')
    token = aes.encrypt(pad(token))
    print(f'pad_token = {token}\n')
    print(f'token = {token.hex()}')

    # exploit
    exp_token = token[:16]+token[32:48]+token[16:32]+token[48:]
    print("exploit token:   ", exp_token.hex())
    # decrypt token
    token = bytes.fromhex(exp_token.hex())
    token = aes.decrypt(token)
    print(token)
    user, money, _ = token.split(b';')
    if int(money.split(b':')[1]) > 666666:
        print(FLAG)
    else:
        print('SHOW ME THE MONEY!!!')
main()


"""
if user = a
user:a;money:10; // len 16

user:AAAAAAAAAAA 6666666666666666 AAAAAAA;money:10 ;
user:AAAAAAAAAAA AAAAAAA;money:10 6666666666666666 ;
len = 64
"""
