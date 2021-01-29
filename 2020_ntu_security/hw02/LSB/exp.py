#!/usr/bin/env python3
import random
from Crypto.Util.number import *
from pwn import *
"""
FLAG = open('./flag', 'rb').read()

def pad(data, block_size):
    padlen = block_size - len(data) - 2
    if padlen < 8:
        raise ValueError
    return b'\x00' + bytes([random.randint(1, 255) for _ in range(padlen)]) + b'\x00' + data

def main():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 65537
    d = inverse(e, (p - 1) * (q - 1))

    m = bytes_to_long(pad(FLAG, 128))
    c = pow(m, e, n)
    print(f'n = {n}')
    print(f'c = {c}')

    while True:
        c = int(input())
        m = pow(c, d, n)
        print(f'm % 3 = {m % 3}')

try:
    main()
except:
    ...
"""
r = remote('140.112.31.97', 30001)
n = int(r.recvline()[4:-1])
c = int(r.recvline()[4:-1])
e = 65537

inv = inverse(3, n) # 3^-1
inv3_e = pow(inv, e, n) # 3^-e

x = 0
m = 0
for i in range(2000):
    r.sendline(str(c))
    b = int(r.recvline()[8:-1])

    bit = (b - x) % 3
    x = (x + bit) * inv % n

    m += bit * pow(3, i)
    c = (c * inv3_e) % n

print(long_to_bytes(m))