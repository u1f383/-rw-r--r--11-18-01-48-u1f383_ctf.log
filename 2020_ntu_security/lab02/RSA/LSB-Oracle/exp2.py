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

    p = getPrime(512)
def main():
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
        print(f'm & 1 = {m & 1}')

try:
    main()
except:
    ...
"""

r = remote('localhost', 20000)
n = int(r.recvline()[4:-1])
c = int(r.recvline()[4:-1])
e = 65537

inv = inverse(2, n)
inve = pow(inv, e, n)

m = 0
x = 0
for i in range(1024):
    r.sendline(str(c))
    b = int(r.recvline().split(b' = ')[1])

    bit = (b - x) % 2
    x = inv * (x + bit) % n # previous + current bit

    m += bit * (1 << i)
    c = (c * inve) % n

print(long_to_bytes(m))