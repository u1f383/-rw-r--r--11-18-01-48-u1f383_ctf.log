#!/usr/bin/env python3
import random
from Crypto.Util.number import *

"""
def pad(data, block_size):
    padlen = block_size - len(data) - 2
    if padlen < 8:
        raise ValueError
    return b'\x00' + bytes([random.randint(1, 255) for _ in range(padlen)]) + b'\x00' + data

FLAG = open('./flag', 'rb').read()

p = getPrime(512)
q = getPrime(512)
n = p * q
e1 = 257
e2 = 65537

m = bytes_to_long(pad(FLAG, 128))
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
print(f'n = {n}')
print(f'c1 = {c1}')
print(f'c2 = {c2}')
"""

def ext_gcd(a, b):
    s0, t1 = 1, 1
    s1, t0 = 0, 0

    while b:
        q = a // b
        s0, s1 = s1, s0 - q*s1
        t0, t1 = t1, t0 - q*t1
        a, b = b, a%b

    return s0, t0, a

exec(open('output.txt', 'r').read()) # get n,c1,c2
e1 = 257
e2 = 65537
s1, s2, r = ext_gcd(e1, e2)

m = ( pow(c1,s1,n) * pow(c2,s2,n) ) % n
print(long_to_bytes(m))