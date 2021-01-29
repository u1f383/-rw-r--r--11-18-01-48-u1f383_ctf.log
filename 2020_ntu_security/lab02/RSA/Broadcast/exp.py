#!/usr/bin/env python3
import random
import gmpy2
import functools
from Crypto.Util.number import *

def pad(data, block_size):
    padlen = block_size - len(data) - 2
    if padlen < 8:
        raise ValueError
    return b'\x00' + bytes([random.randint(1, 255) for _ in range(padlen)]) + b'\x00' + data
"""
FLAG = open('./flag', 'rb').read()

m = bytes_to_long(pad(FLAG, 128))
e = 3
for i in range(3):
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    c = pow(m, e, n)
    print(f'n{i} = {n}')
    print(f'c{i} = {c}')
"""
exec(open('output.txt', 'r').read()) # get n0,n1,n2 and c0,c1,c2
"""
m^3 === c0 mod n0
m^3 === c1 mod n1
m^3 === c2 mod n2

"""
def CRT(c, n):
    M = functools.reduce(lambda x,y: x*y, n)
    total = 0
    for ci,ni in zip(c,n):
        Mi = M // ni
        # gmpy2.gcdext(Mi, ni) == (result, a, b)
        total += (gmpy2.gcdext(Mi, ni)[1] % ni) * Mi * ci
    return total % M

m, _ = gmpy2.iroot((CRT([c0, c1, c2], [n0, n1, n2])), 3)

print(long_to_bytes(m))
