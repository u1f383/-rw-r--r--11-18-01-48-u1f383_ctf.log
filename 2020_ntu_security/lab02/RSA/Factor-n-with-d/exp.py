#!/usr/bin/env python
import random
import math
from Crypto.Util.number import *

"""
def pad(data, block_size):
    padlen = block_size - len(data) - 2
    if padlen < 8:
        raise ValueError
    return b'\x00' + bytes([random.randint(1, 255) for _ in range(padlen)]) + b'\x00' + data

p = getPrime(512)
q = getPrime(512)
n = p * q

e1 = 257
d1 = inverse(e1, (p - 1) * (q - 1))
print(f'n = {n}')
print(f'd1 = {d1}')

e2 = 65537
m = bytes_to_long(pad(FLAG, 128))
c = pow(m, e2, n)
print(f'c = {c}')
"""

def f(n, e, d):
    g = random.randint(1, n-1)
    k = e*d-1 # phi(n)
    
    while True:
        if k % 2 == 1: # change new int
            break

        k //= 2
        x = pow(g, k, n) # g^k mod n
        if x > 1 and 1 < GCD(n, x-1) < n: # x and -x 都是root, 看有沒有在 1~n 之間
            print(x)
            return GCD(n, x-1)

e1 = 257
e2 = 65537
exec(open('output.txt', 'r').read())

p = f(n, e1, d1)
q = n // p
d2 = inverse(e2, (q-1)*(p-1))
m = pow(c, d2, n)
#print(long_to_bytes(m))
