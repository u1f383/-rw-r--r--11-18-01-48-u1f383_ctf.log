#!/usr/bin/env python3
import random
from Crypto.Util.number import *
import gmpy2

"""
def pad(data, block_size):
    padlen = block_size - len(data) - 2
    if padlen < 8:
        raise ValueError
    return b'\x00' + bytes([random.randint(1, 255) for _ in range(padlen)]) + b'\x00' + data

FLAG = open('./flag', 'rb').read()

p = getPrime(512)
q1 = next_prime(2 * p)
q2 = next_prime(3 * q1)

n = p * q1 * q2
e = 65537

m = bytes_to_long(pad(FLAG, 192))
c = pow(m, e, n)
print(f'n = {n}')
print(f'c = {c}')
"""

def prev_prime(a):
    a -= 1
    while True:
        if not isPrime(a):
            a -= 1
        else:
            break
    
    return a

exec(open('output.txt', 'r').read()) # get n,c

e = 65537
p, _ = gmpy2.iroot(n // 12, 3)
q1 = gmpy2.next_prime(2 * p)
q2 = gmpy2.next_prime(3 * q1)

while n % (p*q1*q2) != 0:
    p = prev_prime(p)
    q1 = gmpy2.next_prime(2 * p)
    q2 = gmpy2.next_prime(3 * q1)
    
print(p, q1, q2)
d = inverse(e, (p-1)*(q1-1)*(q2-1))
m = pow(c, d, n)

print(long_to_bytes(m))
