#!/usr/bin/env python
import random
import gmpy2
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

d = None
while d is None or gcd(d, (p - 1) * (q - 1)) != 1:
    d = random.randint(1, int((1 / 3) * n ** (1 / 4)))
e = inverse(d, (p - 1) * (q - 1))

m = bytes_to_long(pad(FLAG, 128))
c = pow(m, e, n)
print(f'n = {n}')
print(f'e = {e}')
print(f'c = {c}')
"""

def continued_fraction_expansion(e, n): # 連分數
    q, r = e // n, e % n
    result = [q]

    while r:
        e, n = n, r
        q, r = e // n, e % n
        result.append(q)

    return result

def convergents(e): # 收斂
    k, d = [], []
    for i in range(len(e)):
        if i == 0:
            ki, di = e[i], 1
        elif i == 1:
            ki, di = e[i] * e[i-1] + 1, e[i]
        else:
            ki, di = e[i] * k[i-1] + k[i-2], e[i] * d[i-1] + d[i-2]
        
        k.append(ki)
        d.append(di)
        yield (ki, di)

def solve_expression(a, b, c):
    # ax^2 + bx + c = 0
    k = b*b - 4*a*c
    if k < 0:
        return []
    
    sk, complete = gmpy2.iroot(k, 2) # 看可不可以拿到開方根
    if not complete:
        return []
    
    return [int( (-b+sk)//2*a ), int( (-b-sk)//2*a )]

# 使用時機: d < (1/3)*(N^1/4)
def wiener(n, e):
    kd = convergents(continued_fraction_expansion(e, n))
    for i, (k, d) in enumerate(kd):
        print(i, k, d)
        if k == 0: # 0, 0, 1
            continue
        
        phi = (e*d - 1) // k
        a = 1
        b = phi-n-1
        c = n
        roots = solve_expression(a, b, c)
        
        if roots:
            p, q = roots
            if p * q == n:
                return p, q

exec(open('output.txt', 'r').read()) # get n,e,c

p, q = wiener(n, e)
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)
print(long_to_bytes(m))