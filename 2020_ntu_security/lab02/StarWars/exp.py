#!/usr/bin/python3
from Crypto.Util.number import *
from pwn import *

r = remote('localhost', 20000)

def pollard(n):
    a, b = 2, 2
    while True:
        a = pow(a, b, n) # a*b mod n
        d = GCD(a-1, n) # a-1 與 n 的最大公因數
        if 1 < d < n:
            return d
        
        b += 1

r.sendlineafter('> ', '1')
exec(r.recvline())
exec(r.recvline())
exec(r.recvline())

p = pollard(n)
q = n // p
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)

print(long_to_bytes(m))
