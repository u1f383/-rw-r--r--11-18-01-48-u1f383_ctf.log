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
n = int(r.recvline()[4:-1].decode('utf-8'))
c = int(r.recvline()[4:-1].decode('utf-8'))

e = 65537
_2e = pow(2, e, n)

# 分子, 起始為 0/1 ~ 1/1
L, R = 0, 1
for i in range(1024): # 每過一輪, 分母自動 << 1
    c = (c * _2e) % n
    r.sendline(str(c))
    m = r.recvline()[-2]

    # 分母 << 1, 分子也 << 1
    L *= 2
    R *= 2

    if m == ord('0'): # 若為 0, 則在左邊區間
        R -= 1
    else: # 右邊區間
        L += 1
    
    print(R, L)
    
print(long_to_bytes(L * n // (1 << 1024))) # 
print(long_to_bytes(R * n // (1 << 1024))) # 



### 沒考慮到中間沒整除的情況
# while start < end:
#     c = (c * _2e) % n # c * 2^e
#     r.sendline(str(c))
#     b = r.recvline()[-2]
#     mid = (start + end) // 2
    
#     if b == ord('0'):
#         end = mid
#     else:
#         start = mid
#     print(start - end)
#     print(long_to_bytes(start))
