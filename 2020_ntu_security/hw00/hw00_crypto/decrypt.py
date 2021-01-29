#!/usr/bin/env python3
import string
import time
import datetime
import random
from typing import List
from io import BufferedReader

def convert(data: bytes, size=4): # 把 data 分成 size=4 的 block, element is int
    return [int.from_bytes(data[idx:idx+size], 'big') for idx in range(0, len(data), size)] #

def invert(data, size=4): # hex 轉成 bytes
    return b''.join([element.to_bytes(size, 'big') for element in data])

def _encrypt(v: List[int], k: List[int]):
    total, delta, mask = 0, 0xFACEB00C, 0xffffffff
    for _ in range(32):
        total = total + delta & mask # restrict number in 2^32-1
        v[0] = v[0] + (    (v[1] << 4) + k[0] & mask ^ (v[1] + total) & mask ^ (v[1] >> 5) + k[1] & mask     ) & mask
        v[1] = v[1] + ((v[0] << 4) + k[2] & mask ^ (v[0] + total) & mask ^ (v[0] >> 5) + k[3] & mask) & mask
        print(total)
    return v # List[int], element is int

def encrypt(flag: bytes, key: bytes):
    d_content = b''
    """
    flag 分成前後 8 個 byte,
    將當前的 part 轉成 2 個 block [4, 4], 以及 key 轉成 [4, 4, 4, 4]
    """
    for idx in range(0, len(flag), 8): # twiced
        a = convert( flag[idx:idx+8] )
        b = convert(key)
        c = _encrypt(a, b)
        d = invert(c)

        d_content += d
    return d_content

if __name__ != '__main__':
    flag = b'aaaaaaaaaaaaaaaa'
    assert len(flag) == 16 # len(flag) is 16
    random.seed(int(time.time()))

    key = random.getrandbits(128).to_bytes(16, 'big')

    d_content = encrypt(flag, key) # return bytes
    
    print(f'd_content = {d_content.hex()}')
    exit(1)

""" payload start """

def _decrypt(v: List[int], k: List[int]):
    total, delta, mask = 0x59d60180, 0xFACEB00C, 0xffffffff
    for _ in range(32):
        v[1] = v[1] -    ((v[0] << 4) + k[2] & mask ^ (v[0] + total) & mask ^ (v[0] >> 5) + k[3] & mask)    & mask
        v[0] = v[0] -    ((v[1] << 4) + k[0] & mask ^ (v[1] + total) & mask ^ (v[1] >> 5) + k[1] & mask)    & mask
        total = total - delta & mask # restrict number in 2^32-1
    return v # a

def decrypt(d_content: bytes):
    key = random.getrandbits(128).to_bytes(16, 'big')
    d1 = d_content[:8]
    c1 = convert(d1)
    d2 = d_content[8:16]
    c2 = convert(d2)
    b = convert(key)

    f1 = _decrypt(c1, b)
    f2 = _decrypt(c2, b)

    return invert(f1)+invert(f2)

d_content = bytes.fromhex('77f905c39e36b5eb0deecbb4eb08e8cb')
start = datetime.datetime(2020,9,13).timestamp() - 1000
i = start
with open('output', 'wb') as f:
    while i:
        random.seed(int(i))
        flag = decrypt(d_content)
        if b'flag' in flag or b'FLAG' in flag:
            print(flag)
        i += 1