#!/usr/bin/python3

from pwn import *
import os


while True:
    r = process('./login')
    r.recvline()
    r.send('\n')
    a = r.recvline()
    print(a)
    r.close()

r.interactive()

