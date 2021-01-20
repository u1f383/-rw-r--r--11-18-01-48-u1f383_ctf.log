#!/usr/bin/python3

from pwn import *

r = process("./stdout_test")

a = r.recvline()
b = r.recvline()
print(a, b)

r.interactive()
