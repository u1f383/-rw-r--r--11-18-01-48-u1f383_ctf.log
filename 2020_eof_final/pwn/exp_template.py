#!/usr/bin/python3

from pwn import *
import *

HOST = ''
PORT = 0
BIN = './bin'
LIB = './lib'
l = ELF(LIB)
e = ELF(BIN)

if len(sys.argv) > 0:
    r = remote(HOST, PORT)
else:
    r = process(BIN)
    # r = process(BIN, env={"LD_PRELOAD" : LIB})

r.interactive()

