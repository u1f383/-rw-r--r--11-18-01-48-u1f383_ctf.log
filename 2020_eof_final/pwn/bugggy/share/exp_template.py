#!/usr/bin/python3

from pwn import *
import *

HOST = 'eof01.zoolab.org'
PORT = 3517
BIN = './bugggy'
e = ELF(BIN)

if len(sys.argv) > 0:
    r = remote(HOST, PORT)
else:
    r = process(BIN)
    # r = process(BIN, env={"LD_PRELOAD" : LIB})

r.interactive()

