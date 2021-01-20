#!/usr/bin/python3

from pwn import *
import sys

HOST = ''
PORT = 0
BIN = './'

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN)



r.interactive()
