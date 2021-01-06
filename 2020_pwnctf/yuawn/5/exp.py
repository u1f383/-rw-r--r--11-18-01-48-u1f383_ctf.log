#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './memo_manager'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2115

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

#r.sendline('cat /home/`whoami`/flag')
r.interactive()
