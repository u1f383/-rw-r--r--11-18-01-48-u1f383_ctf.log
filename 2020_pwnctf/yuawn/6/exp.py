#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './pwntools'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2116

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

i = 1000
magic = 0x79487FF
r.send(p32(magic))
r.recvuntil('yourself.\n')

while i:
    op = r.recvuntil('?').decode()
    exec('result = ' + op[:-3])
    r.sendline(str(result))
    i -= 1

r.sendline('cat /home/`whoami`/flag')
r.interactive()
