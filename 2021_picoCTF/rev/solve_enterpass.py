#!/usr/bin/python3

from pwn import *
import sys

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 48728)
else:
    r = process('./enter_password')

r.sendline('reverseengineericanbarelyforward')
input()
r.sendline('goldfish')

r.interactive()
