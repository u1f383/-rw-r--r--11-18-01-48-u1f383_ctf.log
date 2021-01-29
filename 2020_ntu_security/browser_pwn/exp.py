#!/usr/bin/python3

from pwn import *

r = remote('140.112.31.97', 30108)

src = open('./exp.js', 'r').read()

r.sendlineafter('length : ', str(len(src)))
sleep(0.1)
r.send(src)

r.interactive()
