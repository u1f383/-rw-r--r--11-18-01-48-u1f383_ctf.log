#!/usr/bin/python3

from pwn import *

r = process('./test')

r.send(p64(0xdeadbeefdeadbeef))
input()
