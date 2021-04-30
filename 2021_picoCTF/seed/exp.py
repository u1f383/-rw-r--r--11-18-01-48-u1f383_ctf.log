#!/usr/bin/python3

from pwn import *
import sys
import subprocess

BIN = './seed_spring'

if len(sys.argv) > 1:
    r = remote('jupiter.challenges.picoctf.org', 8311)
else:
    r = process(BIN)

p = subprocess.Popen(['./test'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

outs, errs = p.communicate()

outs = outs.decode().split(' ')[:-1]
print(outs)

for out in outs:
    r.sendlineafter('Guess the height: ', out)

r.interactive()
