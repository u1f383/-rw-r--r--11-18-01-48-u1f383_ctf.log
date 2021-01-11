#!/usr/bin/python3

from pwn import *
import sys

HOST = 'eofqual.zoolab.org'
PORT = 0
BIN = ''
LIBC = './libc-2..so'

e = ELF(BIN)
l = ELF(LIBC)

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BIN, env={"LD_PRELOAD": LIBC})

def ch(i):
    r.sendafter('Choice', str(i))

def add(size, data):
    ch(1)
    r.sendafter("size : ", str(size))
    r.sendafter("Content : ", data)
 
def edit(idx, data):
    ch(2)
    r.sendafter("index : ", str(idx))
    r.sendafter("Content : ", data)
 
def delete(idx):
    ch(3)
    r.sendafter("index : ", str(idx))
 
def show(idx):
    ch(4)
    r.sendafter("index : ", str(idx))

r.interactive()
