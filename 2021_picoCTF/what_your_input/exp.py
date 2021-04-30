#!/usr/bin/python3

from pwn import *
import sys

r = remote('mercury.picoctf.net', 39137)


r.interactive()
