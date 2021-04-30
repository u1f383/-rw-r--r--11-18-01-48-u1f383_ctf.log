#!/usr/bin/python3

from pwn import *

l = ELF('./libc-2.31.so')
r = process('./carpal_tunnel_syndrome')

info(f"""
root: 0x5130
marker: 0x5140
text: 0x5020
""")

r.interactive()
