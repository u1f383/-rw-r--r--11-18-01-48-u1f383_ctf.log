all: sc

sc: shellcode.asm
	nasm -f elf64 -o shellcode.o shellcode.asm
	ld -o shellcode shellcode.o
