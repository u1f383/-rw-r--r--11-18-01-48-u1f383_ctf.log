all: sc 
sc: sc.asm
	nasm -f elf64 -o sc.o sc.asm
	ld -o sc sc.o
