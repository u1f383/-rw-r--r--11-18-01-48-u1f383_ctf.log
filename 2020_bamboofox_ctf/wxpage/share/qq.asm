section .text

global _start:
    mov rbx, 0x2b2b2b2b2b2b2b2b
    push rbx
    inc al
    mov esi, esp
    syscall
