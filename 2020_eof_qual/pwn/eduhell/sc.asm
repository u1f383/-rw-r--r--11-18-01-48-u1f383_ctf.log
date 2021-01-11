section .text
global _start

_start:
mov r15, [rsp+8]
add r15, 0x2f90 ; flag
mov r9, -1
jmp good
nop
compare:
    lea r13, [r14 + 0x100]
    mov rbx, [r13]
    cmp bl, byte [r15+r9]
    je good
bad:
    mov rax, 60
    mov rdi, 0
    syscall
good:
    xor rdi, rdi
    xor rdx, rdx
    xor rax, rax
    lea rsi, [r14+0x100]
    add dx, 0x8
    syscall
    inc r9
    jmp compare
