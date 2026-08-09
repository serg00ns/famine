BITS 64

call next
next:
    pop rax
mov rbx, 0xDEADBEEFDEADBEEF
    add rax, rbx
    jmp rax    
    db "FAMPKNT1"
