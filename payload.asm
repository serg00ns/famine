BITS 64

call next
next:
	pop rax
	add rax, 0xDEADBEEF
	jmp rax
	db "ialgac|beeligul"
