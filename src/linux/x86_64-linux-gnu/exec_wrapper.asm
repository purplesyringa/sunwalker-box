; Runs another the executable from argv[1:], copying envp. Designed to use as little physical memory
; possible. On error, returns an exit code equal to errno.

[bits 64]

[global _start]
_start:
	mov eax, 59  ; execve
	lea rsi, [rsp+16]  ; argv <- argv + 1
	mov rdi, [rsi]  ; pathname <- argv[1]
	mov rdx, [rsp]  ; envp <- argv + argc + 1
	lea rdx, [rsi+rdx*8]
	syscall

	mov rdi, rax  ; status
	neg rdi
	mov eax, 60  ; exit
	syscall

	; if, for some reason, exit(2) fails, don't keep going
	hlt
	ud2
	jmp $
