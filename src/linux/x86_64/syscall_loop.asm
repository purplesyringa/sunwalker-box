[bits 64]

; Runs a syscall in a loop
_start:
	syscall
	jmp _start
