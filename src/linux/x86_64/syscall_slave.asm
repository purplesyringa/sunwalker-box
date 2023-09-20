; Minimal ELF: we don't want it to *do* anything, just provide a way to execute one mmap syscall

[bits 64]

[global _start]
_start:
	syscall
	hlt
