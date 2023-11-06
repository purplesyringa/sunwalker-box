.intel_syntax noprefix
.section .entry
.globl _checkpoint, _start
_checkpoint:
    lea rsp, [rip + STACK + 32 * 4096 - 0x100]
    mov rdi, rsp
    call checkpoint
    mov rdi, rsp
    jmp go
_start:
    lea rsp, [rip + STACK + 32 * 4096 - 0x100]
    mov rdi, rsp
    call start
    mov rdi, rsp
    jmp go
