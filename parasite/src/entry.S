.intel_syntax noprefix
.section .entry
.globl _checkpoint, _start
_checkpoint:
    lea rsp, [rip + STACK + 40960]
    lea rdi, [rip + checkpoint]
    jmp go
_start:
    lea rsp, [rip + STACK + 40960]
    lea rdi, [rip + start]
    jmp go
