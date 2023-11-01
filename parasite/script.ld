ENTRY(_start)

SECTIONS {
    prog : {
        KEEP(*(.entry))
        *(.text .text.*)
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(4096);
    }
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
