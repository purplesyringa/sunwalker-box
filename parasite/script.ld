ENTRY(_start)

SECTIONS {
    prog : {
        *(.text .text.*)
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    }
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
