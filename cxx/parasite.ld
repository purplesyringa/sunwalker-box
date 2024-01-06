ENTRY(_start)

SECTIONS {
    .text : {
        *(.entry)
        *(.text .text.*)
        start_of_data = .;
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    }
    .result_context_map : {
        *(.result_context_map)
    }
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
