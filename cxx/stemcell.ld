ENTRY(_start)

SECTIONS {
    .text 0xdeadbeef000 : {
        start_of_text = .;
        *(.text .text.*)
        start_of_data = .;
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.dynbss)
    }
    .result_context_map : {
        *(.result_context_map)
    }
    .bss : {
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    }
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
