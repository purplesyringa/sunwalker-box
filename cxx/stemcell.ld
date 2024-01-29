ENTRY(_start)

SECTIONS {
    .text 0xdeadbeef0000 : {
        start_of_text = .;
        *(.text .text.*)
        start_of_data = .;
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.got .got.*)
        *(.init_array)
        *(.dynbss)
    }
    .result_context_map : {
        *(.result_context_map)
    }
    .bss : {
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(4096);
        end_of_bss = .;
    }
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
