ENTRY(_start)

PHDRS {
    text PT_LOAD FILEHDR PHDRS;
}

SECTIONS {
    . = 0xdeadbeef0000;
    start_of_text = .;
    . += SIZEOF_HEADERS;
    .text : {
        *(.text .text.*)
        start_of_data = .;
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.got .got.*)
        *(.init_array)
        *(.dynbss)
    } :text
    .result_context_map : {
        *(.result_context_map)
    } :text
    .bss : {
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(4096);
        end_of_bss = .;
    } :text
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
