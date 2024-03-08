ENTRY(_start)

PHDRS {
    text PT_LOAD FILEHDR PHDRS;
}

SECTIONS {
    . = 0x40000 + SIZEOF_HEADERS;
    .text : {
        *(.text .text.*)
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.got .got.*)
        *(.init_array)
        *(.dynbss)
    } :text
    .bss : {
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    } :text
    /DISCARD/ : {
        *(.dynsym .dynstr .gnu.hash .note.* .dynamic .comment)
    }
}
