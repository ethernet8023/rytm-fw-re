ENTRY(_start)

/* Analog Rytm MKII MAIN OS replacement
 * Loaded by bootstrap at 0x40000400 (DDR), entry pointer in image word[0].
 */

MEMORY
{
    OS      (rx) : ORIGIN = 0x40000400, LENGTH = 4M   /* decompressed MAIN OS lands here */
    SCRATCH (rw) : ORIGIN = 0x40200000, LENGTH = 32M  /* upper RAM the OS may use */
}

SECTIONS
{
    /* 16-byte image header consumed by the bootstrap:
     *   [0] entry function pointer (bootstrap does: jsr (ptr) with one stack arg)
     *   [4..15] reserved / zero
     */
    .header : ALIGN(4) {
        KEEP(*(.header.entry))
        LONG(0); LONG(0); LONG(0);   /* total: 4 + 12 = 16 bytes */
    } > OS

    .text : ALIGN(4) {
        *(.text .text.*)
        *(.rodata .rodata.*)
        . = ALIGN(4);
    } > OS

    .data : ALIGN(4) {
        __data_start = .;
        *(.data .data.*)
        . = ALIGN(4);
        __data_end = .;
    } > OS

    .init_array : ALIGN(4) {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
    } > OS

    .bss (NOLOAD) : ALIGN(4) {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > OS

    /DISCARD/ : {
        *(.interp)
        *(.dynsym)
        *(.dynstr)
        *(.hash)
        *(.gnu.hash)
        *(.rela.*)
        *(.dynamic)
        *(.got*)
        *(.comment)
        *(.eh_frame*)
        *(.note*)
    }
}
