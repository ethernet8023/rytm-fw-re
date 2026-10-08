/* main.cpp - Analog Rytm MKII replacement OS, first light.
 *
 * Reached from crt0 with vectors installed at 0x40000000 (VBR set), .bss
 * zeroed, on our own stack. Bring-up order mirrors the stock OS.
 */

extern "C" {
    void hal_entry_pokes();
    void hal_intc_gpio_init();
    void hal_cache_enable();
    void display_channel_init();
    void display_flush(const unsigned char *plane);
    void display_px(unsigned char *plane, int x, int y, int on);
}

/* 1024 B display plane, .bss (DDR @0x40000000+) */
static unsigned char plane[1024];

extern "C" void main()
{
    hal_entry_pokes();      /* stock does these before anything else */
    hal_intc_gpio_init();   /* INTC + GPIO defaults, callback slots */
    hal_cache_enable();     /* CACR + ITT0, same values as stock */

    display_channel_init(); /* ec07 FPGA fifo bridge, verbatim stock pokes */

    /* test pattern: checkerboard of 8x8 tiles + border (fills the whole
     * panel so a working flush is obvious) */
    for (int y = 0; y < 64; y++)
        for (int x = 0; x < 128; x++) {
            int on = ((x >> 3) ^ (y >> 3)) & 1;
            if (x < 2 || x > 125 || y < 2 || y > 61)
                on = 1; /* border */
            display_px(plane, x, y, on);
        }

    display_flush(plane);

    /* done: park with interrupts off, pattern stays on the panel */
    asm volatile(
        "move.w #0x2700, %%sr\n"
        "1: stop #0x2700\n"
        "   jra 1b\n"
        : : : "memory");
    __builtin_unreachable();
}
