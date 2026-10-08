/* hal.cpp - hardware bring-up RE'd from stock OS 1.74.
 *
 * Each poke is copied verbatim from the stock MAIN OS so the SoC ends up in
 * the same state the real firmware puts it in before starting the kernel.
 * Sources (stock addresses) noted per block.
 */

using u8  = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;

#define REG8(x)  (*(volatile u8 *)(x))
#define REG16(x) (*(volatile u16 *)(x))
#define REG32(x) (*(volatile u32 *)(x))

/* ---- entry pokes (stock entry fn @0x40000870) ----
 * GPIO/PIN mux + clock gating-ish writes done before anything else.
 */
extern "C" void hal_entry_pokes()
{
    /* stock: lea 0xfc04002d,%a0; move.b #17..#20,#32,#36,(a0) chain */
    REG8(0xfc04002d) = 0x11;
    REG8(0xfc04002f) = 0x25;
    REG8(0xfc04002d) = 0x12;
    REG8(0xfc04002d) = 0x13;
    REG8(0xfc04002d) = 0x14;
    REG8(0xfc04002d) = 0x20;
    REG8(0xfc04002d) = 0x24;

    /* stock: lea 0xec09000e,%a0; bclr #11,(a0) */
    REG16(0xec09000e) &= ~(1u << 11);
}

/* ---- INTC / GPIO init (stock fn_690 @0x40000690) ---- */
extern "C" void hal_intc_gpio_init()
{
    REG8(0xec09404d) |= 0x0c;          /* stock: or.b #12,(a0) @0xec09404d */
    REG32(0x413d83c0) = 0;              /* stock: clr.l 0x413d83c0 / 83c4 (callback slots) */
    REG32(0x413d83c4) = 0;

    REG16(0xfc090000) |= 0x30;         /* stock: or.w #0x30,(a0) @0xfc090000 */
    REG8(0xfc090003)  |= 0x04;         /* stock: or.b #4,(a0) @0xfc090003 */
    REG8(0xec094056)   = 0;            /* stock: clr.b 0xec094056 */
    REG8(0xec09401e)   = 2;            /* stock: move.b #2,0xec09401e */
    REG8(0xec094012)  |= 0x02;         /* stock: or.b #2,(a0) then #6 (below) */

    REG32(0x40000374) = 0x4000045c;    /* stock: ISR fn ptr installs */
    REG32(0x40000378) = 0x40000486;
    REG8(0xfc05005d)  = 2;
    REG8(0xfc05005e)  = 5;
    REG8(0xfc05001d)  = 0x1d;          /* stock: move.b #29,(a0) */
    REG8(0xec094012)  |= 0x06;         /* stock: or.b #6,(a0) */
}

/* ---- cache config (stock entry) ---- */
extern "C" void hal_cache_enable()
{
    /* stock: move.l #0xa50ce100,%d0; movec %d0,%cacr */
    asm volatile("movec %0, %%cacr" :: "d"(0xa50ce100));
    /* stock: move.l #0x4007e020,%d0; movec %d0,%itt0 */
    asm volatile("movec %0, %%itt0" :: "d"(0x4007e020));
}
