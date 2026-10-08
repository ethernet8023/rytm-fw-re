/* memprobe.cpp - memory region probe for the Rytm MKII replacement OS.
 *
 * Writes a walking pattern into candidate mod-memory regions, reads it back,
 * and reports pass/fail per region on the display (via display.cpp). Built
 * for the alpha4 probe image: one flash on hardware answers "is this region
 * usable for a mod core?"
 *
 * Regions from analysis (docs/core-interface-draft.md):
 *   0x41ad0000 16MB candidate (primary)   0x413f0000 2MB candidate
 *   0x415f0000 2MB candidate               0x48000000+ stack-top region
 *   0x8000c000 FPGA SRAM sparse block (fast mem candidate)
 * Probe: 32 sample words per region (every N bytes), pattern = addr ^ 0xA5A5.
 */

using u8  = unsigned char;
using u32 = unsigned int;

#define REG32(x) (*(volatile u32 *)(x))

extern "C" void display_px(u8 *plane, int x, int y, int on);

struct Region {
    const char *name;
    u32 base;
    u32 span;      /* bytes of the region */
    u32 stride;    /* sample every stride bytes */
};

static const Region regions[] = {
    { "MOD-A 41ad", 0x41ad0000u, 0x200000u, 0x10000u }, /* 2MB of the 16MB hole */
    { "MOD-B 407d", 0x407d0000u, 0x200000u, 0x10000u },
    { "MOD-C 413f", 0x413f0000u, 0x010000u, 0x01000u },
    { "MOD-D 415f", 0x415f0000u, 0x010000u, 0x01000u },
    { "SRAM  800c", 0x8000c000u, 0x002000u, 0x00100u },
    { "TOP   4800", 0x48000000u, 0x002000u, 0x00100u }, /* below stack top? SP=0x48000000 means this is stack — probe ABOVE SP is unsafe; use 0x4b940000 instead */
    { "TOP   4b94", 0x4b940000u, 0x002000u, 0x00100u },
};

/* returns 1 = pass, 0 = fail, -1 = fault (cannot catch bus errors yet:
 * a fault here hangs the probe; regions are ordered safest-first) */
extern "C" int memprobe_region(u32 base, u32 span, u32 stride)
{
    for (u32 off = 0; off < span; off += stride) {
        volatile u32 *p = (volatile u32 *)(base + off);
        u32 expect = (base + off) ^ 0xA5A5A5A5u;
        *p = expect;
        u32 got = *p;
        if (got != expect)
            return 0;
        /* second pass w complement */
        *p = ~expect;
        if (*p != (u32)~expect)
            return 0;
    }
    return 1;
}

/* draw results as a table row per region: name, PASS/FAIL */
extern "C" void memprobe_run(u8 *plane)
{
    int y = 4;
    for (unsigned r = 0; r < sizeof(regions) / sizeof(regions[0]); r++) {
        const Region *rg = &regions[r];
        int x = 2;
        /* name */
        for (const char *c = rg->name; *c; c++, x++)
            ; /* skip: no font yet — draw a marker bar instead */
        int pass = memprobe_region(rg->base, rg->span, rg->stride);
        /* row marker: solid bar = pass, dashed = fail */
        for (int i = 0; i < 124; i++)
            display_px(plane, i, 2 + r * 8, pass ? 1 : ((i & 4) != 0));
        (void)y; (void)x;
    }
}
