/* display.cpp - Rytm MKII panel driver, ported from stock OS 1.74.
 *
 * Stock pipeline (see analysis/output/display_flush.txt):
 *   channel init  FUN_40001c16 @0x40001c16 (FPGA fifo bridge ec07, divisor calc)
 *   polled byte   FUN_40121b08 @0x40121b08 (poll ec070004 bit2, write ec07000c)
 *   tile write    FUN_40095990 @0x40095990 (cmd row, cmd col, 8 data bytes)
 *   frame commit  FUN_40095978 @0x40095978 (cmd 0xb8)
 *   full flush    FUN_40095afa @0x40095afa (16x8 tiles then commit)
 *
 * We are single-threaded polled: no mutex/DMA ring yet, so writes go directly
 * to the fifo data register exactly like stock's polled fallback writer.
 *
 * Plane layout (from bitmap ctor FUN_4006f9b2 + blit FUN_400716e0):
 *   128 cols x 64 rows, 2 u32 per column per plane = 1024 B.
 *   plane[c*8 + y/8] bit (7 - y%8) = pixel (x=c, y)   (MSB = top)
 * Tile gather (from diff flush FUN_40095a5e):
 *   tile(col_t, row) payload byte k = plane[(col_t*8 + k)*8 + row]
 *   i.e. 8 consecutive display columns, 8 pixel rows starting at row*8.
 */

using u8  = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;

#define REG8(x)  (*(volatile u8 *)(x))
#define REG32(x) (*(volatile u32 *)(x))

/* FPGA display fifo bridge registers (0xec070xxx block) */
static volatile u8 &EC07_STATUS = REG8(0xec070004);  /* bit2 = tx ready */
static volatile u8 &EC07_DATA    = REG8(0xec07000c);  /* tx byte */

/* ---- polled fifo byte (stock FUN_40121b08) ---- */
static void ec07_putc(u8 b)
{
    while ((EC07_STATUS & 0x4) == 0)
        ;
    EC07_DATA = b;
}

/* ---- channel init (stock FUN_40001c16, polled subset) ----
 * DMA descriptors omitted: we drive the fifo from the CPU, no ring needed.
 */
extern "C" void display_channel_init()
{
    REG8(0xec09404b) = (u8)((REG8(0xec09404b) & 0x0f) | 0xa0); /* codec/pinmux */
    REG8(0xfc04002f) = 0x1c;                                   /* pinmux */
    REG8(0xec070014) = 3;
    REG8(0xec070004) = 0xdd;   /* bridge cmd, verbatim from stock */
    REG8(0xec070000) = 7;
    /* stock: DAT_ec07001c = 132000000 / (0x2625a << 5) = 26 (bridge clock div) */
    REG8(0xec07001c) = 26;
    REG8(0xec070008) = 4;
}

/* ---- panel command (stock FUN_40001bb2 + tile writer FUN_40095990) ---- */
static void disp_cmd(u8 b) { ec07_putc(b); }

/* one 8x8 tile: 8 columns wide, 8 pixel rows tall (stock FUN_40095990) */
static void disp_tile(u8 col, u8 row, const u8 *data8)
{
    disp_cmd((u8)((row & 0xef) | 0x10)); /* row/page cmd, verbatim */
    disp_cmd(col);
    for (int i = 0; i < 8; i++)
        ec07_putc(data8[i]);
}

/* frame commit (stock FUN_40095978) */
static void disp_commit() { disp_cmd(0xb8); }

/* ---- full frame flush (stock FUN_40095afa shape) ---- */
extern "C" void display_flush(const u8 *plane /* 1024 B, 128x64 */)
{
    for (int row = 0; row < 8; row++) {
        for (int t = 0; t < 16; t++) {
            u8 tile[8];
            for (int k = 0; k < 8; k++)
                tile[k] = plane[(t * 8 + k) * 8 + row];
            disp_tile((u8)(t * 8), (u8)row, tile);
        }
    }
    disp_commit();
}

/* ---- pixel into plane (bitmap layout, MSB = top) ---- */
extern "C" void display_px(u8 *plane, int x, int y, int on)
{
    if ((unsigned)x >= 128 || (unsigned)y >= 64)
        return;
    u8 &b = plane[x * 8 + (y >> 3)];
    u8 mask = (u8)(0x80u >> (y & 7));
    if (on)
        b |= mask;
    else
        b &= (u8)~mask;
}
