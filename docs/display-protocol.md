# Analog Rytm MKII display protocol (OS 1.74)

All addresses from static analysis of the stock OS; verified by building a
driver that speaks the same protocol (`firmware/src/display.cpp`).

## Hardware

Panel is a 128x64 monochrome unit driven through an FPGA "byte fifo" bridge.
The CPU never touches the panel directly — it writes bytes into the fifo and
the FPGA serializes them.

MMIO (bridge channel A — display):

| reg | meaning |
|-----|---------|
| `0xec070000` | bridge command (init writes 7) |
| `0xec070004` | status: bit2 = tx ready, bit3 = completion/busy |
| `0xec07000c` | tx data byte (one write per byte) |
| `0xec070008` | bridge config (init writes 4) |
| `0xec070014` | pinmux/config (init writes 3) |
| `0xec07001c` | bridge clock divisor byte: `132000000 / (base << 5)` |

A second, identical register block at `0xec074xxx` is the MIDI UART:
its init passes `0x7a12` as the divisor base — `132e6 / (0x7a12 << 5)`
evaluates for 31250 baud. Don't confuse the two blocks; the display
channel's init uses base `0x2625a`.

## Channel init (stock fn @0x40001c16)

Besides the MMIO pokes above, the stock init:
- muxes pins (`0xfc04002f = 0x1c`, codec pin `0xec09404b = 0xa0|old`)
- sets up a 4 KB DMA ring buffer at `0x4b80a400` (SRAM) + a second
  descriptor block at `0xfc045470` targeting the fifo data register,
- installs DMA completion/error callbacks,
- stores the DMA burst size (0x50) in the descriptor.

Our replacement firmware drives the fifo polled (no DMA yet) and skips the
ring entirely — the polled writer below is the stock OS's own fallback path
(fn @0x40121b08).

## Byte protocol

Polled write (per byte):
```
while (!(status & 0x4)) ;
data = byte;
```

Tile write (stock fn @0x40095990):
```
cmd((row & 0xef) | 0x10);   // row/page select
cmd(col);                   // column
for (i = 0; i < 8; i++) data(tile[i]);
```

Frame commit (stock fn @0x40095978): `cmd(0xb8)`.

Full frame = 16 column-tiles x 8 rows, 8 bytes each = 1024 bytes per plane.

## Framebuffers

Two static 1024-byte planes. Present (stock fn @0x40095a5e):
diff the planes, send only changed tiles, commit, swap the plane pointers.

Plane layout (from the bitmap ctor/blit pair):
- columns are scanlines: pixel (x, y) lives in byte `plane[x*8 + y/8]`,
  bit `0x80 >> (y%8)` — MSB is the top pixel of each 8-row group.
- The general bitmap API is dual-plane (two pointers at bmp+0x10/bmp+0x14)
  with XOR-semantics blits; the display present loop consumes the planes
  directly.
