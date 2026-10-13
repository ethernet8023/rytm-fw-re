# rytm-fw-re

Reverse engineering the Elektron Analog Rytm MKII OS update (OS 1.74) and building a
from-source replacement firmware that compiles into a flashable `.syx`.

**This repository contains NO Elektron firmware.** No OS files, no memory dumps,
no disassembly listings. It contains our own code, our own analysis tooling, and
factual notes (addresses, structures, protocols) derived from static analysis of
a lawfully obtained OS update (EU 2009/24/EC Art. 5). Work from your own stock
OS download — obtainable from Elektron's Support & Downloads page.

## Findings (verified against stock OS 1.74)

### Update container
- `.syx` = SysEx transport: `F0..F7` messages, 126-byte data packets, 8-in-7
  encoded, per-packet checksums, start/end marker messages.
- Inner binary container `ELE3`: model `H0176`, version, section table,
  content checksum. **No HMAC/signature on this device** (unlike Digitakt II).
- Sections: `2` bootstrap (SRAM 0x07020000), `1` FPGA bitstream, `3` MAIN OS
  (DDR 0x40000400), `5` meta, `8` unknown (~160 KB, likely upgrade journal;
  carries an upgrade-state status string).
- [mischa85/elektron-firmware-tool](https://github.com/mischa85/elektron-firmware-tool)
  unpacks and repacks. Verified on OS 1.74: `-r` self-repack is **byte-identical**
  to the stock file, and a `-c 3` replacement round-trips exactly.

### Boot contract
- Bootstrap decompresses MAIN OS to 0x40000400, sets VBR=0x40000000, then
  `jsr` to the function pointer stored in image word[0] (C-style, one stack arg).
  It is NOT a reset SP/PC header.
- Startup menu ([FUNC] at power-on) lives entirely in the bootstrap section:
  key/encoder/pot/pad tests, empty reset, factory reset, OS upgrade receiver.
  An OS-only update can never touch it; a bad OS is always recoverable.
- Bootstrap version-checks upgrades and refuses to install an older version.

### CPU / memory map (ColdFire MCF5445x family, big-endian)
- DDR 0x40000000+ (OS at 0x40000400, kernel globals ~0x413dxxxx–0x42f9xxxx),
  FPGA SRAM window 0x80000000+, stacks 0x48000000 region, idle stack 0x407c2000.

### Display pipeline (fully decoded)
- Panel: 128x64 mono behind an FPGA byte-fifo bridge at `0xec070xxx`
  (status `+4` bit2 = tx ready, data `+0xc`). A second bridge channel at
  `0xec074xxx` is the MIDI UART (divisor 132e6/(31250*32)).
- Channel init programs a DMA ring (4 KB) and burst descriptors; all display
  traffic flows through a ring-pumper -> DMA -> fifo.
- Tile write: cmd `(row&0xef)|0x10`, cmd `col`, 8 data bytes, under a mutex.
  Frame commit: cmd `0xb8`. Full frame = 16x8 tiles of 8 bytes = 1024 B plane.
- Framebuffers: two static 1024 B planes; present = diff-scan, send changed
  tiles, swap pointers.
- Bitmap API: dual-plane, column-major (columns are scanlines),
  plane = 128 cols x 2 u32 = 1024 B.

### Replacement firmware
- `firmware/` builds a freestanding m68k image (`-mcpu=54455`, gcc via nixpkgs
  `pkgsCross.m68k`), links at 0x40000400 with the entry-pointer header, and
  wraps into a flashable `.syx` with the tool above.
- Current state: boots, brings up INTC/GPIO/caches (pokes copied verbatim from
  stock), drives the display with a test pattern, parks. ~904 B image.
- Gotcha: the nixpkgs m68k binutils `ld` *wrapper* segfaults and emits corrupt
  ELFs; invoke `ld.bfd` from the binutils package directly.

### Flash + upgrade path
- The whole upgrade path lives in the bootstrap section (42 KB, runs from SRAM):
  receive over the MIDI UART, parse the container, verify, write flash, reboot.
- Flash is **SPI NOR on the DSPI controller `0xfc05c000`** (polled, no DMA),
  multi-vendor JEDEC: an RDID probe picks page/erase sizes per manufacturer.
  Erase is 256 KB blocks, program is 512 B units, staged in DDR at `0x3FF80008`.
- Flash layout: **bootstrap + FPGA at `0x0-0x7FFFF` (never written), MAIN OS at
  `0x80000+`** — so writing only above `0x80000` keeps the FUNC+power recovery
  path intact by construction.
- The opcode-level erase/program helpers are called through absolute pointers
  whose targets are *not* those instructions in the file (they resolve into
  startup-menu code): the real driver is loaded or patched at runtime, most
  likely from +Drive. A replacement OS does not need it — standard JEDEC
  commands (WREN/RDSR/RDID/PP/`0xD8`) are enough.
- Writeup: [docs/flash-driver.md](docs/flash-driver.md); the plan to make the
  custom OS own USB and retire the DIN dependency:
  [docs/usb-reflash.md](docs/usb-reflash.md).

### Static-data mods (hardware-confirmed)
- The MAIN OS section carries the boot-splash art and the LED palette as plain
  static data at fixed addresses, so both can be replaced with same-size byte
  patches — no relocation, no in-section checksum, container rebuilt by the
  update tool. Flashed and confirmed on a real unit.
- Splash: two 1-bit bitmaps (32x24 and 117x17) in a column-major plane format
  that a ~100-frame dither wipe blends between. Panel rows run bottom-up
  relative to plane rows.
- LEDs: a colour is a palette index `(hue << 4) | level`, and the boot animation
  is a 42-entry phase table indexing a 6-bank x 7 hue x 16 level palette. The
  phase table is the gradient you watch travel along the panel, so banded hues
  in it read as stripes.
- Full format notes, addresses and tooling: [docs/splash-and-led-mods.md](docs/splash-and-led-mods.md)

## Layout
- `analysis/ghidra-scripts/` — pyghidra probes (function discovery, xrefs,
  decompilation drivers). Reusable on any ColdFire Elektron OS image.
- `firmware/` — the replacement OS.
- `scripts/` — flash/probe tooling + the mod pipeline (`fwpatch.py`,
  `splash_bmp.py`, `led_sweep.py`, `build_mod.py`).
- `docs/` — protocol notes.

## Status
Boot contract, container format, display pipeline, splash bitmap + LED palette:
decoded and verified. Replacement OS boots on hardware (memprobe all-PASS);
static-data mods boot on hardware with the panel confirmed. See
[STATUS.md](STATUS.md) for the working state; this public repo tracks stable
findings.
