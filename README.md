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
  contains the string "No active upgrade").
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
- Bootstrap version-checks upgrades: "DOWNGRADE NOT POSSIBLE".

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

## Layout
- `analysis/ghidra-scripts/` — pyghidra probes (function discovery, xrefs,
  decompilation drivers). Reusable on any ColdFire Elektron OS image.
- `firmware/` — the replacement OS.
- `docs/` — protocol notes.

## Status
Boot contract, container format, display pipeline: decoded and verified.
Hardware flash test pending. See [STATUS.md](STATUS.md) in the private working
repo; this public repo tracks stable findings.
