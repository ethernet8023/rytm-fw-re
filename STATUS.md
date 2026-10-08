# Analog Rytm MKII firmware RE — status handoff

**Goal:** reverse engineer the Analog Rytm MKII OS update (OS 1.74) and build a
from-source C++ replacement firmware that can be compiled into a flashable
`.syx`. Bit-identical is NOT required — "works the same" is the bar.

**Where things live (durable, this project dir):**
- `Analog-Rytm_MKII_OS1.74.syx` — stock OS (keep, never modify)
- `extracted/` — the 5 unwrapped sections (all checksums verified):
  - `section_2_bootstrap.bin` (42,302 B, loads at 0x07020000)
  - `section_1_FPGA.bin` (149,516 B, Xilinx bitstream, AA99 sync)
  - `section_3_MAIN_OS.bin` (3,005,432 B, loads at 0x40000400) ← the main RE target
  - `section_8_?.bin` (159,948 B, unknown, 0xff-padded)
  - `section_5_meta.raw` (build timestamp)
- `firmware/` — our replacement OS source (crt0.s, hal.cpp, main.cpp, ld/rytm.ld)
  + reference disasm dumps (`*.bin` named by address) + `DumpDisplayCandidates.py`
- `elektron-firmware-tool/` — mischa85's tool (built binary inside), wrap/unwrap
- `libanalogrytm/`, `octamax/` — community refs
- `analysis/ghidra-scripts/` — pyghidra query scripts
- `analysis/output/periph_out.txt` — fns referencing peripherals + callers
- `analysis/output/decomp_out.txt` — decompiled UI test suite + a view fn

**Verified pipeline (reproduce from scratch):**

```bash
# unwrap: all checksums must read [ok]
cd elektron-firmware-tool && ./elektron-firmware-tool -i ../Analog-Rytm_MKII_OS1.74.syx -v

# build our firmware (NixOS; no make/cc on PATH, use nix shell, binaries are prefixed)
nix shell nixpkgs#legacyPackages.x86_64-linux.pkgsCross.m68k.buildPackages.gcc \
          nixpkgs#legacyPackages.x86_64-linux.pkgsCross.m68k.buildPackages.binutils -c bash -c '
C=m68k-unknown-linux-gnu-
$C"gcc" -mcpu=54455 -c src/crt0.s -o build/crt0.o
$C"g++" -mcpu=54455 -nostdlib -ffreestanding -fno-builtin -fno-exceptions -fno-rtti \
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -fno-pic \
  -fdata-sections -ffunction-sections -O2 -g -c src/hal.cpp -o build/hal.o
$C"g++" ... -c src/main.cpp -o build/main.o
$C"g++" -mcpu=54455 -nostdlib -static -Wl,--no-undefined -Wl,--gc-sections \
  -T ld/rytm.ld -Wl,-Map,rytmfw.map -o rytmfw.elf build/crt0.o build/hal.o build/main.o
$C"objcopy" -O binary rytmfw.elf rytmfw.bin'

# wrap into flashable syx (tool recomputes ALL checksums)
./elektron-firmware-tool -i ../Analog-Rytm_MKII_OS1.74.syx -c 3 ../firmware/rytmfw.bin \
  -o ../RytmFW-alpha3.syx
# verify: re-extract -d 3 and cmp with rytmfw.bin => identical
```

**Boot contract (RE'd, high confidence):**
- Bootstrap (SRAM 0x80000000) decompresses MAIN OS to 0x40000400, sets
  VBR=0x40000000 with a default handler in the 1KB hole 0x40000000..0x40000400,
  then `a0 = *(u32*)0x40000400; jsr (a0)` — image word[0] is an ENTRY FUNCTION
  POINTER, called C-style with one stack arg. NOT a reset SP/PC header.
- Stock entry fn @0x40000870: saves stack arg, SP=0x48000000, pin pokes
  (0xfc04002d series + 0xec09000e bclr #11), then
  0x400014ae (fill 256 vectors @0x40000000 with default 0x40000d6e)
  → 0x40000690 (INTC/GPIO pokes) → 0x400014cc (VBR=0x40000000)
  → 0x400007e4/0x4000083a (kernel task/queue init)
  → caches (CACR=0xa50ce100, ITT0=0x4007e020)
  → jsr 0x4017014a (kernel bring-up: zeroes globals @0x42f678xx, calls
  0x40100b12 which starts tasks incl. idle task SP=0x407c2000) → halt.
- Our crt0 (firmware/src/crt0.s) mirrors this: vector fill → VBR → bss →
  init_array → main. hal.cpp replicates the entry pokes + INTC/GPIO + caches
  verbatim from stock.

**Hardware/arch facts:**
- CPU: ColdFire MCF5445x family (BE). gcc: `-mcpu=54455`.
- RAM: DDR 0x40000000+ (OS at 0x40000400, kernel globals ~0x413dxxxx-0x42f6xxxx,
  scratch up to 0x40200000+, stacks 0x48000000 region, idle stack 0x407c2000).
- FPGA bitstream section (id=1) is flashed separately by the update; we leave it stock.
- Vector table: 256 x u32 at 0x40000000 (below image), runtime-filled. VBR=0x40000000.

**Display RE (SOLVED — flush pipeline fully decoded, see analysis/output/display_flush.txt):**
- Panel: 128x64 mono, driven over an FPGA byte-fifo bridge at 0xec07xxxx.
- Bus/channel (ec07): status 0xec070004 (bit2=tx ready, bit3=busy-done), data 0xec07000c.
  Channel init `FUN_40001c16`: DMA chan src ring @0x4b80a400 (4KB), burst 0x50, plus
  second descriptor @fc045470 → 0xec07000c; completion cb 0x400016f2, err 0x40001654.
  All display writes go: `FUN_400019e4(len, buf)` — ring pumper, kicks DMA when idle.
  (ec074xxx = second channel = MIDI UART, divisor 132e6/(31250*32); NOT display.)
- THE FLUSH `FUN_40095990(col, row, ptr8)`: mutex(0x413da6d4) → cmd(row&0xef|0x10)
  → cmd(col) → 8 data bytes → mutex give. Full clear+flush = `FUN_40095afa`:
  zero both planes, 16 col-tiles x 8 rows of 8 bytes, then commit cmd 0xb8.
- Diff flush `FUN_40095a5e`: compare planes (front @*0x40287b68=0x4191fbc8,
  back @*0x40287b6c=0x4191ffc8, both 1024B static), send changed 8B tiles, swap ptrs.
- Frame tasks (no callers = kernel-spawned): `FUN_40101fc0` boot splash (draws into
  back plane via bitmap ctor `FUN_4006fa2e(bmp,0x80,0x40,front,back)`, presents via
  FUN_40095a5e per frame, animates 100 frames, feeds LED engine too);
  `FUN_40095796` main frame loop (waits on queue 0x4191b6e8).
- Bitmap API: ctor FUN_4006f9b2(bmp,w,h) allocs TWO planes (w*ceil(h/32)*16B);
  ctor2 FUN_4006fa2e wraps static planes (no own). Layout: columns are scanlines —
  plane[col*(h+31)/32 + bit] — 128 cols x 64px → exactly 1024B/plane (matches
  "framebuffer 1024B" from test suite). Blit FUN_400716e0 = dual-plane XOR blit.
  Screen-ish popup overlays: singletons @0x417e3250/324c/3254 (lazy, 128x64).
- 2-byte addressing helper FUN_40095bb4(a,b): a<0x10 → (a&0xdf)|0x20 else (a&0xf)|0x30,
  then b — column/page addressing cmds, panel-specific (SSD1306-ish 0xB0|page does
  NOT appear; panel is behind the FPGA bridge, protocol is bridge-defined).
- LED engine (same FPGA SRAM family): FUN_4007a5a4 copies 0x1ecB pattern data to
  0x80004810 SRAM, DMAed to 0xfc03c034; kicker task FUN_4013ca1c (periodic) +
  FUN_4013cdd4 irq handler at vec ptr 0x400002fc. Init cluster FUN_4013d058.

**Display drawing API (decompiled, from test suite @0x4013d200 and view fn @0x400584fe):**
  - `FUN_4006f9b2(bmp, w, h)` — Bitmap ctor (e.g. 0x7a x 0x20)
  - `FUN_4007154c(dstBmp, fontspec, x, y, style, 0, str)` — draw string
  - `FUN_400712fc(dst, font, w, ?, -1, fmt, ...)` — draw formatted number
  - `FUN_400716e0(dst, srcBmp, x, y, flags)` — blit bitmap
  - `FUN_4006fd34/6fbd8` rect fill/invert; `FUN_40070726` box; `FUN_400703f4` xor box
  - `DAT_4027aa28` (w=3,h=1) and `DAT_40272a58` (w=8,h=8) are FONT/color objects
    (struct [w][h][3 plane ptrs]) — NOT framebuffers.
- Fonts: small table ~0x4027c8ec+ (6x7 glyphs); large strip ~0x40287200.
- Peripherals mapped so far:
  - DSPI 0xfc05c000 = +Drive eMMC/FS path (transfer fn 0x40135fb8: PUSHR +0x2c,
    full-bit-28 poll, POPR +0x38; driver cluster 0x40135a00-0x40137200)
  - eSDHC 0xfc0cc000 (init fn 0x401222d2)
  - 0xec09xxxx = audio codec GPIO/control (driver 0x400963ec-0x40096448)
  - 0xfc03c000 = DMA candidate (fns 0x400054ea, 0x4007a4e4/632)
  - 0xfc04002d/0xfc044018 pinmux/clock pokes (in stock entry + hal init)
- MISSING PIECE (SOLVED): the panel flush is FUN_40095990 (8B tiles over the ec07
  FPGA fifo channel, commit 0xb8, diff+swap on two static 1024B planes).
  Older notes below kept for reference; see the Display RE section above.
  1. Decompile callers of FUN_400716e0 (blit) — the top-level caller probably
     owns the screen bitmap and calls flush after drawing.
  2. Find the kernel task-start calls in 0x40100b12's callees — look for a task
     fn that references the screen bitmap + a bus write loop.
  3. Check fns referencing 0xfc03c000 (DMA) with 1024-byte bounds — the flush
     may be DMA-driven.

**Ghidra workflow (verified, quirk-heavy):**
- Analyze once (already done, project at /tmp/gproj — NOTE /tmp is ephemeral,
  re-create with the command below if gone; ~157 s):
  `ghidra-analyzeHeadless /tmp/gproj rytm174 -import <path>/section_3_MAIN_OS.bin \
   -processor "68000:BE:32:Coldfire" -loader BinaryLoader -loader-baseAddr 0x40000400`
  (project dir must NOT contain dot-path elements; `.hermes` paths break it)
- Query/decompile: `nix shell --impure --expr 'with import <nixpkgs> {};
  python314.withPackages (ps: with ps; [ pyghidra ])'` then run a script like
  analysis/ghidra-scripts/dump_periph_standalone.py (sets GHIDRA_INSTALL_DIR,
  opens via GhidraProject.openProject + openProgram("/", name, False)).
  Decompiler: DecompInterface + ConsoleTaskMonitor.
- Raw disasm alternative: `m68k-unknown-linux-gnu-objdump -D -b binary -m m68k
  --adjust-vma=<addr> chunk.bin`.

**Gotchas learned (do not re-learn):**
- gas rejects `move.l #sym,mem` on ColdFire — go through a data register.
- ghidra headless refuses dot-element paths; pyghidra needed for .py scripts.
- The tool's aPLib re-compression differs from stock's (its .syx is ~72 KB
  smaller) — verify by re-extracting content, never by full-file cmp.
- Version field max 10 chars ("RYTMFW_001" ok).
- objdump -m accepts `m68k` for raw binaries (not m68k:54455).
- Audio codec driver writes look like `move.b (arg-0x20),reg` — don't confuse
  with display.
- The `0x4013xxxx` cluster is +Drive FS/console, NOT display. The `0x402c8628`
  "256-entry table" is heap free-lists, not vectors.

**Immediate next steps (in order):**
1. Port the display driver into firmware/src/hal.cpp: ec07 channel init (from
   FUN_40001c16, incl. DMA descriptor pokes), the 3 cmd primitives
   (cmd/flush tile/commit), a 1024B plane pair, and a "draw test pattern +
   present" in main. Verify code path shape vs stock disasm.
2. Build + wrap -> RytmFW-alpha3.syx, verify checksums + content round-trip.
3. (Hardware step, needs the actual unit + Elektron Transfer or C6 over MIDI):
   flash stock-repack first as a no-op sanity check, then alpha3.
   Bootloader is never touched by an OS update — a bad OS is recoverable via
   [FUNC]+power-on startup menu.

**Legal note:** static analysis of a lawfully obtained OS, no redistribution of
Elektron binaries; community norm (EU 2009/24/EC Art. 5). The skill
`elektron-os-unwrap` in this Hermes profile carries the same knowledge.
