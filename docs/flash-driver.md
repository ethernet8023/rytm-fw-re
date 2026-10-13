# Flash driver (SPI NOR) — decoded from section_2_bootstrap.bin

Source: ghidra project `rytm174`, program `section_2_bootstrap.bin`
(base 0x80000000, file↔SRAM 1:1 — verified by dozens of consistent internal
cross-references). Probes 64-69; raw decompils in `analysis/output/bootstrap_*.txt`.

## Controller + chip

- Bus: **DSPI** at `0xfc05c000` (module cfg `+0x000`, status `+0x2c`, PUSHR
  `+0x34`, POPR `+0x38`). Polled transfers, no DMA. PUSHR encodings observed:
  `0x8020_XXXX` = command byte XXXX (CTAS cfg B), `0x8002_XXXX` = data byte
  (CTAS cfg A).
- Chip: commodity **SPI NOR**; the probe (FUN_800025fc) RDIDs 5 bytes and
  sets driver parameters per vendor:

| manufacturer | device IDs | page | erase block | flag |
|---|---|---|---|---|
| Spansion (0x01) | 0x2018 | 0x200 | 0x40000 | 1 |
| Winbond (0xEF) | 0x4014/0x7015, 0x4017/0x4018 | 0x100 | 0x10000 | 0 |
| Macronix (0xC2) | 0x2017/0x2018 | 0x100 | 0x10000 | 0 |
| ISSI (0x9D) | 0x6017/0x6018 | 0x100 | 0x10000 | 0 |
| EON (0x1C) | 0x7015 | 0x100 | 0x10000 | 0 |

Page size → PTR_DAT_80009684, erase size → PTR_DAT_80009680, vendor flag →
_DAT_8000bc18. The upgrade fn also gates on the staged image's version-date
field (image+0x10, 4 ASCII chars, compared against "0125"/"0135"/"0134"/"0421"
per chip family) — downgrade/eligibility logic (the bootstrap refuses an older
version outright).

## Flash layout (verified in FUN_80005d66's loops, raw-byte checked)

| flash offset | content |
|---|---|
| 0x00000–0x7FFFF | bootstrap (42KB) + FPGA bitstream (149KB) — **NEVER WRITE** |
| 0x80000+ | MAIN OS section image |

- Staging: image assembled in **DDR at 0x3FF80008** (flash offset X ↔
  0x3FF80008 + X), header: `size @ 0x40000000`, `checksum @ 0x40000004`
  (`sum = (i ^ word[i]) + sum` over size>>2 words from 0x40000008), image
  from 0x40000008.
- Erase loop: from flash offset **0x80000**, step **0x40000** (256KB), count
  `(size + 0x3FFFF) >> 18`; watchdog kick `0xfc04c01c = 0x2e` per block.
- Program loop: from 0x80000, step **0x200** (512B), count `size >> 9`, src =
  offset + 0x3FF80008.
- After write: `0x48000000 = 0`, `0xec090000 = 0x80`, return (reboot path).

## DSPI driver primitives (fully decompiled, clean region 0x22f8-0x29xx)

| fn | role |
|---|---|
| FUN_800022f8 | WREN — PUSHR 0x8020006 (cmd 0x06) |
| FUN_8000233a | push 0x00 + read POPR (status/dummy read) |
| FUN_8000238e(cmd, n, buf) | command byte + write n bytes |
| FUN_8000248c(cmd) | single command byte |
| FUN_8000254c(buf, n) | read n bytes |
| FUN_80002852 | WREN + cmd + status poll (gated by vendor flag) |
| FUN_8000293a(dst, n, src) | chunked program wrapper (page-size aware) |
| FUN_800025fc | chip probe: RDID → per-vendor page/erase/flag table |
| FUN_8000a3f4 | 4-byte preamble + read n (fast-read shaped) |

## THE MYSTERY (open, does NOT block our own driver)

The upgrade fn calls its erase/program/ID helpers through absolute pointers:
**0x80002d36** (page program, args off/0x200/src), **0x80002da2** (erase,
arg = flash offset), **0x80002dfa/0x80002e0e/0x80002e20/0x80002e34** (ID
readers). All six land inside the startup-menu state machine region
(0x80002d42-0x8000316c) in the FILE bytes — forced re-disassembly from each
entry re-derives the same menu code; the bytes decode only one way. A scan
for a 6-function cluster at the pointer-implied spacings
(0x6c/0x58/0x14/0x12/0x14) finds NOTHING anywhere in the file.

**Conclusion: the real flash driver is loaded or patched at runtime.**
Leading theory: it comes from **+Drive** — the bootstrap's otherwise
unexplained eSDHC (0xfc0c8000/0xfc0cc000) + eDMA (TCDs at 0xfc045xxx, one
descriptor sourcing SRAM 0x80008820) init, plus section 8's upgrade-state
journal, all point to a +Drive-staged installer: the running OS
stores an update on +Drive, and the bootstrap loads the installer stage +
image at boot. The FUNC-menu DIN receiver presumably feeds the same
pipeline. Next-session target: trace the eSDHC read path
(FUN_80004170 = eSDHC cmd/arg/poll) + where its data lands in SRAM.

Note: an old anchor recorded "handoff at SRAM 0x80000d46" but the file's
`jsr (a0)` sits at 0x80000d56 — the file is self-consistent at 1:1, so treat
0x80000d56 as correct and the old note as a transcription artifact.

## Also seen in the bootstrap (not flash, note for later)

- `0xec064xxx` = second FPGA fifo bridge channel (same protocol family
  as display 0xec070xxx: status bit2 + data reg 0x0c) — likely the
  bootstrap's MIDI DIN UART for the upgrade receiver.
- Bootstrap inits eSDHC (`0xfc0c8000` regs + eDMA TCDs at 0xfc045xxx) —
  now folded into the +Drive-installer theory above.

## What this means for OUR USB reflash (the actual goal)

We do NOT need the bootstrap's mystery driver. We have every ingredient to
write our own in the replacement OS:
- DSPI primitives (above) — port the five small polling fns.
- Standard JEDEC NOR commands on all listed vendors: WREN 0x06, RDSR 0x05,
  RDID 0x9F, READ 0x03/0x0B, PP 0x02, **erase 0xD8** (64KB — supported by
  every vendor in the table; matches the 0x10000/0x40000 erase sizes).
- Flash layout: write flash ≥ 0x80000 ONLY → bootstrap+FPGA untouched →
  FUNC+DIN safety net always intact.
- Staging header format for our own receive-verify flow.
- Progress display while erasing/programming (we have the display driver).

## Next steps (stage 1 remainder)

- [x] Exact SPI framing of the bootstrap's erase/program — SOLVED as
      "runtime-loaded driver, not in file" (see MYSTERY). Our own driver
      uses standard JEDEC commands instead.
- [ ] Reconcile DSPI register/CTAS config with the MCF5445x RM chapter
      (still worth doing before writing our driver).
- [ ] Trace the eSDHC read path (FUN_80004170) + SRAM landing — confirms or
      kills the +Drive-installer theory (curiosity, not blocking).
- [ ] MCF5445x RM USB chapter → init sequence skeleton (stage 2 prep).
- [ ] Stock MAIN OS: find its USB init pokes (clock/pinmux/PHY) to copy.
