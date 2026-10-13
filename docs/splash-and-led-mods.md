# Boot splash + LED animation mods

Static-data mods, hardware-confirmed on a real unit (flashed over USB, booted,
splash art and LED animation seen on the panel).

Everything here is a *same-size byte-range patch inside section 3* (MAIN OS):
the splash art and the LED palette are plain static data at fixed addresses, so
nothing relocates, there is no in-section checksum to fix, and the update tool
rebuilds the container. That makes this the lowest-risk mod tier on the device —
the only remaining risk is container format, which `scripts/fwpatch.py` checks on
every build.

No Elektron bytes appear in this document or in the tooling: only addresses,
formats, and our own code.

## Boot splash

The splash is a frame task that runs ~100 frames. Per frame it walks all 128x64
pixels, picks per pixel between two static bitmaps **A** and **B** through a
64-byte ordered-dither matrix and a sweeping ramp, presents the frame, and drives
the LED animation. Both bitmaps are drawn centred. At frame 100 it signals and
waits.

| bitmap | size | art plane | mask plane | plane bytes |
|--------|------|-----------|------------|-------------|
| A | 32x24 | 0x402b2c24 | 0x402b2ba4 | 128 |
| B | 117x17 | 0x402be4e8 | 0x402be314 | 468 |

- **Plane format** (column-major mono): one 32-bit big-endian word per 32 plane
  rows of a column, stride = `(h+31)>>5` words per column, MSB = plane row 0:

  ```
  word  = BE u32 at plane + ((y >> 5) + stride * x) * 4
  pixel = (word >> (31 - (y & 31))) & 1
  ```

  Plane size = `w * stride * 4` bytes. The two planes are stored contiguously
  (`[mask][art]`), and the **mask** is all-ones over plane rows 0..h-1 (opaque
  blit) — it is not art.
- **Panel rows run bottom-up relative to plane rows.** Rendering a plane
  top-down shows the art upside down; reversing the h rows shows it as it appears
  on the panel, x untouched. So a screen-oriented bitmap row `s` is plane row
  `h-1-s`, and any authored art must be stored row-reversed. (The plane
  addressing itself is MSB = top — that is what the mask extents and the
  centring maths agree on; the inversion is the panel's.)
- The bitmap *objects* live in BSS and are wrapped around these static planes at
  runtime, but the art bytes are ordinary image data — which is what makes a
  same-size in-place swap possible.

## LED animation

A LED colour is a **palette index**, not RGB: `colour = (hue << 4) | level`,
hue 0..7, level 0..15.

- The splash's animation walks 8 groups of LED ids and per LED sets
  `colour = phase_table[clamp(frame - group - 3*position, 0, 41)]` — a chase.
- **Phase table** @0x40289104: 42 u32. Stock is hue 5 (magenta) with levels
  `1,2,4,8,15 x7,14,14,13,13,...,1,0`, i.e. the magenta chase.
- **Palette** @0x401d8ae0: 6 reachable banks x 7 hues x 16 levels x RGB (3 bytes
  each), bank stride 0x150. The bank is selected at boot from a runtime global
  (bits 0/1/2 and 6/7), which is why a static-only mod patches every reachable
  bank rather than guessing. Palette channels are **5-bit** (0..31).
- Hue map at level 15: `0` red (31,0,0) · `1` green (0,31,0) · `2` blue (0,0,31) ·
  `3` orange (31,26,0) · `4` cyan (0,31,31) · `5` magenta (31,0,31) · `6` white
  (~30,30,30). Hue `7` is the dynamic range — not in the loaded palette: `0x70`
  black and `0x71` white are set by the LED clear path at boot, `0x74..0x7f` are
  defined at runtime.
- Level 0 of every hue is a near-black (1,1,1) entry, so "level 0" is dim rather
  than fully off; palette index 0x00 is off.
- The palette is **shared with the UI**, so redefining a hue to recolour the boot
  animation shifts that colour everywhere in the UI too. Recolouring by rewriting
  only the phase table's hue nibbles is bank-independent and touches nothing else.

Because the phase table *is* the gradient you watch travel along the panel,
putting different hues in different phase ranges reads as striped bands rather
than a single fade. `led_sweep.py --flag trans` builds
`off -> blue -> pink -> white -> pink -> blue -> off` that way (7/7/6/7/7 phases
at level 15, with the fade in/out riding blue's low levels), redefining hues 2
and 5 to the flag tones; `--flag trans-stock` builds the same stripes out of the
stock blue/magenta/white and patches nothing but the phase table.

## Tooling

```
scripts/fwpatch.py     load section 3 / patch / wrap into .syx / verify
scripts/splash_bmp.py  extract  : section bin or .syx -> 1bpp BMP (+ preview, + raw plane)
                       build    : BMP -> patched section -> flashable .syx
scripts/led_sweep.py   show     : decode the phase table + palette
                       preview  : render the envelope colour strip as a PNG
                       build    : --hue <name> | --flag trans | --rgb R,G,B
scripts/build_mod.py   chain every mod into one image, one flash cycle
```

```bash
python3 scripts/splash_bmp.py extract                 # stock art -> editable BMPs
python3 scripts/build_mod.py --sweep-flag trans --out RytmFW-mod.syx
python3 scripts/led_sweep.py preview --flag trans      # eyeball before flashing
```

`extract` writes 1-bit BMPs (index 1 = white = lit pixel, rows bottom-up);
`build` accepts 1/24/32 bpp BMPs and also any integer multiple of the native
size (it downsamples), so art can be authored at 8x and shrunk back.

## Verification and flashing

Every build:

1. re-extracts section 3 from the produced `.syx` and compares it byte-for-byte
   against the patched image;
2. checks the container's section table — 16-byte aligned offsets with
   `next_off == align16(off + clen)` (the earlier "clen must be 4-byte aligned"
   belief was wrong: `clen` is the exact stored stream length and stock ships
   `clen=0xf` on its raw meta section).

With unmodified inputs the pipeline is lossless — the patched section is
byte-identical to stock, which is the property that makes a diff meaningful.

Flashing is over USB with `scripts/flash_rytm.py --send <file> --wait-reboot`
(press YES on the unit when prompted). **Recovery is MIDI DIN only and never
enumerates USB**: once a non-stock OS is running, USB flash-back is impossible,
so have a MIDI-DIN sender and a stock OS file ready before flashing. Assume one
USB shot per cycle.
