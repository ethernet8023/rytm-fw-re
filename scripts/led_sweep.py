#!/usr/bin/env python3
"""Boot-splash LED sweep colours.

The splash task (FUN_40101fc0) also runs the panel LED animation: per frame it
walks 8 groups of LED ids (table 0x40288e64, -1 = skip) and per LED calls
FUN_40095fc0(led_id, colour), which pushes [0xb0|slot, field, colour] to the
FPGA LED controller. `colour` is a PALETTE INDEX:

    colour = (hue << 4) | level          hue 0..7, level 0..15

The sweep's phase -> colour table is 42 u32 at **0x40289104**:

    0x70 (hue 7 = dynamic/black), then hue 5 levels 1,2,4,8,15 x7, then
    14,14,13,13,12,12,...,51,50, 0,0,0   <- clamp(frame - group - 3*pos, 0, 0x29)

so the fade you see is hue 5's 16-step ramp, chased around the panel. Levels are
palette entries, and the palette is static data at **0x401d8ae0**:

    6 reachable banks x 7 hues x 16 levels x RGB(3 bytes)     (bank stride 0x150)

loaded at boot by FUN_40095f54(FUN_400faac4()) which pushes each entry as
FUN_40095ed4(index, r, g, b) = cmd 0xb5. Hues: 0 red, 1 green, 2 blue,
3 orange, 4 cyan, 5 magenta (the stock sweep), 6 white; 7 = the dynamic range
(0x70 = black, 0x71 = white, 0x74..0x7f set at runtime). FUN_400faac4 picks the
bank from bits 0/1/2 and 6/7 of a runtime global at 0x405c8e4f, so which bank
this unit loads is a hardware/runtime thing - the sweep colour edit below is
bank-independent because it only touches the hue nibble, and the custom-RGB mode
rewrites that hue in every reachable bank.

Commands
    show                      decode the sweep table + palette
    build --hue cyan          recolour the sweep (keeps the level envelope)
    build --rgb 255,80,0      custom ramp for hue 5 in every reachable bank
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import fwpatch

REPO = fwpatch.REPO

SWEEP_TABLE = 0x40289104
SWEEP_ENTRIES = 42          # clamp bound in the splash is 0x29 (= 41)
SWEEP_HUE = 5               # the hue the stock envelope ramps

PALETTE = 0x401D8AE0
PAL_BANKS = 6               # FUN_400faac4 only ever returns 0..5
PAL_BANK_STRIDE = 0x150     # 7 hues x 16 levels x 3 bytes
PAL_HUES = 7
PAL_LEVELS = 16
PAL_HUE_STRIDE = PAL_LEVELS * 3

HUE_NAMES = ("red", "green", "blue", "orange", "cyan", "magenta", "white")
HUE_BY_NAME = {n: i for i, n in enumerate(HUE_NAMES)}

# Palette channels are 5-bit (stock hue 0 level 15 = 31,0,0), so 8-bit flag
# colours get scaled to 0..31 on the way in.
PAL_MAX = 31

# off -> blue -> pink -> white -> pink -> blue -> off, as (hue, level) per phase.
# The sweep table IS the gradient you see travel along the panel, so banded hues
# here read as flag stripes; the levels are only there for the fade in/out.
HUE_BLUE, HUE_PINK, HUE_WHITE = 2, 5, 6
TRANS_FLAG_BANDS = (HUE_BLUE, HUE_PINK, HUE_WHITE, HUE_PINK, HUE_BLUE)
TRANS_FLAG_WIDTHS = (7, 7, 6, 7, 7)      # 34 lit phases, symmetric
TRANS_FLAG_FADE = (6, 12)                # blue levels either end
TRANS_COLOURS = {                        # 8-bit, off the trans flag
    "blue": (91, 206, 250),
    "pink": (245, 169, 184),
    "white": (255, 255, 255),
}
FLAG_STOCK_HUES = "trans-stock"          # same stripes, stock blue/magenta/white


def read_sweep(image: bytes | bytearray) -> list[int]:
    return list(struct.unpack_from(">" + "I" * SWEEP_ENTRIES,
                                   fwpatch.slice_of(image, SWEEP_TABLE, 4 * SWEEP_ENTRIES)))


def write_sweep(image: bytearray, entries: list[int]) -> None:
    fwpatch.patch(image, SWEEP_TABLE, struct.pack(">" + "I" * len(entries), *entries))


def read_palette_hue(image: bytes | bytearray, bank: int,
                     hue: int) -> list[tuple[int, int, int]]:
    off = hue * PAL_HUE_STRIDE
    raw = fwpatch.slice_of(image, PALETTE + bank * PAL_BANK_STRIDE + off, PAL_HUE_STRIDE)
    return [tuple(raw[i * 3:i * 3 + 3]) for i in range(PAL_LEVELS)]  # type: ignore[misc]


def hue_label(v: int) -> str:
    hue = (v >> 4) & 0xF
    return HUE_NAMES[hue] if hue < len(HUE_NAMES) else "dynamic"


def describe_colour(v: int) -> str:
    if v == 0:
        return "0x00 (off)"
    return f"0x{v:02x} ({hue_label(v)} lvl {v & 0xF})"


# --------------------------------------------------------------------- mods

def apply_hue(image: bytearray, hue: int, log: bool = True) -> int:
    """Recolour the sweep by rewriting the hue nibble, keeping every level.

    Only entries already in the sweep's hue are touched, so the off/dynamic
    entries (0x00, 0x70) keep their stock meaning and the fade envelope is
    untouched - this is why it works whichever palette bank the unit loads.
    """
    if hue == SWEEP_HUE:
        if log:
            print(f"led sweep: already hue {hue} ({HUE_NAMES[hue]}), nothing to do")
        return 0
    entries = read_sweep(image)
    changed = 0
    for i, v in enumerate(entries):
        if (v >> 4) & 0xF == SWEEP_HUE:
            entries[i] = (hue << 4) | (v & 0xF)
            changed += 1
    write_sweep(image, entries)
    if log:
        print(f"led sweep: hue {SWEEP_HUE} ({HUE_NAMES[SWEEP_HUE]}) -> {hue} "
              f"({HUE_NAMES[hue]}) in {changed}/{len(entries)} entries "
              f"@0x{SWEEP_TABLE:08x}")
    return changed


def apply_rgb(image: bytearray, rgb: tuple[int, int, int], log: bool = True) -> int:
    """Rewrite hue 5's ramp as a custom RGB fade, in every reachable bank.

    Level n scales the colour by n/15 (level 0 keeps the stock near-black
    (1,1,1) entry), so the chase keeps its shape but takes your colour.
    """
    r, g, b = rgb
    ramp = [bytes((1, 1, 1))]
    ramp += [bytes((r * l // 15, g * l // 15, b * l // 15)) for l in range(1, PAL_LEVELS)]
    blob = b"".join(ramp)
    for bank in range(PAL_BANKS):
        fwpatch.patch(image, PALETTE + bank * PAL_BANK_STRIDE
                      + SWEEP_HUE * PAL_HUE_STRIDE, blob)
    if log:
        print(f"led sweep: hue {SWEEP_HUE} ramp -> RGB({r},{g},{b}) fade in "
              f"{PAL_BANKS} banks @0x{PALETTE:08x}")
    return len(blob) * PAL_BANKS


def trans_flag_entries() -> list[int]:
    """42 sweep-table entries for off -> blue -> pink -> white -> pink -> blue -> off.

    Both degrees of freedom are used deliberately: hue picks the stripe, and
    level 15 keeps the stripes at full brightness so they read as bands rather
    than one long fade; only the fade in/out rides blue's low levels. Which
    actual tones those hues are is a palette question (see apply_flag).
    """
    body: list[int] = [(HUE_BLUE << 4) | fade for fade in TRANS_FLAG_FADE]
    body += [(hue << 4) | 15 for hue, n in zip(TRANS_FLAG_BANDS, TRANS_FLAG_WIDTHS)
             for _ in range(n)]
    body += [(HUE_BLUE << 4) | fade for fade in reversed(TRANS_FLAG_FADE)]
    entries = [0] * SWEEP_ENTRIES
    entries[0] = 0x70                       # keep the stock off/dynamic marker
    if len(body) > SWEEP_ENTRIES - 1:
        raise SystemExit(f"flag envelope is {len(body)} phases, table holds "
                         f"{SWEEP_ENTRIES - 1}")
    entries[1:1 + len(body)] = body
    return entries


def apply_flag(image: bytearray, flag: str, log: bool = True) -> int:
    """Apply a named sweep preset to the section image, in place."""
    if flag not in ("trans", FLAG_STOCK_HUES):
        raise SystemExit(f"unknown sweep flag {flag!r}")
    stock_hues = flag == FLAG_STOCK_HUES
    write_sweep(image, trans_flag_entries())
    lit = sum(1 for v in read_sweep(image)[1:] if v)
    if log:
        names = [hue_label(v) for v in read_sweep(image)[1:] if v]
        print(f"led sweep: {flag} flag envelope, {lit} lit phases "
              f"@0x{SWEEP_TABLE:08x}: " + ">".join(
                  [n for i, n in enumerate(names) if i == 0 or names[i - 1] != n]))
    if stock_hues:
        return lit
    # Redefine hue 2 (blue) and hue 5 (magenta) so the stripes are the actual
    # flag tones. Note this is the SHARED static palette, so the UI's blue and
    # magenta shift too - that is what FLAG_STOCK_HUES exists to avoid.
    written = 0
    for hue, key in ((HUE_BLUE, "blue"), (HUE_PINK, "pink")):
        r8, g8, b8 = TRANS_COLOURS[key]
        base = tuple(c * PAL_MAX // 255 for c in (r8, g8, b8))
        ramp = [bytes((1, 1, 1))]
        ramp += [bytes(tuple(c * l // 15 for c in base)) for l in range(1, PAL_LEVELS)]
        blob = b"".join(ramp)
        for bank in range(PAL_BANKS):
            fwpatch.patch(image, PALETTE + bank * PAL_BANK_STRIDE + hue * PAL_HUE_STRIDE,
                          blob)
        written += len(blob) * PAL_BANKS
        if log:
            print(f"led sweep: hue {hue} ({HUE_NAMES[hue]}) ramp -> "
                  f"{key} RGB{r8},{g8},{b8} (5-bit {base}) in {PAL_BANKS} banks")
    return lit + written


# ------------------------------------------------------------------ preview

def write_rgb_png(path: Path, rows: list[list[tuple[int, int, int]]],
                  bg: tuple[int, int, int] = (16, 16, 16)) -> None:
    """RGB PNG with no third-party deps, for eyeballing a palette offline."""
    import zlib

    H = len(rows)
    W = max(len(r) for r in rows)
    raw = bytearray()
    for row in rows:
        raw.append(0)
        for x in range(W):
            r, g, b = row[x] if x < len(row) else bg
            raw += bytes((r, g, b))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    path.write_bytes(b"\x89PNG\r\n\x1a\n"
                     + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
                     + chunk(b"IEND", b""))


def cmd_preview(args: argparse.Namespace) -> int:
    """Render the sweep envelope as an image: what colour each phase lights.

    Per-phase colours come from bank 0 of the palette (the banks only differ in
    fine brightness tweaks), scaled from the palette's 5-bit channels to 8-bit.
    The panel's physical LED order is not known statically, so this is the
    envelope you would see travel, not a photo of the panel.
    """
    image = bytearray(fwpatch.load_section(args.section, args.syx))
    if args.flag:
        apply_flag(image, args.flag, log=False)
    if args.hue is not None:
        apply_hue(image, args.hue, log=False)
    if args.rgb:
        apply_rgb(image, tuple(int(x) for x in args.rgb.split(",")), log=False)  # type: ignore[arg-type]
    entries = read_sweep(image)
    cell, tall = args.cell, args.height
    scale = 255 // PAL_MAX
    rows: list[list[tuple[int, int, int]]] = []
    ramp = []
    for v in entries:
        r, g, b = read_palette_hue(image, 0, (v >> 4) & 0xF)[v & 0xF] if v else (0, 0, 0)
        ramp += [(r * scale, g * scale, b * scale)] * cell
    rows += [ramp] * tall
    rows += [[(40, 40, 40)] * len(ramp)] * 2          # separator
    levels = []
    for v in entries:
        g = 255 * (v & 0xF) // 15
        levels += [(g, g, g)] * cell
    rows += [levels] * (tall // 3)
    out = Path(args.out)
    write_rgb_png(out, rows)
    print(f"sweep preview ({len(entries)} phases, {args.cell}px each, bank 0) -> {out}")
    return 0


# ------------------------------------------------------------------ commands

def cmd_show(args: argparse.Namespace) -> int:
    image = fwpatch.load_section(args.section, args.syx)
    entries = read_sweep(image)
    print(f"sweep table @0x{SWEEP_TABLE:08x} - {SWEEP_ENTRIES} entries "
          f"((hue<<4)|level), phase = clamp(frame - group - 3*pos, 0, 0x29)\n")
    for i, v in enumerate(entries):
        print(f"  [{i:2d}] {describe_colour(v)}")
    print(f"\npalette @0x{PALETTE:08x} - {PAL_BANKS} reachable banks x "
          f"{PAL_HUES} hues x {PAL_LEVELS} levels x RGB")
    for bank in range(PAL_BANKS):
        row = read_palette_hue(image, bank, SWEEP_HUE)
        print(f"  bank {bank} hue {SWEEP_HUE}: " + " ".join(f"{r:3d},{g:3d},{b:3d}"
                                                            for r, g, b in row))
    print("\nother hues (bank 0, level 15 = full):")
    for h in range(PAL_HUES):
        full = read_palette_hue(image, 0, h)[PAL_LEVELS - 1]
        print(f"  hue {h} ({HUE_NAMES[h]}): {full[0]},{full[1]},{full[2]}")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    image = bytearray(fwpatch.load_section(args.section, args.syx))
    if args.flag:
        apply_flag(image, args.flag)
    if args.hue is not None:
        apply_hue(image, args.hue)
    if args.rgb:
        apply_rgb(image, tuple(int(x) for x in args.rgb.split(",")))  # type: ignore[arg-type]
    if args.out_bin:
        Path(args.out_bin).write_bytes(image)
        print(f"patched section bin -> {args.out_bin} (no .syx wrapped)")
        return 0
    return 0 if fwpatch.wrap_and_verify(image, args.out, args.syx_in, args.level,
                                        args.version) else 1


def hue_value(text: str) -> int:
    if text.isdigit():
        v = int(text)
        if not 0 <= v <= 6:
            raise argparse.ArgumentTypeError("hue index must be 0..6")
        return v
    try:
        return HUE_BY_NAME[text.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"hue must be one of {', '.join(HUE_NAMES)} or 0..6")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--section", default=str(fwpatch.DEFAULT_SECTION),
                       help="unwrapped section 3 bin (default: %(default)s)")
        p.add_argument("--syx", help="read section 3 straight out of a .syx instead")

    s = sub.add_parser("show", help="decode the sweep table + palette")
    common(s)
    s.set_defaults(func=cmd_show)

    p = sub.add_parser("preview", help="render the sweep envelope as a PNG")
    common(p)
    p.add_argument("--hue", type=hue_value, help="recolour first (as in build)")
    p.add_argument("--flag", choices=("trans", FLAG_STOCK_HUES))
    p.add_argument("--rgb", help="custom hue-5 ramp as R,G,B (0..255 each)")
    p.add_argument("--cell", type=int, default=10, help="pixels per phase (default 10)")
    p.add_argument("--height", type=int, default=40, help="strip height in pixels")
    p.add_argument("--out", default=str(REPO / "extracted" / "sweep-preview.png"))
    p.set_defaults(func=cmd_preview)

    b = sub.add_parser("build", help="recolour the sweep -> patched .syx")
    common(b)
    b.add_argument("--hue", type=hue_value, help=f"one of {', '.join(HUE_NAMES)} or 0..6")
    b.add_argument("--flag", choices=("trans", FLAG_STOCK_HUES),
                   help="named sweep preset: trans = off>blue>pink>white>pink>blue>off "
                        "in the real flag tones; trans-stock = same stripes in the "
                        "stock blue/magenta/white, so the shared palette is untouched")
    b.add_argument("--rgb", help="custom hue-5 ramp as R,G,B (0..255 each)")
    b.add_argument("--syx-in", default=str(fwpatch.STOCK_SYX), help="stock .syx to patch")
    b.add_argument("--out", default=str(REPO / "RytmFW-led.syx"))
    b.add_argument("--out-bin", help="write just the patched section bin, no wrap")
    b.add_argument("--version", help="override the container version string")
    b.add_argument("-l", "--level", type=int, default=3, choices=range(4),
                   help="aPLib effort 0..3 (0 is ~18x faster, ~3%% larger)")
    b.set_defaults(func=cmd_build)

    args = ap.parse_args()
    if args.cmd == "build" and args.hue is None and not args.rgb and not args.flag:
        ap.error("build needs --flag <preset>, --hue <name> and/or --rgb R,G,B")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
