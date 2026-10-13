#!/usr/bin/env python3
"""Build one flashable .syx with every mod applied.

Each mod is a function that patches the section-3 image in place, so combining
them is just calling them in a row and wrapping once - one flash cycle per
build, and the mods cannot disagree about which base image they patched.

    python3 scripts/build_mod.py --sweep-hue cyan --out RytmFW-mod.syx
    python3 scripts/build_mod.py --no-splash --sweep-rgb 255,90,0
    python3 scripts/build_mod.py --splash-dir extracted/splash --sweep-hue white

Splash bitmaps default to extracted/splash (extract rewrites them from whatever
image you point it at); --no-splash leaves section 3's splash art stock.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import fwpatch
import led_sweep
import splash_bmp

REPO = fwpatch.REPO


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--section", default=str(fwpatch.DEFAULT_SECTION),
                    help="unwrapped section 3 bin (default: %(default)s)")
    ap.add_argument("--syx", help="read section 3 straight out of a .syx instead")
    ap.add_argument("--syx-in", default=str(fwpatch.STOCK_SYX),
                    help="container to patch (default: %(default)s)")
    ap.add_argument("--splash-dir", default=str(REPO / "extracted" / "splash"))
    ap.add_argument("--no-splash", dest="splash", action="store_false",
                    help="leave the splash bitmaps stock")
    ap.add_argument("--sweep-hue", type=led_sweep.hue_value,
                    help=f"recolour the LED sweep: {', '.join(led_sweep.HUE_NAMES)} or 0..6")
    ap.add_argument("--sweep-flag", choices=("trans", led_sweep.FLAG_STOCK_HUES),
                    help="named sweep preset (see led_sweep.py)")
    ap.add_argument("--sweep-rgb", help="custom sweep ramp as R,G,B (0..255 each)")
    ap.add_argument("--out", default=str(REPO / "RytmFW-mod.syx"))
    ap.add_argument("--out-bin", help="write just the patched section bin, no wrap")
    ap.add_argument("--version", help="override the container version string")
    ap.add_argument("-l", "--level", type=int, default=3, choices=range(4),
                    help="aPLib effort 0..3 (0 is ~18x faster, ~3%% larger)")
    args = ap.parse_args()

    stock = fwpatch.load_section(args.section, args.syx)
    image = bytearray(stock)

    if args.splash:
        splash_bmp.apply_bmps(image, Path(args.splash_dir))
    if args.sweep_flag:
        led_sweep.apply_flag(image, args.sweep_flag)
    if args.sweep_hue is not None:
        led_sweep.apply_hue(image, args.sweep_hue)
    if args.sweep_rgb:
        led_sweep.apply_rgb(image, tuple(int(x) for x in args.sweep_rgb.split(",")))  # type: ignore[arg-type]

    total = sum(1 for a, b in zip(stock, image) if a != b)
    print(f"mods changed {total} bytes of section 3:")
    for lo, hi, n in fwpatch.diff_ranges(stock, bytes(image)):
        print(f"  0x{lo:08x}..0x{hi - 1:08x}  ({n} bytes)")

    if args.out_bin:
        Path(args.out_bin).write_bytes(image)
        print(f"patched section bin -> {args.out_bin} (no .syx wrapped)")
        return 0
    if total == 0:
        print("nothing changed - refusing to build a pointlessly identical image")
        return 1
    ok = fwpatch.wrap_and_verify(image, args.out, args.syx_in, args.level, args.version)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
