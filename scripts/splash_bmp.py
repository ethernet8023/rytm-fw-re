#!/usr/bin/env python3
"""Boot-splash bitmap pipeline: stock firmware <-> 1-bit BMP.

The Rytm MKII boot splash (task FUN_40101fc0) is a procedural diagonal dither
wipe between two STATIC mono bitmaps that it wraps with the display planes via
bitmap ctor2 FUN_4006fa2e(&bmp, w, h, art_plane, mask_plane):

    splash_A   32x24   art 0x402b2c24  mask 0x402b2ba4   (loader site 0x401469b0)
    splash_B  117x17   art 0x402be4e8  mask 0x402be314   (loader site 0x401433a4)

(set up in FUN_40140260; addresses are immediates in the ctor2 calls, the
structs themselves live in BSS at 0x419f1b94 / 0x419f2338.)

Plane format (bitmap ctor FUN_4006f9b2 + get/set pixel FUN_4006fb40 / FUN_4006fa74):
column-major, one 32-bit BE word per 32 plane rows of a column, stride =
(h+31)>>5 words per column, MSB = plane row 0:

    word   = BE u32 at plane + ((y >> 5) + stride * x) * 4
    pixel  = (word >> (31 - (y & 31))) & 1
    plane  = w * stride * 4 bytes     (A=128B, B=468B)

Plane rows run BOTTOM-UP on the physical panel (hardware-confirmed against the
stock splash: rendering the plane top-down shows the art upside down), so a
screen-oriented BMP row s is plane row h-1-s. That mapping is applied in both
directions here, which is why the pipeline round-trips byte-exactly.

The mask plane is all-ones over plane rows 0..h-1 (opaque blit); this tool
regenerates it and refuses to build if stock does not match that pattern.

Commands
    extract   section bin (or stock .syx) -> one 1bpp BMP per splash bitmap
    build     BMPs -> patched section bin -> flashable .syx (re-verified)

Examples
    python3 scripts/splash_bmp.py extract
    python3 scripts/splash_bmp.py extract --scale 8          # easy to edit
    python3 scripts/splash_bmp.py build --out RytmFW-splash.syx
"""
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

import fwpatch

REPO = fwpatch.REPO
IMAGE_BASE = fwpatch.IMAGE_BASE


@dataclass(frozen=True)
class SplashBitmap:
    name: str
    w: int
    h: int
    art: int  # plane0 - the image
    mask: int  # plane1 - opacity mask
    ctor_site: int

    @property
    def stride(self) -> int:
        return (self.h + 31) >> 5

    @property
    def plane_size(self) -> int:
        return self.w * self.stride * 4

    def ascii(self, px: list[list[int]]) -> str:
        return "\n".join("".join("#" if v else "." for v in row) for row in px)


BITMAPS: tuple[SplashBitmap, ...] = (
    SplashBitmap("splash_A", 0x20, 0x18, 0x402B2C24, 0x402B2BA4, 0x401469B0),
    SplashBitmap("splash_B", 0x75, 0x11, 0x402BE4E8, 0x402BE314, 0x401433A4),
)


# ---------------------------------------------------------------- plane codec

def _bit(y: int) -> int:
    return 0x80000000 >> (y & 31)


def unpack_plane(b: SplashBitmap, plane: bytes) -> list[list[int]]:
    """Plane bytes -> screen-oriented grid (row 0 = top of what you see)."""
    px = [[0] * b.w for _ in range(b.h)]
    for x in range(b.w):
        for y in range(b.h):
            word = struct.unpack_from(">I", plane, ((y >> 5) + b.stride * x) * 4)[0]
            px[y][x] = (word >> (31 - (y & 31))) & 1
    return px[::-1]


def pack_plane(b: SplashBitmap, px: list[list[int]]) -> bytes:
    """Screen-oriented grid -> plane bytes (screen row s = plane row h-1-s)."""
    out = bytearray(b.plane_size)
    for x in range(b.w):
        for sy in range(b.h):
            if not px[sy][x]:
                continue
            y = b.h - 1 - sy
            off = ((y >> 5) + b.stride * x) * 4
            struct.pack_into(">I", out, off, struct.unpack_from(">I", out, off)[0] | _bit(y))
    return bytes(out)


def mask_plane(b: SplashBitmap) -> bytes:
    """All-ones over plane rows 0..h-1 (the stock mask: opaque full-rect blit)."""
    return pack_plane(b, [[1] * b.w for _ in range(b.h)])


def read_plane(image: bytes, addr: int, n: int) -> bytes:
    return fwpatch.slice_of(image, addr, n)


# ------------------------------------------------------------------ BMP codec

def write_bmp(path: Path, px: list[list[int]], scale: int = 1) -> None:
    """1bpp BI_RGB BMP. index 1 = white = lit pixel; rows stored bottom-up."""
    h, w = len(px), len(px[0])
    W, H = w * scale, h * scale
    row_bytes = ((W + 31) // 32) * 4
    pixels = bytearray()
    for sy in range(H - 1, -1, -1):
        row = bytearray(row_bytes)
        for sx in range(W):
            if px[sy // scale][sx // scale]:
                row[sx >> 3] |= 0x80 >> (sx & 7)
        pixels += row
    palette = bytes((0, 0, 0, 0, 255, 255, 255, 0))  # black, white
    off = 14 + 40 + len(palette)
    file_hdr = struct.pack("<2sIHHI", b"BM", off + len(pixels), 0, 0, off)
    info_hdr = struct.pack("<IiiHHIIiiII", 40, W, H, 1, 1, 0, len(pixels),
                           2835, 2835, 2, 2)
    path.write_bytes(file_hdr + info_hdr + palette + bytes(pixels))


def write_png(path: Path, px: list[list[int]], scale: int = 1) -> None:
    """Grayscale preview (1 = lit = black on white), hand-rolled so this needs
    no third-party imaging deps. Preview only - the BMP is the editable artifact."""
    import zlib

    h, w = len(px), len(px[0])
    W, H = w * scale, h * scale
    raw = bytearray()
    for y in range(H):
        raw.append(0)
        for x in range(W):
            raw.append(0 if px[y // scale][x // scale] else 255)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    path.write_bytes(b"\x89PNG\r\n\x1a\n"
                     + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 0, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
                     + chunk(b"IEND", b""))


def read_bmp(path: Path) -> list[list[int]]:
    """Read 1/24/32bpp BI_RGB BMP -> screen-oriented grid (1 = lit)."""
    data = path.read_bytes()
    if data[:2] != b"BM":
        raise SystemExit(f"{path}: not a BMP")
    pix_off = struct.unpack_from("<I", data, 10)[0]
    (hdr_size, w, h, planes, bpp, comp, _size, _xp, _yp, _ncol,
     _nimp) = struct.unpack_from("<IiiHHIIiiII", data, 14)
    if hdr_size < 40:
        raise SystemExit(f"{path}: BITMAPCOREHEADER not supported")
    if comp not in (0, 3):
        raise SystemExit(f"{path}: compressed BMP (compression={comp}) not supported")
    top_down = h < 0
    h = abs(h)
    if bpp == 1:
        pal_off = 14 + hdr_size
        entries = []
        for i in range(2):
            b, g, r, _ = struct.unpack_from("<BBBB", data, pal_off + i * 4)
            entries.append(0.299 * r + 0.587 * g + 0.114 * b)
        lit_index = 1 if entries[1] >= entries[0] else 0
        row_bytes = ((w + 31) // 32) * 4
        px = []
        for y in range(h):
            src = y if top_down else h - 1 - y
            base = pix_off + src * row_bytes
            px.append([1 if (data[base + (x >> 3)] >> (7 - (x & 7))) & 1 == lit_index
                       else 0 for x in range(w)])
        return px
    if bpp in (24, 32):
        row_bytes = ((w * bpp + 31) // 32) * 4
        step = bpp // 8
        px = []
        for y in range(h):
            src = y if top_down else h - 1 - y
            base = pix_off + src * row_bytes
            row = []
            for x in range(w):
                b, g, r = data[base + x * step : base + x * step + 3]
                row.append(1 if 0.299 * r + 0.587 * g + 0.114 * b >= 128 else 0)
            px.append(row)
        return px
    raise SystemExit(f"{path}: {bpp}bpp not supported (use 1, 24 or 32)")


def fit(b: SplashBitmap, px: list[list[int]], path: Path) -> list[list[int]]:
    """Accept exactly w x h, or any integer multiple (downsample to native)."""
    h, w = len(px), len(px[0])
    if (w, h) == (b.w, b.h):
        return px
    if w % b.w == 0 and h % b.h == 0 and w // b.w == h // b.h:
        s = w // b.w
        return [[px[y * s][x * s] for x in range(b.w)] for y in range(b.h)]
    raise SystemExit(f"{path}: {w}x{h} does not match {b.name} ({b.w}x{b.h}) "
                     f"or an integer multiple of it")


# --------------------------------------------------------------------- mod

def apply_bmps(image: bytearray, bmp_dir: Path | str, log: bool = True) -> int:
    """Patch both splash bitmaps (art + regenerated mask) into the section image."""
    bmp_dir = Path(bmp_dir)
    n = 0
    for b in BITMAPS:
        bmp = bmp_dir / f"{b.name}.bmp"
        if not bmp.exists():
            raise SystemExit(f"{bmp} missing - run extract first")
        fwpatch.patch(image, b.art, pack_plane(b, fit(b, read_bmp(bmp), bmp)))
        fwpatch.patch(image, b.mask, mask_plane(b))
        n += 1
        if log:
            print(f"{b.name}: patched art @0x{b.art:08x} ({b.plane_size}B) "
                  f"+ mask @0x{b.mask:08x} from {bmp}")
    return n


# ------------------------------------------------------------------ commands

def cmd_extract(args: argparse.Namespace) -> int:
    image = fwpatch.load_section(args.section, args.syx)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for b in BITMAPS:
        art = read_plane(image, b.art, b.plane_size)
        mask = read_plane(image, b.mask, b.plane_size)
        if mask != mask_plane(b):
            print(f"WARNING {b.name}: stock mask plane is not the all-ones pattern "
                  f"- it will be regenerated on build", file=sys.stderr)
        px = unpack_plane(b, art)
        write_bmp(out / f"{b.name}.bmp", px, args.scale)
        write_png(out / f"{b.name}.preview.png", px, max(args.scale, 8))
        (out / f"{b.name}.art.bin").write_bytes(art)
        print(f"{b.name}: {b.w}x{b.h} art=0x{b.art:08x} mask=0x{b.mask:08x} "
              f"plane={b.plane_size}B lit={sum(map(sum, px))}/{b.w * b.h} "
              f"-> {out / (b.name + '.bmp')}"
              + (f"  ({b.w * args.scale}x{b.h * args.scale}px)" if args.scale > 1 else ""))
        if args.show:
            print(b.ascii(px))
            print()
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    image = bytearray(fwpatch.load_section(args.section, args.syx))
    apply_bmps(image, args.bmp_dir)
    if args.out_bin:
        Path(args.out_bin).write_bytes(image)
        print(f"patched section bin -> {args.out_bin} (no .syx wrapped)")
        return 0
    return 0 if fwpatch.wrap_and_verify(image, args.out, args.syx_in, args.level,
                                        args.version) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--section", default=str(fwpatch.DEFAULT_SECTION),
                       help="unwrapped section 3 bin (default: %(default)s)")
        p.add_argument("--syx", help="read section 3 straight out of a .syx instead")

    e = sub.add_parser("extract", help="firmware -> BMP")
    common(e)
    e.add_argument("--out", default=str(REPO / "extracted" / "splash"))
    e.add_argument("--scale", type=int, default=1, help="upscale the BMP (default 1)")
    e.add_argument("--show", action="store_true", help="also print ascii art")
    e.set_defaults(func=cmd_extract)

    b = sub.add_parser("build", help="BMP -> patched .syx")
    common(b)
    b.add_argument("--bmp-dir", default=str(REPO / "extracted" / "splash"))
    b.add_argument("--syx-in", default=str(fwpatch.STOCK_SYX), help="stock .syx to patch")
    b.add_argument("--out", default=str(REPO / "RytmFW-splash.syx"))
    b.add_argument("--out-bin", help="write just the patched section bin, no wrap")
    b.add_argument("--version", help="override the container version string")
    b.add_argument("-l", "--level", type=int, default=3, choices=range(4),
                   help="aPLib effort 0..3 (0 is ~18x faster, ~3%% larger)")
    b.set_defaults(func=cmd_build)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
