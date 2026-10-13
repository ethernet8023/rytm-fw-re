#!/usr/bin/env python3
"""Shared plumbing for firmware mods: load section 3, patch bytes in place,
wrap into a flashable .syx, and verify the result.

A mod is just a function that mutates the section-3 image in place (all the
mods found so far - splash bitmaps, LED palette/sweep - are same-size static
data swaps, so no relocation or checksum work is needed inside the section).

Verification is not optional and not decorative: it re-extracts section 3 from
the built .syx and compares it to the patched image, then checks the container's
section table (offsets 16-byte aligned, next_off == align16(off+clen)). That
catches format drift at build time instead of on a unit with one USB shot left.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
IMAGE_BASE = 0x40000400
SECTION_ID = 3
CONTAINER_ALIGN = 16
DEFAULT_SECTION = REPO / "extracted" / "section_3_MAIN_OS.bin"
STOCK_SYX = REPO / "Analog-Rytm_MKII_OS1.74.syx"
TOOL = REPO / "elektron-firmware-tool" / "elektron-firmware-tool"
BUILD_DIR = REPO / "firmware" / "build"


def require_tool() -> None:
    if not TOOL.exists():
        raise SystemExit(
            f"{TOOL} missing - build it:\n"
            "  cd elektron-firmware-tool && nix shell nixpkgs#gcc -c bash -c "
            "'gcc -std=c11 -O2 -Wall -Wextra -o elektron-firmware-tool *.c'")


def load_section(section: Path | str | None = None, syx: Path | str | None = None) -> bytes:
    """Section 3 bytes, either from an unwrapped bin or straight out of a .syx."""
    if syx:
        require_tool()
        with tempfile.TemporaryDirectory() as td:
            subprocess.run([str(TOOL), "-i", str(syx), "-d", str(SECTION_ID), "-o", td],
                           check=True, capture_output=True)
            hits = list(Path(td).glob("*.bin"))
            if not hits:
                raise SystemExit(f"no section {SECTION_ID} came out of {syx}")
            return hits[0].read_bytes()
    path = Path(section or DEFAULT_SECTION)
    if not path.exists():
        raise SystemExit(f"{path} missing - pass --syx or unwrap the stock .syx first")
    return path.read_bytes()


def slice_of(image: bytes | bytearray, addr: int, n: int) -> bytes:
    off = addr - IMAGE_BASE
    if off < 0 or off + n > len(image):
        raise SystemExit(f"0x{addr:08x}+{n} is outside the {len(image)}B image "
                         f"(image covers 0x{IMAGE_BASE:08x}..0x{IMAGE_BASE + len(image):08x})")
    return bytes(image[off:off + n])


def patch(image: bytearray, addr: int, data: bytes) -> None:
    off = addr - IMAGE_BASE
    if off < 0 or off + len(data) > len(image):
        raise SystemExit(f"patch 0x{addr:08x}+{len(data)} is outside the image")
    image[off:off + len(data)] = data


def diff_ranges(stock: bytes, patched: bytes, limit: int = 8,
                merge_gap: int = 8) -> list[tuple[int, int, int]]:
    """[(start_addr, end_addr_exclusive, changed_count)] for changed regions.

    Runs separated by fewer than merge_gap untouched bytes are reported as one
    region: a table edit touches scattered bytes, and 30 single-byte rows is
    noise, not information.
    """
    runs: list[list[int]] = []
    i, n = 0, min(len(stock), len(patched))
    while i < n:
        if stock[i] != patched[i]:
            j = i
            while j < n and stock[j] != patched[j]:
                j += 1
            runs.append([i, j])
            i = j
        else:
            i += 1
    merged: list[list[int]] = []
    for run in runs:
        if merged and run[0] - merged[-1][1] < merge_gap:
            merged[-1][1] = run[1]
        else:
            merged.append(run)
    out = []
    for start, end in merged[:limit]:
        changed = sum(1 for k in range(start, end) if stock[k] != patched[k])
        out.append((IMAGE_BASE + start, IMAGE_BASE + end, changed))
    return out


def wrap_and_verify(image: bytes | bytearray, out_syx: Path | str,
                    syx_in: Path | str | None = None,
                    level: int = 3, version: str | None = None,
                    patched_bin: Path | str | None = None, verbose: bool = True) -> bool:
    """Patch section 3 into a copy of the stock .syx, then prove the result."""
    require_tool()
    out_syx = Path(out_syx)
    src = Path(syx_in or STOCK_SYX)
    if not src.exists():
        raise SystemExit(f"{src} missing - that is the container we patch")
    if patched_bin is None:
        BUILD_DIR.mkdir(parents=True, exist_ok=True)
        patched_bin = BUILD_DIR / "section_3_mod.bin"
    Path(patched_bin).write_bytes(image)

    cmd = [str(TOOL), "-i", str(src), "-c", str(SECTION_ID), str(patched_bin),
           "-l", str(level), "-o", str(out_syx)]
    if version:
        cmd[1:1] = ["-V", version]
    subprocess.run(cmd, check=True)
    if verbose:
        print(f"wrote {out_syx} ({out_syx.stat().st_size}B) from {src}")

    with tempfile.TemporaryDirectory() as td:
        subprocess.run([str(TOOL), "-i", str(out_syx), "-d", str(SECTION_ID), "-o", td],
                       check=True, capture_output=True)
        hits = list(Path(td).glob("*.bin"))
        back = hits[0].read_bytes() if hits else b""
    if back != image:
        print(f"verify: FAILED - re-extracted section {SECTION_ID} differs "
              f"({len(back)}B vs {len(image)}B)", file=sys.stderr)
        return False
    if verbose:
        print(f"verify: re-extracted section {SECTION_ID} is byte-identical to the "
              f"patched bin ({len(back)}B) - patch round-trips")

    report = subprocess.run([str(TOOL), "-i", str(out_syx), "-v"],
                            check=True, capture_output=True, text=True).stdout
    rows: list[tuple[int, int, int]] = []
    for line in report.splitlines():
        m = re.search(r"id=(\d+)\s+.*?off=0x([0-9a-f]+)\s+clen=0x([0-9a-f]+)", line)
        if m:
            rows.append((int(m.group(1)), int(m.group(2), 16), int(m.group(3), 16)))
    for i, (sid, off, clen) in enumerate(rows):
        if off % CONTAINER_ALIGN:
            print(f"container: FAIL section {sid} off=0x{off:x} is not "
                  f"{CONTAINER_ALIGN}-byte aligned", file=sys.stderr)
            return False
        if i + 1 < len(rows):
            nxt = rows[i + 1][1]
            want = (off + clen + CONTAINER_ALIGN - 1) // CONTAINER_ALIGN * CONTAINER_ALIGN
            if nxt != want:
                print(f"container: FAIL section {sid} off+clen does not align up to the "
                      f"next section (0x{off + clen:x} -> 0x{nxt:x})", file=sys.stderr)
                return False
    print(f"container: {len(rows)} sections, all {CONTAINER_ALIGN}-byte aligned with "
          f"next_off == align{CONTAINER_ALIGN}(off+clen) [ok]")
    return True
