#!/usr/bin/env python3
"""Memory budget scan v2 (reliable): use ghidra's reference manager — every
memory reference FROM code/data TO DDR 0x40000000-0x4c000000. Bucket per 64KB.
Then report unreferenced 64KB blocks inside the used span, plus the classic
candidates: below 0x40720000 (SRAM load region), above stack region 0x48000000."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
listing = program.getListing()

from collections import Counter
ddr = Counter()

it = refmgr.getReferenceSourceIterator(program.getMinAddress(), True)
n = 0
for fa in it:
    for ref in refmgr.getReferencesFrom(fa):
        to = ref.getToAddress()
        if to is None:
            continue
        off = to.getOffset()
        if 0x40000000 <= off < 0x4c000000:
            ddr[off >> 16] += 1
            n += 1

used = sorted(ddr)
print(f"{n} refs into DDR from {len(used)} 64KB blocks")
print(f"span: 0x{used[0]<<16:08x} - 0x{used[-1]<<16:08x}")

# gap analysis inside span
gaps = []
prev = used[0]
for b in used[1:]:
    if b - prev > 1:
        gaps.append((prev + 1, b - 1))
    prev = b
print("\n== unreferenced gaps >= 64KB inside span ==")
tot = 0
for g in gaps:
    kb = (g[1] - g[0] + 1) * 64
    tot += kb
    print(f"  0x{g[0]<<16:08x} - 0x{(g[1]<<16)+0xffff:08x}  ({kb} KB)")
print(f"total gap bytes: {tot//1024} KB")

# density map of the low 8MB (OS + kernel globals live here)
print("\n== density per 64KB, 0x40000000-0x40800000 ==")
for b in range(0x40000000 >> 16, 0x40800000 >> 16):
    c = ddr.get(b, 0)
    if c:
        print(f"  0x{b<<16:08x}: {c:5d} refs")

# what's above the highest kernel-global-ish block?
hi_used = [b for b in used if b < 0x44000000]
print(f"\nhighest referenced block below 0x44000000: 0x{hi_used[-1]<<16:08x}")
