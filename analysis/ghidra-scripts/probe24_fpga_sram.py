#!/usr/bin/env python3
"""Scan raw binary for 4-byte BE values 0x80000000-0x8000ffff (FPGA SRAM addresses)
embedded in code, and report which functions contain them."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
listing = program.getListing()

BASE = 0x40000400
data = open("extracted/section_3_MAIN_OS.bin", "rb").read()

from collections import defaultdict
hits = defaultdict(set)

for off in range(0, len(data) - 3):
    b = data[off]
    if b != 0x80 or data[off+1] != 0x00:
        continue
    val = int.from_bytes(data[off:off+4], "big")
    if 0x80000000 <= val < 0x80010000:
        addr_va = BASE + off
        fn = fm.getFunctionContaining(af.getAddress(hex(addr_va)[2:]))
        fnid = fn.getEntryPoint().getOffset() if fn else 0
        hits[val].add(fnid)

print("=== FPGA SRAM addresses referenced, grouped ===")
for val in sorted(hits):
    fns = sorted(hits[val])
    print(f"0x{val:08x}: {len(fns)} fns  {[hex(f) if f else '?' for f in fns[:12]]}")

# aggregate per function
from collections import Counter
per_fn = Counter()
for val in hits:
    for f in hits[val]:
        per_fn[f] += 1
print("\n=== functions by #distinct 0x8000xxxx refs ===")
for f, n in per_fn.most_common(25):
    print(f"  {'?' if f==0 else hex(f)}: {n}")
