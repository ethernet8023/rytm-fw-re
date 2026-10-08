#!/usr/bin/env python3
"""Scan the WHOLE program for MMIO references (0xec000000-0xffffffff) and cluster by 64KB block.
Display flush must write to some panel bus; find ranges we haven't accounted for."""
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

def addr(x):
    return af.getAddress(hex(x)[2:])

from collections import defaultdict
blocks = defaultdict(lambda: {"fns": set(), "refs": 0})

lo = addr(0xec000000)
hi = addr(0xffffffff)

it = refmgr.getReferenceSourceIterator(program.getMinAddress(), True)
for fa in it:
    for ref in refmgr.getReferencesFrom(fa):
        ta = ref.getToAddress()
        if ta is None:
            continue
        off = ta.getOffset()
        if 0xec000000 <= off <= 0xffffffff:
            fn = fm.getFunctionContaining(fa)
            fnid = fn.getEntryPoint().getOffset() if fn else 0
            key = off & 0xffff0000
            blocks[key]["fns"].add(fnid)
            blocks[key]["refs"] += 1

print("=== MMIO 64KB blocks (block, #refs, #fns, sample fns) ===")
for k in sorted(blocks):
    b = blocks[k]
    fns = sorted(b["fns"])
    print(f"0x{k:08x}  refs={b['refs']:4d} fns={len(fns):3d}  e.g. {[hex(f) for f in fns[:8]]}")
