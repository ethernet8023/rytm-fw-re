#!/usr/bin/env python3
"""Bootstrap flash-writer hunt, step 1: full MMIO + function census of
section_2_bootstrap.bin (base 0x80000000). The bootstrap contains the whole
flash read/write path; its peripheral footprint is tiny compared to MAIN OS.

Deliverables from this probe:
- every function (entry, size)
- every MMIO 64KB block referenced (0xec0/0xfc0 ranges) + which fns touch them
- SRAM-window references (0x8000xxxx) cluster

Flash controller candidates: DSPI 0xfc05cxxx (SPI NOR), eSDHC 0xfc0ccxxx,
anything new in 0xec0xxxxx (FPGA bridges).
"""
import os
# GHIDRA_INSTALL_DIR gets patched at runtime by the wrapper; default last-known
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_2_bootstrap.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()

def addr(x):
    return af.getAddress(hex(x)[2:])

print("=== functions (entry, size) ===")
fns = []
for f in fm.getFunctions(True):
    body = f.getBody()
    fns.append((f.getEntryPoint().getOffset(), body.getNumAddresses(), f.getName()))
print(f"count={len(fns)}")
for e, sz, n in fns:
    print(f"  0x{e:08x}  {sz:5d}  {n}")

from collections import defaultdict
blocks = defaultdict(lambda: {"fns": set(), "refs": 0})

it = refmgr.getReferenceSourceIterator(program.getMinAddress(), True)
for fa in it:
    for ref in refmgr.getReferencesFrom(fa):
        ta = ref.getToAddress()
        if ta is None:
            continue
        off = ta.getOffset()
        if (0xec000000 <= off <= 0xffffffff) or (0x80000000 <= off <= 0x8000ffff):
            fn = fm.getFunctionContaining(fa)
            fnid = fn.getEntryPoint().getOffset() if fn else 0
            key = off & 0xffff0000
            blocks[key]["fns"].add(fnid)
            blocks[key]["refs"] += 1

print("=== MMIO/SRAM 64KB blocks (block, #refs, #fns, fn list) ===")
for k in sorted(blocks):
    b = blocks[k]
    fl = sorted(b["fns"])
    print(f"0x{k:08x}  refs={b['refs']:4d} fns={len(fl):3d}  {[hex(f) for f in fl]}")

project.close()
print("done")
