#!/usr/bin/env python3
"""For every call site of the ring pumper FUN_400019e4, dump preceding instructions
to find the length argument (looking for 0x400 = 1024 = framebuffer size)."""
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
refmgr = program.getReferenceManager()

def addr(x):
    return af.getAddress(hex(x)[2:])

print("=== call sites of ring pumper 0x400019e4 ===")
for ref in refmgr.getReferencesTo(addr(0x400019e4)):
    if not ref.getReferenceType().isCall():
        continue
    ca = ref.getFromAddress()
    fn = fm.getFunctionContaining(ca)
    fname = f"FUN_{fn.getEntryPoint().getOffset():08x}" if fn else "?"
    print(f"\n--- 0x{ca.getOffset():08x} in {fname} ---")
    insns = list(listing.getInstructions(ca, False))[:12]
    for ins in reversed(insns):
        print(f"  0x{ins.getAddress().getOffset():08x}  {ins}")
