#!/usr/bin/env python3
"""Bootstrap flash hunt, step 4: raw disasm surgery on the regions where
ghidra's auto-boundaries lied:
- FUN_80005d66's full body (the upgrade fn) — read the REAL jsr targets of
  the erase + program loops and the exact constants
- the swallowed cluster 0x80002d30-0x80003170 (menu loop swallowed the ID
  readers + erase fn)
"""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/hcbfjkvrc2lk0bzhv9b4yv7rrmc8qsmh-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject

project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_2_bootstrap.bin", False)

af = program.getAddressFactory()
listing = program.getListing()

def addr(x):
    return af.getAddress(hex(x)[2:])

def dump(lo, hi, tag):
    print(f"\n===== {tag} 0x{lo:08x}-0x{hi:08x} =====")
    a = addr(lo)
    end = addr(hi)
    ins = listing.getInstructionAt(a)
    # walk instructions only
    it = listing.getInstructions(a, True)
    for ins in it:
        if ins.getAddress().getOffset() > hi:
            break
        print(f"0x{ins.getAddress().getOffset():08x}  {ins}")

dump(0x80005d66, 0x800061d0, "FUN_80005d66 upgrade fn, full")
dump(0x80002d30, 0x80002e60, "swallowed cluster: erase + ID readers")

project.close()
print("done")
