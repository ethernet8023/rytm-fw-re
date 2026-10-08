#!/usr/bin/env python3
"""Probe 1: find callers of the blit fn 0x400716e0 and callers-of-callers.
The top-level caller likely owns the screen bitmap + calls flush after drawing."""
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

def callers_of(ep):
    fn = fm.getFunctionAt(addr(ep))
    if fn is None:
        return []
    return sorted(c.getEntryPoint().getOffset() for c in fn.getCallingFunctions(None))

BLIT = 0x400716e0
l1 = callers_of(BLIT)
print(f"=== L1 callers of blit 0x{BLIT:08x}: {len(l1)}")
for c in l1:
    print(f"  0x{c:08x}")

print("\n=== L2 (callers of L1) ===")
seen = set()
for c in l1:
    l2 = callers_of(c)
    tag = "" if l2 else "  <- NO CALLERS (maybe task/called via ptr)"
    print(f"L1 0x{c:08x} <- {len(l2)} callers: {[hex(x) for x in l2]}{tag}")
    for x in l2:
        seen.add(x)
print(f"\nL2 union: {sorted(hex(x) for x in seen)}")

# also: does anything reference these L1 fns via a pointer in DATA (task table)?
from ghidra.program.model.symbol import RefType
print("\n=== data references TO L1/L2 (possible task-table pointers) ===")
for c in l1 + sorted(seen):
    for ref in refmgr.getReferencesTo(addr(c)):
        rt = ref.getReferenceType()
        if rt.isData() or str(rt) == "DATA":
            print(f"  0x{c:08x} referenced as DATA from 0x{ref.getFromAddress().getOffset():08x} type={rt}")
