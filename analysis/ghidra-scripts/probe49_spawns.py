#!/usr/bin/env python3
"""Find the event PRODUCER: fns that write event+0xc (key code) and +0x10 (flags).
Approach: scan all functions for stores to offset 0xc AND 0x10 of the same base
register with small immediates, or callers of pool/queue helpers that feed
FUN_40071f90's readers. Also: find who calls FUN_4000227c (task spawn) with fns
we haven't identified — full inventory of kernel tasks."""
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

def addr(x):
    return af.getAddress(hex(x)[2:])

# 1. full inventory: all call sites of the task spawner FUN_4000227c + the arg fn
print("=== all task spawns (calls of FUN_4000227c) ===")
for ref in refmgr.getReferencesTo(addr(0x4000227c)):
    if not ref.getReferenceType().isCall():
        continue
    ca = ref.getFromAddress()
    fn = fm.getFunctionContaining(ca)
    # dump 12 preceding instructions to find the fn-ptr argument
    insns = list(listing.getInstructions(ca, False))[:14]
    fn_arg = None
    for ins in insns:
        s = str(ins)
        if "pea" in s or ("move.l" in s and "#0x4" in s):
            pass
    print(f"\n--- spawn call at 0x{ca.getOffset():08x} in {'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'} ---")
    for ins in reversed(insns):
        print(f"  0x{ins.getAddress().getOffset():08x}  {ins}")
