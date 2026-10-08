#!/usr/bin/env python3
"""Who references ec07 channel state globals 0x413da6a0..0x413da6e0 (ring buffer state)?"""
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

targets = [0x413da6a0, 0x413da6a4, 0x413da6a8, 0x413da6ac, 0x413da6b0,
           0x413da6b4, 0x413da6b8, 0x413da6bc, 0x413da6c0, 0x413da6c4,
           0x413da6c8, 0x413da6cc, 0x413da6d0, 0x413da6e0]
for t in targets:
    refs = list(refmgr.getReferencesTo(addr(t)))
    if not refs:
        continue
    print(f"=== 0x{t:08x} ===")
    for ref in refs:
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        fname = f"FUN_{fn.getEntryPoint().getOffset():08x}" if fn else "?"
        ins = listing.getInstructionAt(fa)
        print(f"  0x{fa.getOffset():08x} [{fname}]: {ins}")
