#!/usr/bin/env python3
"""Trace the frame/UI queue cluster: who references 0x4191b6e8 (frame queue) and
0x4191bb6c/0x4191bb70 (progress values)? Decompile the frame task FUN_40095796's
neighbors: who wakes it, and what global holds the ACTIVE VIEW?"""
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

for t in (0x4191b6e8, 0x4191baf8, 0x4191bb6c):
    print(f"=== refs to 0x{t:08x} ===")
    for ref in refmgr.getReferencesTo(addr(t)):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        ins = listing.getInstructionAt(fa)
        print(f"  0x{fa.getOffset():08x} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else 'DATA@0x%08x' % fa.getOffset()}: {ins}")
    print()
