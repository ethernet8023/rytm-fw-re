#!/usr/bin/env python3
"""Who references the DMA buffer 0x4b80a400 / 0x4b80a000 (ec07 channel) and 0x4b808000/0x4b800000 (ec074)?"""
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

for t in (0x4b80a400, 0x4b80a000, 0x4b808000, 0x4b800000, 0x4b809000, 0x4b80b000):
    print(f"=== references to 0x{t:08x} ===")
    for ref in refmgr.getReferencesTo(addr(t)):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        fname = f"FUN_{fn.getEntryPoint().getOffset():08x}" if fn else "?"
        ins = listing.getInstructionAt(fa)
        print(f"  0x{fa.getOffset():08x} [{fname}] {ref.getReferenceType()}: {ins}")
    print()
