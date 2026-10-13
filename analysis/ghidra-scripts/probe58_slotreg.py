#!/usr/bin/env python3
"""Find writers of the 8-slot callback array 0x42f67b64 (each = 4 bytes) and
the pending bitmap 0x42f67b50 (clear side) — registrations reveal what the
slots ARE. Refs to 0x42f67b50..0x42f67b84."""
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

for t in range(0x42f67b50, 0x42f67b90, 4):
    refs = list(refmgr.getReferencesTo(addr(t)))
    if not refs:
        continue
    print(f"=== 0x{t:08x} ===")
    for ref in refs:
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        ins = listing.getInstructionAt(fa)
        print(f"  0x{fa.getOffset():08x} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}: {ins}")
