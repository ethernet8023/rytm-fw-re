#!/usr/bin/env python3
"""Find data refs to 0x400c6a42 and 0x400d2e86 — the view callback registration points.
Then dump the table around the data-ref location to find the view dispatch table."""
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

for t in (0x400c6a42, 0x400d2e86, 0x400584fe, 0x40037a56):
    print(f"=== refs to 0x{t:08x} ===")
    for ref in refmgr.getReferencesTo(addr(t)):
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        print(f"  from 0x{fa.getOffset():08x} type={rt}")
