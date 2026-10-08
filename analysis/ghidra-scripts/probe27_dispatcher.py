#!/usr/bin/env python3
"""Decompile FUN_40039782 (called by both popup dispatchers before drawing).
Find who reads the view tables (0x401cc404, 0x401e15a0) = the UI dispatcher."""
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

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface()
ifc.openProgram(program)
mon = ConsoleTaskMonitor()

fn = fm.getFunctionAt(addr(0x40039782))
if fn:
    res = ifc.decompileFunction(fn, 120, mon)
    print("// ===== 0x40039782 =====")
    print(res.getDecompiledFunction().getC() if res.decompileCompleted() else res.getErrorMessage())

for t in (0x401cc404, 0x401e15a0, 0x401d2134):
    print(f"\n=== refs to view-table entry {hex(t)} ===")
    for ref in refmgr.getReferencesTo(addr(t)):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        fname = f"FUN_{fn.getEntryPoint().getOffset():08x}" if fn else "?"
        ins = listing.getInstructionAt(fa)
        print(f"  0x{fa.getOffset():08x} [{fname}] {ref.getReferenceType()}: {ins}")
