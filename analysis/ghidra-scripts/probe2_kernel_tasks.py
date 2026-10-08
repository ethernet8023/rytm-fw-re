#!/usr/bin/env python3
"""Probe 2: decompile kernel bring-up 0x40100b12 + list callees (task starts).
Then dump fns referencing 0xfc03c000 (DMA) — probe 3 targets."""
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

def dump(ep, label=""):
    fn = fm.getFunctionAt(addr(ep))
    if fn is None:
        print(f"// no function at {hex(ep)}")
        return
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())

# bring-up fn
dump(0x40100b12, "kernel bring-up")

# callees of bring-up
fn = fm.getFunctionAt(addr(0x40100b12))
if fn:
    print("\n// ===== direct callees of 0x40100b12 =====")
    called = fn.getCalledFunctions(None)
    for c in sorted(c.getEntryPoint().getOffset() for c in called):
        print(f"  callee 0x{c:08x}")
