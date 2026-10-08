#!/usr/bin/env python3
"""Decompile task-entry candidate 0x40100a94 + kernel helpers 0x40000de4/0x40000e30."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()

def addr(x):
    return af.getAddress(hex(x)[2:])

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface()
ifc.openProgram(program)

def dump(ep, label="", depth=0):
    fn = fm.getFunctionAt(addr(ep))
    if fn is None:
        print(f"// no fn at {hex(ep)} {label}")
        return
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())

dump(0x40100a94, "task entry candidate")
dump(0x40000de4, "kernel task-create helper")
dump(0x40000e30, "kernel task-start helper")
