#!/usr/bin/env python3
"""Decompile a list of functions from the rytm174 ghidra project."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

ifc = DecompInterface()
ifc.openProgram(program)

targets = [0x4013d200, 0x400584fe, 0x4013d9c0]
af = program.getAddressFactory()
fm = program.getFunctionManager()
for t in targets:
    a = af.getAddress(hex(t)[2:])
    fn = fm.getFunctionAt(a)
    if fn is None:
        print(f"// no function at {hex(t)}")
        continue
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(t)} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())