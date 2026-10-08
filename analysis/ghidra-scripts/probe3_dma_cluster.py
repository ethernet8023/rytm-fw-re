#!/usr/bin/env python3
"""Decompile DMA cluster: 0x400054ea, 0x4007a4e4, 0x4007a598, 0x4007a4d6, 0x4011f9e0, 0x40121eca."""
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

for ep, label in [(0x400054ea, "DMA init called by main init task"),
                  (0x4007a4d6, "after init-fn table loop"),
                  (0x4007a4e4, "DMA candidate"),
                  (0x4007a598, "caller of a4e4"),
                  (0x4011f9e0, "called in 0x80-bit-clear branch"),
                  (0x40121eca, "audio+dma mixed"),
                  ]:
    fn = fm.getFunctionAt(addr(ep))
    if fn is None:
        print(f"// ===== {hex(ep)} {label}: NO FN =====")
        continue
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
