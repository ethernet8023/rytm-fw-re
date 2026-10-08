#!/usr/bin/env python3
"""Decompile 0x40095bb4 (likely panel init cmd sequence) and 0x40095b74 (LED pos helper)."""
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

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
mon = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(program)

def ensure(ep):
    fn = fm.getFunctionAt(addr(ep))
    if fn is not None:
        return fn
    DisassembleCommand(addr(ep), None, True).applyTo(program, mon)
    try:
        return fm.createFunction(f"fn_{ep:x}", None, addr(ep), AddressSet(addr(ep)), SourceType.USER_DEFINED)
    except Exception as e:
        print(f"// cannot create {hex(ep)}: {e}")
        return None

for ep, label in [(0x40095bb4, "panel init sequence?"), (0x40095b64, "plane user"), (0x40095b74, "led helper")]:
    fn = ensure(ep)
    if fn is None:
        print(f"// NO FN {hex(ep)}")
        continue
    res = ifc.decompileFunction(fn, 120, mon)
    print(f"// ===== {hex(ep)} {label} =====")
    print(res.getDecompiledFunction().getC()[:4500] if res.decompileCompleted() else res.getErrorMessage())
    cl = sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None))
    print(f"// callers: {[hex(c) for c in cl]}\n")
