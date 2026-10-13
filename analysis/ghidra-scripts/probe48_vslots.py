#!/usr/bin/env python3
"""Decompile remaining base-vtable fns: 40078408, 4007880c, 4007840a, 4007887c,
40078416, 40078422, 40078624, 4007842c, 4007842e/32/36 (arrow handlers!),
400789aa, 400789b6, 400787b2, 400787f0."""
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

for ep, label in [(0x40078408, "slot +0x14"), (0x4007880c, "slot +0x18"), (0x4007840a, "slot +0x1c"),
                  (0x4007887c, "slot +0x20"), (0x40078416, "slot +0x24"), (0x40078422, "slot +0x28"),
                  (0x40078624, "slot +0x2c"), (0x4007842c, "slot +0x30"),
                  (0x4007842e, "slot +0x34 up?"), (0x40078432, "slot +0x38"), (0x40078436, "slot +0x3c"),
                  (0x400789aa, "slot +0x40"), (0x400789b6, "slot +0x44"),
                  (0x400787b2, "slot +0x50"), (0x400787f0, "slot +0x54")]:
    fn = ensure(ep)
    if fn is None:
        print(f"// NO FN {hex(ep)} {label}")
        continue
    res = ifc.decompileFunction(fn, 90, mon)
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        print(c[:1800])
        if len(c) > 1800:
            print(f"... // TRUNC ({len(c)-1800})")
    else:
        print("// fail:", res.getErrorMessage())
    print()
