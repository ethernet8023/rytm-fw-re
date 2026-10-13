#!/usr/bin/env python3
"""Clear defined data over the default handlers via the ClearCmd, then disassemble
+ decompile. Ghidra python: use ghidra.app.cmd.data.ClearCmd."""
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
from ghidra.app.cmd.data import ClearCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
mon = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(program)

start, end = addr(0x401d7824), addr(0x401d7880)
cmd = ClearCmd(start, end, False)
cmd.applyTo(program, mon)
DisassembleCommand(start, None, True).applyTo(program, mon)

for ep in (0x401d7824, 0x401d7838, 0x401d784c, 0x401d7860):
    fn = fm.getFunctionAt(addr(ep))
    if fn is None:
        try:
            fn = fm.createFunction(f"dflt_{ep:x}", None, addr(ep), AddressSet(addr(ep)), SourceType.USER_DEFINED)
        except Exception as e:
            print(f"// {hex(ep)}: {e}")
            continue
    res = ifc.decompileFunction(fn, 60, mon)
    print(f"// ===== {hex(ep)} default handler =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC()[:2500])
    else:
        print("// fail:", res.getErrorMessage())
    print()

fn = fm.getFunctionAt(addr(0x4007871e))
if fn:
    res = ifc.decompileFunction(fn, 60, mon)
    print("// ===== 0x4007871e second vtable user =====")
    print(res.getDecompiledFunction().getC()[:2500] if res.decompileCompleted() else res.getErrorMessage())
