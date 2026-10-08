#!/usr/bin/env python3
"""Decompile 0x400820f0 — callback passed to FUN_40001c16 channel init (panel enable?)."""
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

fn = fm.getFunctionAt(addr(0x400820f0))
if fn is None:
    DisassembleCommand(addr(0x400820f0), None, True).applyTo(program, mon)
    try:
        fn = fm.createFunction("fn_400820f0", None, addr(0x400820f0), AddressSet(addr(0x400820f0)), SourceType.USER_DEFINED)
    except Exception as e:
        print("// cannot create:", e)
if fn:
    res = ifc.decompileFunction(fn, 120, mon)
    print("// ===== 0x400820f0 =====")
    print(res.getDecompiledFunction().getC() if res.decompileCompleted() else res.getErrorMessage())
else:
    # raw disasm fallback
    listing = program.getListing()
    it = listing.getInstructions(addr(0x400820f0), True)
    for i, ins in enumerate(it):
        if i > 30: break
        print(f"0x{ins.getAddress().getOffset():08x}  {ins}")
