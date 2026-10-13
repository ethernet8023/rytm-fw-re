#!/usr/bin/env python3
"""Look at 0x401cbf8c (DATA ref region) - dump surrounding words to identify
the structure. Decompile FUN_40095696 (writes progress 0x4191bb6c - near the
frame task, maybe the UI pump feeding it!)."""
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

fn = ensure(0x40095696)
if fn:
    res = ifc.decompileFunction(fn, 120, mon)
    print("// ===== 0x40095696 =====")
    print(res.getDecompiledFunction().getC()[:4500] if res.decompileCompleted() else res.getErrorMessage())

# dump data around 0x401cbf8c
data = open("/home/ethie/rytm-fw-re/extracted/section_3_MAIN_OS.bin", "rb").read()
IB = 0x40000400
print("\n== data around 0x401cbf8c ==")
for row in range(0x401cbf60, 0x401cbfd0, 16):
    off = row - IB
    words = [int.from_bytes(data[off+i:off+i+4], "big") for i in range(0, 16, 4)]
    print(f"  {row:08x}: " + "  ".join(f"{w:08x}" for w in words))
