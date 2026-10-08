#!/usr/bin/env python3
"""Force-create fn at 0x40100b12 (lea 0x40000000,a0 = clean prologue), decompile it + callees."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
listing = program.getListing()

def addr(x):
    return af.getAddress(hex(x)[2:])

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
mon = ConsoleTaskMonitor()

a = addr(0x40100b12)
DisassembleCommand(a, None, True).applyTo(program, mon)
fn = fm.createFunction("kernel_bringup_12", None, a, AddressSet(a), SourceType.USER_DEFINED)
print("fn created:", fn)

from ghidra.app.decompiler import DecompInterface
ifc = DecompInterface()
ifc.openProgram(program)

def dump(ep, label=""):
    f2 = fm.getFunctionAt(addr(ep))
    if f2 is None:
        # try to create it first (disassemble + create)
        aa = addr(ep)
        DisassembleCommand(aa, None, True).applyTo(program, mon)
        try:
            f2 = fm.createFunction(f"fn_{ep:x}", None, aa, AddressSet(aa), SourceType.USER_DEFINED)
        except Exception as e:
            print(f"// cannot create fn at {hex(ep)}: {e}")
            return
    res = ifc.decompileFunction(f2, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())

dump(0x40100b12, "kernel bring-up (small)")
