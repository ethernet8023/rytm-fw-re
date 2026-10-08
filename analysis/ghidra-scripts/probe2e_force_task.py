#!/usr/bin/env python3
"""Force-create + decompile task entry 0x40100a94 (and follow ITS callees = task started by bring-up)."""
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
from ghidra.app.decompiler import DecompInterface
mon = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(program)

def ensure(ep):
    fn = fm.getFunctionAt(addr(ep))
    if fn is not None:
        return fn
    aa = addr(ep)
    DisassembleCommand(aa, None, True).applyTo(program, mon)
    try:
        return fm.createFunction(f"fn_{ep:x}", None, aa, AddressSet(aa), SourceType.USER_DEFINED)
    except Exception as e:
        print(f"// cannot create fn at {hex(ep)}: {e}")
        return None

def dump(ep, label=""):
    fn = ensure(ep)
    if fn is None:
        # fall back to raw disasm
        print(f"// ===== RAW {hex(ep)} {label} =====")
        it = listing.getInstructions(addr(ep), True)
        n = 0
        for ins in it:
            if n > 40:
                break
            print(f"{ins.getAddress():08x}  {ins}")
            n += 1
        return
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
    callees = sorted(x.getEntryPoint().getOffset() for x in fn.getCalledFunctions(None))
    print(f"// callees: {[hex(c) for c in callees]}")

dump(0x40100a94, "task entry started by bring-up")
