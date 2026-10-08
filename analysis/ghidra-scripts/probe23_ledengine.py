#!/usr/bin/env python3
"""Decompile the 0x4013d058 family: 4009de28, 4013cd7c, 4013cc50, 4013cdd4, 4013ca1c,
4007a5a4, 401218fc, and peek at data at 0x402720b0."""
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
    DisassembleCommand(addr(ep), None, True).applyTo(program, mon)
    try:
        return fm.createFunction(f"fn_{ep:x}", None, addr(ep), AddressSet(addr(ep)), SourceType.USER_DEFINED)
    except Exception as e:
        print(f"// cannot create {hex(ep)}: {e}")
        return None

def dump(ep, label="", maxlen=6000):
    fn = ensure(ep)
    if fn is None:
        print(f"// NO FN at {hex(ep)} {label}")
        return
    res = ifc.decompileFunction(fn, 180, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        print(c[:maxlen])
        if len(c) > maxlen:
            print(f"... // TRUNCATED {len(c)-maxlen} chars")
    else:
        print("// decompile failed:", res.getErrorMessage())
    cl = sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None))
    print(f"// callers: {[hex(c) for c in cl]}\n")

# what's at 0x402720b0?
d = listing.getDataAt(addr(0x402720b0))
print("// data at 0x402720b0:", d)
print()

dump(0x4009de28, "big alloc 0x3800000")
dump(0x4013cd7c, "loop 16x init fn")
dump(0x4013cc50, "loop 12x init fn")
dump(0x4013ca1c, "periodic registered")
dump(0x4013cdd4, "irq handler at vec 0x400002fc")
dump(0x4007a5a4, "dma start fn")
