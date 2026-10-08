#!/usr/bin/env python3
"""Decompile fns referencing 0xec070000: 0x4007a37c, 0x4007a3c2, 0x4007a3dc, 0x4007a39a.
These look like display text output (used by crash reporter)."""
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
refmgr = program.getReferenceManager()

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

def dump(ep, label=""):
    fn = ensure(ep)
    if fn is None:
        print(f"// NO FN at {hex(ep)} {label}")
        return
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())

# where exactly in 0xec070000 do they touch?
print("=== refs into 0xec07xxxx ===")
it = refmgr.getReferenceSourceIterator(program.getMinAddress(), True)
for fa in it:
    for ref in refmgr.getReferencesFrom(fa):
        ta = ref.getToAddress()
        if ta is None:
            continue
        off = ta.getOffset()
        if 0xec070000 <= off < 0xec080000:
            fn = fm.getFunctionContaining(fa)
            fname = f"FUN_{fn.getEntryPoint().getOffset():08x}" if fn else "?"
            ins = listing.getInstructionAt(fa)
            print(f"  0x{fa.getOffset():08x} [{fname}] -> 0x{off:08x}: {ins}")

for ep in (0x4007a37c, 0x4007a39a, 0x4007a3c2, 0x4007a3dc):
    dump(ep, "ec07 writer")
