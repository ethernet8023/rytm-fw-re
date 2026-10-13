#!/usr/bin/env python3
"""Decompile FUN_40003c48 (slot-event handler called by prio-4 dispatcher
FUN_40005380) and find writers of the pending bitmap 0x42f67b60."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
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

fn = ensure(0x40003c48)
if fn:
    res = ifc.decompileFunction(fn, 120, mon)
    print("// ===== 0x40003c48 slot-event handler =====")
    print(res.getDecompiledFunction().getC()[:4000] if res.decompileCompleted() else res.getErrorMessage())

print("\n=== writers/readers of pending bitmap 0x42f67b60 ===")
for ref in refmgr.getReferencesTo(addr(0x42f67b60)):
    fa = ref.getFromAddress()
    fn = fm.getFunctionContaining(fa)
    ins = listing.getInstructionAt(fa)
    print(f"  0x{fa.getOffset():08x} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}: {ins}")
