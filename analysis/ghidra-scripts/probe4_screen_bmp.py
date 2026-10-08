#!/usr/bin/env python3
"""Probe: who calls FUN_4006f9b2 with (0x80, 0x40) — the screen bitmap creator.
Also decompile FUN_40070c78 (clear?) and find its callers."""
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

# 1. find callers of bitmap ctor 0x4006f9b2 and their call-site args (looking for 0x80,0x40)
ctor = fm.getFunctionAt(addr(0x4006f9b2))
print("=== call sites of bitmap ctor 0x4006f9b2 ===")
for ref in refmgr.getReferencesTo(addr(0x4006f9b2)):
    if not ref.getReferenceType().isCall():
        continue
    ca = ref.getFromAddress()
    print(f"\n--- call site at 0x{ca.getOffset():08x} ---")
    # dump 12 instructions before the call
    insns = list(listing.getInstructions(ca, False))[:14]
    for ins in reversed(insns):
        print(f"  0x{ins.getAddress().getOffset():08x}  {ins}")

# 2. decompile FUN_40070c78
dump(0x40070c78, "clear/full-flush candidate")

# 3. callers of 40070c78
fn = fm.getFunctionAt(addr(0x40070c78))
if fn:
    print("\n=== callers of 0x40070c78 ===")
    for c in sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None)):
        print(f"  0x{c:08x}")
