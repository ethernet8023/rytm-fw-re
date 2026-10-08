#!/usr/bin/env python3
"""Decompile the full 0xec07 display bridge driver cluster."""
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
    cl = sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None))
    print(f"// callers: {[hex(c) for c in cl]}\n")

# 0x40001b18/0x40001bce poll-writers; 0x40001c16 cmd writer pair; 0x40001f1e/0x40001fd4 = second channel 0xec074xxx
# 0x40121b08, 0x4013fcc8, 0x4013fdae, 0x40140068 = higher-level users
dump(0x40001b18, "ec07 low writer")
dump(0x40001bce, "ec07 low writer 2")
dump(0x40001c16, "ec07 cmd pair")
dump(0x40001f1e, "ec074 low writer")
dump(0x40001fd4, "ec074 low writer 2")
dump(0x4000201c, "ec074 cmd pair")
dump(0x40121b08, "user")
dump(0x4013fcc8, "user")
dump(0x4013fdae, "user")
dump(0x40140068, "user (called in init task!)")
dump(0x400838b2, "ec074 status poller")
