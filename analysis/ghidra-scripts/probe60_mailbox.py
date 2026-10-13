#!/usr/bin/env python3
"""FUN_40004294 = the input event parser (mailbox 0x42f67b54). Find:
1. its callers (the pump loop)
2. refs to 0x42f67b54..0x42f67b5a (who writes the mailbox = FPGA IRQ side)
3. decompile the LAB handlers: 0x40004216, 0x4000421c, 0x400035ca, 0x40004dfc"""
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

fn = fm.getFunctionAt(addr(0x40004294))
if fn:
    print("=== callers of input parser FUN_40004294 ===")
    for c in sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None)):
        print(f"  0x{c:08x}")

print("\n=== refs to mailbox 0x42f67b54 ===")
for t in (0x42f67b54, 0x42f67b58, 0x42f67b5a):
    for ref in refmgr.getReferencesTo(addr(t)):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        ins = listing.getInstructionAt(fa)
        print(f"  0x{t:x} <- 0x{fa.getOffset():08x} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}: {ins}")
    print()
