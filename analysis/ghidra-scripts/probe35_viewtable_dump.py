#!/usr/bin/env python3
"""Find the input dispatch: the UI-test fn 0x4013d200 reads a struct with input
state at offsets 0x60 (index), 0xb8 (button table), +0x3a/0x7f (arrays).
Trace: who calls the test-suite entry, and what IS param_1? Also hunt for the
kernel input task: scan for fns reading the pad/encoder GPIO/EC regions."""
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
        return None

# 1. The UI-test fn is data-referenced from 0x40235fac (view table). Dump the table around it
# to find the struct that owns it, and find who walks that table.
print("=== data around view-table entry 0x40235fac (dump 0x40235f00..0x40236080) ===")
base = 0x40235f00
data = open("/home/ethie/rytm-fw-re/extracted/section_3_MAIN_OS.bin", "rb").read()
IB = 0x40000400
for row in range(0x40235f00, 0x40236100, 16):
    off = row - IB
    words = [int.from_bytes(data[off+i:off+i+4], "big") for i in range(0, 16, 4)]
    print(f"0x{row:08x}: " + "  ".join(f"{w:08x}" for w in words))
