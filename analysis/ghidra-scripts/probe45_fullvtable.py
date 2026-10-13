#!/usr/bin/env python3
"""Dump the FULL base vtable at 0x401d77d4 (say 24 slots) and find the event
PRODUCER: search all code for 'move.l #imm,(disp,Ax)' writing small key codes
to +0xc of a struct, or find fns that call view vtable slot +8 (key handler).
The dispatcher: find fns containing jsr (aN@) where AN loaded from view+8."""
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

# 1. full vtable dump
data = open("/home/ethie/rytm-fw-re/extracted/section_3_MAIN_OS.bin", "rb").read()
IB = 0x40000400
print("== base view vtable 0x401d77d4, 26 slots ==")
va = 0x401d77d4
for i in range(26):
    w = int.from_bytes(data[va - IB + i*4: va - IB + i*4 + 4], "big")
    fn = fm.getFunctionAt(addr(w)) if 0x40000400 <= w < 0x43000000 else None
    print(f"  +0x{i*4:02x}: {w:08x} {'(fn)' if fn else ''}")

# 2. find jsr through struct offsets: scan instruction operands for
#    "jsr (d8,An)" patterns referencing +8 (key slot)
print("\n== all 'jsr (0x8,An)' style indirect calls ==")
it = listing.getInstructions(True)
for ins in it:
    s = str(ins)
    if "jsr" in s and ("@(0x8," in s or "@(8," in s):
        print(f"  0x{ins.getAddress().getOffset():08x}: {ins}")
