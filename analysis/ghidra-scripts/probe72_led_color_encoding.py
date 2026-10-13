#!/usr/bin/env python3
"""LED colour encoding: decompile the clear/reset + 4-arg LED helper.

FUN_40095fc0(led, colour) writes the colour byte raw to the FPGA. Hypothesis to
test: colour byte = (R<<6)|(G<<5)|(B<<4)|brightness(0..15) - which would make the
sweep's 0x50..0x5f = R+B = magenta at 16 levels, matching what the panel shows.
FUN_40095ed4(?,?,?,?) is called as (0x70,0,0,0) and (0x71,1,1,1) from the clear
path - decompile it and the whole clear fn.
"""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/hcbfjkvrc2lk0bzhv9b4yv7rrmc8qsmh-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.function import CreateFunctionCmd

project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
mem = program.getMemory()
listing = program.getListing()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)
mon = ConsoleTaskMonitor()

def dump_decomp(x, label=""):
    a = addr(x)
    f = fm.getFunctionAt(a)
    if f is None:
        CreateFunctionCmd(a).applyTo(program, mon)
        f = fm.getFunctionAt(a)
    print(f"\n===== {label} 0x{x:08x} =====")
    if f is None:
        print("// no function")
        return
    res = dec.decompileFunction(f, 240, mon)
    print(res.getDecompiledFunction().getC() if res.decompileCompleted()
          else "// failed: " + res.getErrorMessage())

for x, lbl in ((0x40095ed4, "4-arg LED helper"), (0x400960bc, "LED clear/reset"),
               (0x400a043e, "other writer caller"), (0x40095b74, "slot select")):
    dump_decomp(x, lbl)

print("\n===== refs to FUN_40095ed4 =====")
for r in refmgr.getReferencesTo(addr(0x40095ed4)):
    s = r.getFromAddress().getOffset()
    f = fm.getFunctionContaining(addr(s))
    print(f"  0x{s:08x} in {f.getName() if f else '<none>'}")

print("\n===== call sites of FUN_40095ed4 with their arg setup =====")
sites = sorted({r.getFromAddress().getOffset()
                for r in refmgr.getReferencesTo(addr(0x40095ed4))
                if r.getReferenceType().isCall()})
for s in sites[:40]:
    ins = listing.getInstructionAt(addr(s))
    ctx, cur = [], ins
    for _ in range(6):
        cur = cur.getPrevious()
        if cur is None:
            break
        ctx.append(str(cur))
    ctx.reverse()
    f = fm.getFunctionContaining(addr(s))
    print(f"\n0x{s:08x} in {f.getName() if f else '<none>'}")
    for c in ctx:
        print("      ", c)

project.close()
print("\ndone")
