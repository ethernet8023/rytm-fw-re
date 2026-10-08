#!/usr/bin/env python3
"""Disassemble the fn containing 0x40039040 (third lazy 128x64 bitmap singleton),
find its start, decompile it. Also FUN_40039782 (clear+bg?) and FUN_40039f3c."""
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

# find function containing 0x40039040
fn = fm.getFunctionContaining(addr(0x40039040))
if fn:
    print(f"fn containing 0x40039040: {fn.getName()} @ 0x{fn.getEntryPoint().getOffset():08x}")
    print(f"body: {fn.getBody()}")
else:
    print("no fn contains 0x40039040; raw disasm:")

# raw disasm from a bit before
a = addr(0x40038fe0)
it = listing.getInstructions(a, True)
n = 0
for ins in it:
    if ins.getAddress().getOffset() > 0x40039070:
        break
    print(f"0x{ins.getAddress().getOffset():08x}  {ins}")
    n += 1

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface()
ifc.openProgram(program)
mon = ConsoleTaskMonitor()

for ep, label in [(fn.getEntryPoint().getOffset() if fn else 0, "singleton 3"),
                  (0x40039782, "clear+bg?"),
                  (0x40039f3c, "ec07 cluster 0x8000007f user")]:
    if ep == 0:
        continue
    f2 = fm.getFunctionAt(addr(ep))
    if f2 is None:
        print(f"// no fn at {hex(ep)}")
        continue
    res = ifc.decompileFunction(f2, 120, mon)
    print(f"\n// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC()[:5000])
    else:
        print("// decompile failed:", res.getErrorMessage())
