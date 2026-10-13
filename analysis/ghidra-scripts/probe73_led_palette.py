#!/usr/bin/env python3
"""LED palette: decompile the palette loader FUN_40095f54 + its data table.

FUN_40095f54(sel) loops FUN_40095ed4(idx, byteA, byteB, ?) with bytes read from a
table -> looks like "define colour idx = rgb". If so, the whole LED palette is
static data in the image and the sweep's colour byte is
(index << 4) | brightness. Dump the table it reads.
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
        return None
    res = dec.decompileFunction(f, 240, mon)
    print(res.getDecompiledFunction().getC() if res.decompileCompleted()
          else "// failed: " + res.getErrorMessage())
    return f

for x, lbl in ((0x40095f54, "palette loader?"), (0x400a0690, "0x74-base caller"),
               (0x40095c04, "per-id helper"), (0x40095d98, "another helper")):
    dump_decomp(x, lbl)

print("\n===== disasm of FUN_40095f54 (table addresses) =====")
f = fm.getFunctionAt(addr(0x40095f54))
for a in f.getBody().getAddresses(True):
    ins = listing.getInstructionAt(a)
    if ins is None:
        continue
    s = str(ins)
    if "PC)" in s or "pea" in s or "lea" in s:
        print(f"0x{a.getOffset():08x}  {s}")

print("\n===== refs to FUN_40095f54 =====")
for r in refmgr.getReferencesTo(addr(0x40095f54)):
    s = r.getFromAddress().getOffset()
    fn = fm.getFunctionContaining(addr(s))
    print(f"  0x{s:08x} in {fn.getName() if fn else '<none>'}")

project.close()
print("\ndone")
