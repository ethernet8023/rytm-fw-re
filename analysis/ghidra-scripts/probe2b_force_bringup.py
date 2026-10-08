#!/usr/bin/env python3
"""Force-disassemble + create fn at 0x40100b12, then decompile it."""
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

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor
mon = ConsoleTaskMonitor()

# what's there now?
a = addr(0x40100b12)
cu = listing.getCodeUnitContaining(a)
print("current unit at 0x40100b12:", cu)

# disassemble from a bit before in case it's mid-instruction alignment
start = addr(0x40100b0c)
cmd = DisassembleCommand(start, None, True)
cmd.applyTo(program, mon)
fm.createFunction(a, "kernel_bringup_0x40100b12")

fn = fm.getFunctionAt(a)
print("fn now:", fn)
if fn:
    print("body:", fn.getBody())

from ghidra.app.decompiler import DecompInterface
ifc = DecompInterface()
ifc.openProgram(program)
if fn:
    res = ifc.decompileFunction(fn, 120, ConsoleTaskMonitor())
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
    print("\n// ===== callees =====")
    for c in sorted(x.getEntryPoint().getOffset() for x in fn.getCalledFunctions(None)):
        print(f"  callee 0x{c:08x}")

# also dump raw disasm 0x40100b00..0x40100d00 regardless
print("\n// ===== raw disasm 0x40100b00..0x40100d00 =====")
it = listing.getInstructions(addr(0x40100b00), True)
n = 0
for ins in it:
    if ins.getAddress().getOffset() > 0x40100d00 or n > 120:
        break
    print(f"{ins.getAddress():08x}  {ins}")
    n += 1
