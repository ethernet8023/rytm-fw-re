#!/usr/bin/env python3
"""Bootstrap flash hunt, step 5: boundary surgery. The upgrade loops call
erase @ 0x80002da2 and page-program @ 0x80002d36, but ghidra's linear
disassembly is misaligned there (entries land inside other functions'
instruction streams). Re-disassemble from each EXACT entry point and
dump/decompile the true bodies.
"""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/hcbfjkvrc2lk0bzhv9b4yv7rrmc8qsmh-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_2_bootstrap.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
listing = program.getListing()
mon = ConsoleTaskMonitor()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)

for entry in [0x80002d36, 0x80002da2, 0x80002dfa, 0x80002e0e, 0x80002e20, 0x80002e34, 0x80002e1c]:
    a = addr(entry)
    print(f"\n######## entry 0x{entry:08x} ########")
    # force a fresh disassembly stream from this exact address
    cmd = DisassembleCommand(a, None, False)
    cmd.applyTo(program, mon)
    # dump the instruction stream from the entry
    n = 0
    for ins in listing.getInstructions(a, True):
        print(f"  0x{ins.getAddress().getOffset():08x}  {ins}")
        n += 1
        if n >= 45:
            break
    # try to form a function + decompile
    if fm.getFunctionAt(a) is None:
        CreateFunctionCmd(a).applyTo(program, mon)
    f = fm.getFunctionAt(a)
    if f is not None:
        res = dec.decompileFunction(f, 90, mon)
        print("  --- decompile ---")
        if res.decompileCompleted():
            print(res.getDecompiledFunction().getC())
        else:
            print(f"  // fail: {res.getErrorMessage()}")
    else:
        print("  // no function formed")

project.close()
print("done")
