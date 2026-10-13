#!/usr/bin/env python3
"""Splash step 3: find WHO fills the splash bitmaps A(0x419f1b94) / B(0x419f2338).

Raw 4-byte-BE scan found code refs to those addresses outside the splash task at
0x401469b0 / 0x401523a2 (A) and 0x401433a4 / 0x4015263e (B). Decompile the
containing functions - one of them is the splash-art loader.
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
mem = program.getMemory()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)
mon = ConsoleTaskMonitor()

def containing(x):
    f = fm.getFunctionContaining(addr(x))
    return f

def dump_fn(x, label=""):
    f = containing(x) if fm.getFunctionContaining(addr(x)) else None
    if f is None:
        a = addr(x)
        CreateFunctionCmd(a).applyTo(program, mon)
        f = fm.getFunctionAt(a)
    print(f"\n===== {label} site 0x{x:08x} -> fn "
          f"{f.getName() if f else '?'} @0x{f.getEntryPoint().getOffset():08x}"
          if f else f"\n===== {label} site 0x{x:08x} -> NO FN")
    if f is None:
        return None
    res = dec.decompileFunction(f, 240, mon)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
    return f

for site in (0x401469b0, 0x401523a2, 0x401433a4, 0x4015263e):
    dump_fn(site)

project.close()
print("\ndone")
