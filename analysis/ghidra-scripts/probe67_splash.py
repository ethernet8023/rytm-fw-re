#!/usr/bin/env python3
"""Boot splash: decompile the splash frame task + dump its data refs.

Goal: locate the STARTUP SPLASH BITMAP in the stock MAIN OS image so it can be
extracted (and later replaced by a mod). Prints the decompiled splash task and
every reference it makes, plus the raw words at each data target.
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
print("=== programs in project ===")
for f in project.getRootFolder().getFiles():
    print(" ", f.getName())
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
mem = program.getMemory()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)
mon = ConsoleTaskMonitor()

def ensure_fn(x):
    a = addr(x)
    f = fm.getFunctionAt(a)
    if f is None:
        CreateFunctionCmd(a).applyTo(program, mon)
        f = fm.getFunctionAt(a)
    return f

def dump_decomp(x):
    f = ensure_fn(x)
    print(f"\n===== 0x{x:08x} =====")
    if f is None:
        print("// no function")
        return None
    res = dec.decompileFunction(f, 180, mon)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
    return f

SPLASH = 0x40101fc0
f = dump_decomp(SPLASH)

print("\n===== data refs from splash task =====")
seen = set()
for fa in f.getBody().getAddresses(True):
    for ref in refmgr.getReferencesFrom(fa):
        t = ref.getToAddress()
        off = t.getOffset()
        if off in seen:
            continue
        seen.add(off)
        kind = "call" if ref.getReferenceType().isCall() else "data"
        extra = ""
        if kind == "data" and mem.contains(t):
            try:
                extra = " | words: " + " ".join(
                    "%08x" % (mem.getInt(t.add(i*4)) & 0xffffffff) for i in range(4))
            except Exception as e:
                extra = f" | (read fail {e})"
        print(f"0x{fa.getOffset():08x} -> 0x{off:08x} [{kind}]{extra}")

# also decompile the bitmap ctor + blit for the struct layout reminder
for x in (0x4006fa2e, 0x400716e0, 0x4006f9b2):
    dump_decomp(x)

project.close()
print("\ndone")
