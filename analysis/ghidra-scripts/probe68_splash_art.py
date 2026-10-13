#!/usr/bin/env python3
"""Splash step 2: identify the two source bitmaps the splash blends between.

- decompile the pixel helpers (FUN_4006fb40 / FUN_4006fa74) and the plane
  accessors FUN_40095a5e / FUN_400959e0 that the splash task uses
- find every reference to the splash's bitmap objects 0x419f1b94 / 0x419f2338
  and to the display plane buffer 0x419b638c -> whoever writes them is the
  splash-art loader
- dump the 64-byte table at 0x4025a09a (suspected ordered-dither matrix)
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

def dump_decomp(x, label=""):
    f = ensure_fn(x)
    print(f"\n===== {label} 0x{x:08x} =====")
    if f is None:
        print("// no function")
        return None
    res = dec.decompileFunction(f, 180, mon)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
    return f

def refs_to(x):
    a = addr(x)
    out = []
    it = refmgr.getReferencesTo(a)
    for r in it:
        src = r.getFromAddress().getOffset()
        f = fm.getFunctionContaining(addr(src))
        out.append((src, f.getName() if f else "<none>"))
    return out

print("=== refs to splash bitmap objects / display planes ===")
for t in (0x419f1b94, 0x419f2338, 0x419b638c, 0x419b6384, 0x419b637c, 0x419b678c, 0x419b6790):
    rs = refs_to(t)
    print(f"\n0x{t:08x} ({len(rs)} refs):")
    for src, fn in sorted(rs)[:40]:
        print(f"   0x{src:08x}  in {fn}")

print("\n=== 64-byte table @0x4025a09a ===")
a = addr(0x4025a09a)
print(" ".join("%02x" % (mem.getByte(a.add(i)) & 0xff) for i in range(64)))

for x, lbl in ((0x4006fb40, "get_pixel?"), (0x4006fa74, "set_pixel?"),
               (0x40095a5e, "present/swap"), (0x400959e0, "clear+present?")):
    dump_decomp(x, lbl)

project.close()
print("\ndone")
