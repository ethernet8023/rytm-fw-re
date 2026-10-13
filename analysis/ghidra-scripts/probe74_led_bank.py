#!/usr/bin/env python3
"""Which LED palette BANK does the boot splash load?

FUN_400960bc (LED clear, called first thing by the splash) does
  uVar2 = FUN_400faac4();
  FUN_40095f54(max(0,uVar2));      // load palette bank uVar2
FUN_40095f54(sel) loads 7 hues x 16 levels x RGB from 0x401d8ae0 + sel*0x150 and
pushes each as FUN_40095ed4(index, r, g, b) -> cmd 0xb5 payload. Decompile
FUN_400faac4 to see what picks the bank.
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
    res = dec.decompileFunction(f, 200, mon)
    print(res.getDecompiledFunction().getC() if res.decompileCompleted()
          else "// failed: " + res.getErrorMessage())

for x, lbl in ((0x400faac4, "bank selector"),):
    dump_decomp(x, lbl)

print("\n===== callers of FUN_400faac4 =====")
for r in refmgr.getReferencesTo(addr(0x400faac4)):
    s = r.getFromAddress().getOffset()
    fn = fm.getFunctionContaining(addr(s))
    print(f"  0x{s:08x} in {fn.getName() if fn else '<none>'}")

print("\n===== callers of the palette loader FUN_40095f54 =====")
for r in refmgr.getReferencesTo(addr(0x40095f54)):
    s = r.getFromAddress().getOffset()
    fn = fm.getFunctionContaining(addr(s))
    print(f"  0x{s:08x} in {fn.getName() if fn else '<none>'}")

print("\n===== callers of the clear fn FUN_400960bc =====")
for r in refmgr.getReferencesTo(addr(0x400960bc)):
    s = r.getFromAddress().getOffset()
    fn = fm.getFunctionContaining(addr(s))
    print(f"  0x{s:08x} in {fn.getName() if fn else '<none>'}")

print("\n===== palette table bounds: words around 0x401d8ae0 and its end =====")
a = addr(0x401d8ae0)
print("...first 16 bytes:", " ".join("%02x" % (mem.getByte(a.add(i)) & 0xff) for i in range(16)))
end = addr(0x401d8ae0 + 7 * 0x150)
print("word at end (0x%08x):" % end.getOffset(),
      " ".join("%08x" % (mem.getInt(end.add(i)) & 0xffffffff) for i in range(0, 16, 4)))

print("\n===== any other refs into the palette table (bases)? =====")
for r in refmgr.getReferencesTo(addr(0x401d8ae0)):
    s = r.getFromAddress().getOffset()
    fn = fm.getFunctionContaining(addr(s))
    print(f"  0x{s:08x} in {fn.getName() if fn else '<none>'}")

project.close()
print("\ndone")
