#!/usr/bin/env python3
"""LED sweep: what do the splash's colour values MEAN?

The splash (FUN_40101fc0) walks 8 groups of LED ids (table 0x40288e64, -1 = skip)
and per LED calls FUN_40095fc0(led_id, colour) with
colour = (&DAT_40289104)[clamp(frame - group - 3*pos, 0, 0x29)] — the 42-entry
table at 0x40289104. Decompile the writer + LED engine to learn the encoding
(palette index? packed RGB? per-channel?).
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
        return None
    res = dec.decompileFunction(f, 180, mon)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// decompile failed:", res.getErrorMessage())
    return f

TARGETS = [
    (0x40095fc0, "per-LED colour writer"),
    (0x4013d058, "LED engine init"),
    (0x4013cc50, "per-pad init A"),
    (0x4013cd7c, "per-pad init B"),
    (0x4013ca1c, "kicker task"),
    (0x4007a5a4, "pattern upload to FPGA SRAM"),
    (0x4007a4e4, "pattern DMA setup"),
    (0x4013cdd4, "irq handler"),
]
for x, lbl in TARGETS:
    dump_decomp(x, lbl)

print("\n===== refs to the colour table 0x40289104 and LED id table 0x40288e64 =====")
for t in (0x40289104, 0x40288e64, 0x40289100, 0x40289108):
    rs = list(refmgr.getReferencesTo(addr(t)))
    print(f"0x{t:08x}: {len(rs)} refs")
    for r in rs[:20]:
        src = r.getFromAddress().getOffset()
        f = fm.getFunctionContaining(addr(src))
        print(f"   0x{src:08x} in {f.getName() if f else '<none>'}")

print("\n===== raw words around the colour table (0x402890f0..0x402891c0) =====")
a = addr(0x402890f0)
for row in range(0, 0xd0, 16):
    ws = " ".join("%08x" % (mem.getInt(a.add(row + i)) & 0xffffffff) for i in range(0, 16, 4))
    print(f"0x{0x402890f0 + row:08x}: {ws}")

project.close()
print("\ndone")
