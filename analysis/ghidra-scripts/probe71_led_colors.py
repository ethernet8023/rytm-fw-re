#!/usr/bin/env python3
"""LED sweep: build the colour vocabulary.

FUN_40095fc0(led_id, colour) is the per-LED writer; the colour byte goes
straight to the FPGA LED controller as the 3rd payload byte. To learn what the
byte MEANS (the sweep uses 0x50..0x5f + 0x70 and shows up as magenta), dump every
call site's immediate colour argument plus the instructions that set it up.
"""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/hcbfjkvrc2lk0bzhv9b4yv7rrmc8qsmh-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
listing = program.getListing()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)
mon = ConsoleTaskMonitor()

WRITER = 0x40095fc0
sites = []
for r in refmgr.getReferencesTo(addr(WRITER)):
    if r.getReferenceType().isCall():
        sites.append(r.getFromAddress().getOffset())
sites = sorted(set(sites))
print(f"=== {len(sites)} call sites of FUN_40095fc0 ===")

# per-site: show the 5 instructions before the call (arg setup) and the caller fn
for s in sites:
    ins = listing.getInstructionAt(addr(s))
    fn = fm.getFunctionContaining(addr(s))
    ctx = []
    cur = ins
    for _ in range(5):
        cur = cur.getPrevious()
        if cur is None:
            break
        ctx.append(str(cur))
    ctx.reverse()
    print(f"\n0x{s:08x} in {fn.getName() if fn else '<none>'}")
    for c in ctx:
        print("      ", c)

# and the decompiled callers, so immediate colours are readable in context
callers = []
for s in sites:
    f = fm.getFunctionContaining(addr(s))
    if f is not None and f.getEntryPoint().getOffset() not in callers:
        callers.append(f.getEntryPoint().getOffset())
print(f"\n=== {len(callers)} distinct caller functions ===")
for c in callers[:24]:
    f = fm.getFunctionAt(addr(c))
    print(f"\n########## 0x{c:08x} ##########")
    res = dec.decompileFunction(f, 180, mon)
    if res.decompileCompleted():
        txt = res.getDecompiledFunction().getC()
        # keep it readable: only lines mentioning the writer or a 0x4x/0x5x/0x6x/0x7x constant
        keep = [ln for ln in txt.splitlines()
                if "FUN_40095fc0" in ln or "0x4" in ln or "0x5" in ln or "0x6" in ln or "0x7" in ln]
        print("\n".join(keep[:80]) if keep else txt[:2000])
    else:
        print("// decompile failed:", res.getErrorMessage())

project.close()
print("\ndone")
