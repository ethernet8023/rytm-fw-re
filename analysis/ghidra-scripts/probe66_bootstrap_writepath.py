#!/usr/bin/env python3
"""Bootstrap flash hunt, step 3: finish the WRITE path.
- FUN_80002da2 = erase-one-256KB-block (970B) — want exact SPI framing
- the page-program thunk called in FUN_80005d66's program loop as default_4
- FUN_800025fc = the flash-present/readiness gate used by write wrappers
Also resolve ALL call targets of FUN_80005d66 so nothing in the write path
stays a mystery thunk.
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
program = project.openProgram("/", "section_2_bootstrap.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)
mon = ConsoleTaskMonitor()

def ensure_fn(x):
    a = addr(x)
    f = fm.getFunctionAt(a)
    if f is None:
        cmd = CreateFunctionCmd(a)
        cmd.applyTo(program, mon)
        f = fm.getFunctionAt(a)
    return f

# 1. resolve all call targets of the upgrade fn
upgrade = fm.getFunctionAt(addr(0x80005d66))
calls = set()
for fa in upgrade.getBody().getAddresses(True):
    for ref in refmgr.getReferencesFrom(fa):
        if ref.getReferenceType().isCall():
            calls.add(ref.getToAddress().getOffset())
print("=== FUN_80005d66 call targets ===")
print(sorted(hex(c) for c in calls))

# 2. decompile the write-path fns
targets = [0x80002da2, 0x800025fc]
# add unknown (non-yet-named) small targets in the DSPI/flash cluster
for c in sorted(calls):
    if 0x80002d00 <= c <= 0x80003100 and c not in targets:
        targets.append(c)

for e in targets:
    f = ensure_fn(e)
    print(f"\n=== 0x{e:08x} ===")
    if f is None:
        print("// could not create function")
        continue
    res = dec.decompileFunction(f, 120, mon)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print(f"// decompile failed: {res.getErrorMessage()}")

# 3. disassemble the program-loop region of FUN_80005d66 to see the exact
#    call + args of the page-program thunk (byte-level framing evidence)
print("\n=== FUN_80005d66 program-loop disasm ===")
listing = program.getListing()
for fa in upgrade.getBody().getAddresses(True):
    if 0x80005d66 <= fa.getOffset() <= 0x800061d0:
        continue
# find the loop: print instructions referencing 0x200 or 0x3ff80008
for fa in upgrade.getBody().getAddresses(True):
    ins = listing.getInstructionAt(fa)
    if ins is None:
        continue
    ops = str(ins)
    if "3ff80008" in ops or ("200" in ops and "jsr" not in ops):
        print(f"0x{fa.getOffset():08x}  {ops}")

project.close()
print("done")
