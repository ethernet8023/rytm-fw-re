#!/usr/bin/env python3
"""Find the event PRODUCER. The event has +0xc key, +0x10 flags. Consumers:
40071efc/40071fa0/40071f70/40071f90. Find fns that CALL the consumers' cohort:
who calls 0x40071f90 (long-press flag)? Those are key handlers like the default.
The producer instead WRITES +0xc. Scan all instructions for writes to (0xc,An)
with small immediates (key codes 0x10-0xbf)."""
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
refmgr = program.getReferenceManager()

def addr(x):
    return af.getAddress(hex(x)[2:])

print("=== callers of 0x40071f90 (flag accessor cohort) ===")
fn = fm.getFunctionAt(addr(0x40071f90))
if fn:
    for c in sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None)):
        print(f"  0x{c:08x}")

# Also: refs to event getter 0x40071efc callers - the dispatcher might also use it
print("\n=== callers of 0x40071efc ===")
fn = fm.getFunctionAt(addr(0x40071efc))
if fn:
    cl = sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None))
    print(f"  {len(cl)} callers")

# The DISPATCHER must hold the active view list. The view ctor FUN_400784c8 was
# called by 61 fns. The stack head: find global list init — FUN_4018a45c called
# on view+0x10 (a list node ctor!). Find its twin: a "process list" walker.
print("\n=== refs to list-node ctor 0x4018a45c ===")
for ref in refmgr.getReferencesTo(addr(0x4018a45c)):
    fa = ref.getFromAddress()
    print(f"  from 0x{fa.getOffset():08x} type={ref.getReferenceType()}")
