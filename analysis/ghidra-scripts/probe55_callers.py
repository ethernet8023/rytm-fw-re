#!/usr/bin/env python3
"""Find computed-call references TO the default key handler fn 0x4007843a and
to the UI-test key handler 0x4013dee6 — ghidra may have resolved vtable
dispatches as computed calls. Also: the view STACK head. FUN_4007880c (modal
open) broadcast to view+0x34 list. The ACTIVE view chain: find globals holding
vtable ptrs — search all DATA refs to vtable addresses 0x401d77d4."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
listing = program.getListing()

def addr(x):
    return af.getAddress(hex(x)[2:])

print("=== ALL refs to default key handler 0x4007843a ===")
for ref in refmgr.getReferencesTo(addr(0x4007843a)):
    fa = ref.getFromAddress()
    fn = fm.getFunctionContaining(fa)
    print(f"  from 0x{fa.getOffset():08x} type={ref.getReferenceType()} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}")

print("\n=== ALL refs to UI-test key handler 0x4013dee6 ===")
for ref in refmgr.getReferencesTo(addr(0x4013dee6)):
    fa = ref.getFromAddress()
    print(f"  from 0x{fa.getOffset():08x} type={ref.getReferenceType()}")

# who references the view-name ctor's registry: FUN_400784c8 second arg usage?
# instead check refs to 0x4018a69c (subscribe) — subscription sites:
print("\n=== callers of subscribe fn FUN_4018a69c ===")
fn = fm.getFunctionAt(addr(0x4018a69c))
if fn:
    cl = sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None))
    print(f"  {len(cl)}: {[hex(c) for c in cl[:25]]}")
