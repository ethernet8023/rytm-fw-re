#!/usr/bin/env python3
"""Find the input DISPATCHER: the fn that reads events from a queue and calls
view->handler(view, event). Strategy: find fns that reference the view-struct
vtable marker 0x40235f9c (all views have it at +0), or that call FUN_40071efc-like
accessors on a produced event. Also check the UI-test callers of 0x4013dee6's
siblings: the struct at 0x40235f88 has handler ptrs; who invokes slot+8?"""
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

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
ifc = DecompInterface()
ifc.openProgram(program)
mon = ConsoleTaskMonitor()

# 1. All references to the key-handler fn 0x4013dee6 — who points at it?
print("=== refs to key handler 0x4013dee6 ===")
for ref in refmgr.getReferencesTo(addr(0x4013dee6)):
    fa = ref.getFromAddress()
    fn = fm.getFunctionContaining(fa)
    print(f"  from 0x{fa.getOffset():08x} type={ref.getReferenceType()} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}")

# 2. The view struct template 0x40235f9c (vtable marker). Who WRITES it into structs?
print("\n=== refs to 0x40235f9c (view template/vtable) ===")
for ref in refmgr.getReferencesTo(addr(0x40235f9c)):
    fa = ref.getFromAddress()
    fn = fm.getFunctionContaining(fa)
    ins = listing.getInstructionAt(fa)
    print(f"  from 0x{fa.getOffset():08x} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}: {ins}")

# 3. Who reads event structs? The event has key at +0xc, flags at +0x10.
# Find the producer: fns that WRITE +0xc/+0x10 pattern with enqueue.
# Try: callers of FUN_40078580 that ALSO call through pointers = dispatchers.
# Direct approach: decompile fns calling BOTH 0x40078580 and something queue-ish.
# Instead: who calls 0x40071efc (key getter)? Producers don't, consumers do.
# So: find callers of 0x4013e7b6 (view ctor/entry) — the view stack pusher.
print("\n=== refs to 0x4013e7b6 (view ctor) ===")
for ref in refmgr.getReferencesTo(addr(0x4013e7b6)):
    fa = ref.getFromAddress()
    fn = fm.getFunctionContaining(fa)
    print(f"  from 0x{fa.getOffset():08x} type={ref.getReferenceType()} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'}")
