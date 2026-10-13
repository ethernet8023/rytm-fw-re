#!/usr/bin/env python3
"""The input pump must: (a) obtain events (from pads/encoders scan or FPGA),
(b) invoke view->key(view, event) via vtable +8, i.e. a computed call through
(vtable+8). Search the whole program for computed calls where the target is
loaded from +8 of something loaded from +0 of something — i.e. pattern:
  move.l (view), A0      ; vtable
  move.l 8(A0), A0      ; key slot
  jsr (A0)
Ghidra sees these as COMPUTED_CALL refs to the target fn when known. Instead,
find all fns whose DISASM contains a call to 0x4007843a (default key handler
address stored in vtables) — no. Better: find all fns that reference event
getter 0x40071fa0 AND make computed calls — those are dispatchers/handlers.
Best: list all COMPUTED_CALL references in the UI cluster 0x40078000-0x40079000."""
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

from ghidra.program.model.symbol import RefType

# Find all fns that make COMPUTED calls AND call an event accessor
print("=== fns calling event accessors (any of 40071efc/40071fa0/40071f70/40071f90) ===")
accessors = {0x40071efc, 0x40071fa0, 0x40071f70, 0x40071f90}
fns_with_accessors = set()
for acc in accessors:
    fn = fm.getFunctionAt(addr(acc))
    if not fn:
        continue
    for c in fn.getCallingFunctions(None):
        fns_with_accessors.add(c.getEntryPoint().getOffset())

# Among those, which ones ALSO perform computed calls (indirect)?
print(f"{len(fns_with_accessors)} fns call accessors")
computed_callers = []
for ep in sorted(fns_with_accessors):
    fn = fm.getFunctionAt(addr(ep))
    if not fn:
        continue
    has_computed = False
    body = fn.getBody()
    it = listing.getInstructions(body, True)
    for ins in it:
        for ref in refmgr.getReferencesFrom(ins.getAddress()):
            if str(ref.getReferenceType()) == "COMPUTED_CALL":
                has_computed = True
                break
        if has_computed:
            break
    if has_computed:
        computed_callers.append(ep)

print(f"\nof those, {len(computed_callers)} also make computed calls (dispatcher candidates):")
for ep in computed_callers:
    print(f"  0x{ep:08x}")
