#!/usr/bin/env python3
"""Final protocol decode: 40095afa (full flush), 40001bf6, 40001bb2, 40001c06, 40095c04.
Also check DAT_40287b68/b6c init (plane buffer alloc) — who sets them."""
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

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
mon = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(program)

def ensure(ep):
    fn = fm.getFunctionAt(addr(ep))
    if fn is not None:
        return fn
    DisassembleCommand(addr(ep), None, True).applyTo(program, mon)
    try:
        return fm.createFunction(f"fn_{ep:x}", None, addr(ep), AddressSet(addr(ep)), SourceType.USER_DEFINED)
    except Exception as e:
        print(f"// cannot create {hex(ep)}: {e}")
        return None

def dump(ep, label="", maxlen=7000):
    fn = ensure(ep)
    if fn is None:
        print(f"// NO FN at {hex(ep)} {label}")
        return
    res = ifc.decompileFunction(fn, 120, mon)
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        print(c[:maxlen])
        if len(c) > maxlen:
            print(f"... // TRUNCATED {len(c)-maxlen}")
    else:
        print("// decompile failed:", res.getErrorMessage())
    cl = sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None))
    print(f"// callers({len(cl)}): {[hex(c) for c in cl[:20]]}\n")

dump(0x40095afa, "full flush")
dump(0x40001bf6, "pre-cmd")
dump(0x40001bb2, "cmd byte")
dump(0x40001c06, "post/latch")

print("=== refs to plane ptr globals 0x40287b68 / 0x40287b6c ===")
for t in (0x40287b68, 0x40287b6c):
    for ref in refmgr.getReferencesTo(addr(t)):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        fname = f"FUN_{fn.getEntryPoint().getOffset():08x}" if fn else "?"
        ins = listing.getInstructionAt(fa)
        print(f"  0x{fa.getOffset():08x} [{fname}]: {ins}")
    print()
