#!/usr/bin/env python3
"""The view vtable: 0x401d77d4 = {base_op?, +4: 0x401d7824, +8: 0x401d7838,
+0xc: 0x401d784c, +0x10: 0x401d7860}. Decompile the 4 default handlers, then
find the DISPATCHER: fns calling through view vtable slots. The dispatcher
calls (*(view+4/8/...))(view, event) — search for calls through +0xc slot."""
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

def dump(ep, label="", maxlen=3000):
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
    print()

# the 4 default vtable handlers
dump(0x401d7824, "default handler A")
dump(0x401d7838, "default handler B")
dump(0x401d784c, "default handler C")
dump(0x401d7860, "default handler D")

# who references 0x401d77d4 (the base vtable) besides the ctor?
print("=== refs to base vtable 0x401d77d4 ===")
for ref in refmgr.getReferencesTo(addr(0x401d77d4)):
    fa = ref.getFromAddress()
    fn = fm.getFunctionContaining(fa)
    print(f"  from 0x{fa.getOffset():08x} in={'FUN_%08x' % fn.getEntryPoint().getOffset() if fn else '?'} type={ref.getReferenceType()}")
