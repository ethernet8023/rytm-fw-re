#!/usr/bin/env python3
"""Find the input dispatcher: fns that CALL THROUGH the view vtable slot for
keys. Strategy: the dispatcher likely calls FUN_40071efc's siblings on a fresh
event AND invokes a view fn ptr. Find all fns that call 0x40071efc (key getter)
— they're all key HANDLERS. The dispatcher instead calls the event SOURCE.
Find producers: fns writing to offsets +0xc/+0x10 of a queue node. Get the
callers of the frame task FUN_40095796 — wait, it has none (kernel task).
Better: find who references the global event queue. The UI-test struct had
param_1+0x22/+0x23 = self-referential list {+0x20 list head}. FUN_40078580
marks +0x14 = dirty. Let's find WRITERS of view+0x14 consumers: FUN_400790c6
(called when dirty && +0x2c). Decompile it + the fn that POPS events.
Simplest: xrefs to the two KNOWN consumer fns won't find the pump. Instead,
search for fns that call BOTH something at view-slot AND reference 0x42f9xxxx
queue globals. Try: decompile FUN_400790c6 and FUN_40072008."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()

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

def dump(ep, label="", maxlen=4000):
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
    print(f"// callers({len(cl)}): {[hex(c) for c in cl[:12]]}")
    print()

dump(0x400790c6, "dirty handler (modal?)")
dump(0x40072008, "base ctor step 1")
