#!/usr/bin/env python3
"""Decompile the event accessors: 0x40071efc (key code?), 0x40071fa0 (pressed?),
0x40071f70, 0x40071e90-ish family. Then find callers of the key handler
FUN_4013dee6-shaped slots: who dispatches view->key_handler(view, event)?"""
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
    print()

dump(0x40071efc, "event: key code")
dump(0x40071fa0, "event: pressed flag")
dump(0x40071f70, "event: third accessor")
dump(0x40078580, "post-key fn A")
dump(0x400785b8, "post-key fn B")

# who references 0x4013dee6-style handlers? The view struct at 0x40235f88 had
# the key handler at some slot. Find ALL fns that call through a struct slot
# AND are reachable from the kernel: easier - find callers of FUN_40078580 (called
# at the end of every key handler).
fn = fm.getFunctionAt(addr(0x40078580))
if fn:
    print("=== callers of 0x40078580 (key dispatch participants) ===")
    for c in sorted(x.getEntryPoint().getOffset() for x in fn.getCallingFunctions(None)):
        cf = fm.getFunctionAt(addr(c))
        print(f"  0x{c:08x}")
