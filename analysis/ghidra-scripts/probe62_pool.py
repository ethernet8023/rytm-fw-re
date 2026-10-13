#!/usr/bin/env python3
"""Decompile FUN_400035ca (parser dispatch target), FUN_4000396a (event node
alloc/pool), FUN_40003d24 (enqueue). The pool base will reveal the event
struct layout the views consume."""
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

def dump(ep, label="", maxlen=5000):
    fn = ensure(ep)
    if fn is None:
        print(f"// NO FN at {hex(ep)} {label}")
        return
    res = ifc.decompileFunction(fn, 150, mon)
    print(f"// ===== {hex(ep)} {label} =====")
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        print(c[:maxlen])
        if len(c) > maxlen:
            print(f"... // TRUNC {len(c)-maxlen}")
    else:
        print("// fail:", res.getErrorMessage())
    print()

dump(0x400035ca, "parser dispatch target")
dump(0x4000396a, "event node alloc")
dump(0x40003d24, "enqueue")
