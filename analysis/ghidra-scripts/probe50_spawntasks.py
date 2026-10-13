#!/usr/bin/env python3
"""Decompile unexamined spawned tasks: 0x400008fc (from FUN_40000946, prio 0x20),
the one spawned by FUN_400837a4 at PC-0x534 -> 0x4008327c?, FUN_400846e6's
(PC-0x157c -> 0x4008319c?), and FUN_40095e9e's (PC-0x208 -> 0x40095ca?).
Compute pea targets precisely: pea d16(PC) at addr A encodes A+2+d."""
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

def dump(ep, label="", maxlen=4500):
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
            print(f"... // TRUNC {len(c)-maxlen}")
    else:
        print("// fail:", res.getErrorMessage())
    print()

# pea d16(PC): target = insn_addr + 2 + d16. From spawns.txt:
# 0x400009ac pea (-0xb2,PC) -> 0x400009ac + 2 - 0xb2 = 0x400008fc
dump(0x400008fc, "spawned task (prio 0x20, from FUN_40000946)")
# 0x400837a8 pea (0x534,PC) -> 0x400837aa + 0x534 = 0x40083cde?? wait: addr+2+d
dump(0x40083cde, "spawned task from FUN_400837a4 (prio 1)")
# 0x40084714 pea (-0x157c,PC) -> 0x40084716 - 0x157c = 0x4008319a
dump(0x4008319a, "spawned task from FUN_400846e6 (prio 4)")
# 0x40095ea2 pea (-0x208,PC) -> 0x40095ea4 - 0x208 = 0x40095c9c
dump(0x40095c9c, "spawned task from FUN_40095e9e (prio 1, LED struct arg)")
