#!/usr/bin/env python3
"""Dump the complete display pipeline decompilation to analysis/output/display_flush.txt."""
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
        return None

TARGETS = [
    (0x40095990, "disp_write_tile(col, row, 8B*) — THE FLUSH"),
    (0x40095978, "disp commit (0xb8)"),
    (0x40095a5e, "present + swap (diff full)"),
    (0x400959e0, "present + swap (all tiles)"),
    (0x40095afa, "clear both planes + full flush"),
    (0x40095bb4, "2-byte addressing cmd"),
    (0x40095796, "main frame loop task"),
    (0x40101fc0, "boot splash task"),
    (0x40001c16, "ec07 channel init (DMA setup)"),
    (0x40001b18, "ec07 byte writer w ring fallback"),
    (0x400019e4, "DMA ring pumper"),
    (0x40001bb2, "send cmd byte"),
    (0x40001bf6, "mutex take"),
    (0x40001c06, "mutex give"),
    (0x4006f9b2, "bitmap ctor (alloc planes)"),
    (0x4006fa2e, "bitmap ctor w/ static planes"),
    (0x4006f960, "bitmap dtor"),
    (0x400716e0, "blit"),
    (0x40070c78, "clear/fill dual-plane"),
]

out = []
for ep, label in TARGETS:
    fn = ensure(ep)
    out.append(f"// ===== {hex(ep)} {label} =====")
    if fn is None:
        out.append("// NO FN")
        continue
    res = ifc.decompileFunction(fn, 120, mon)
    if res.decompileCompleted():
        out.append(res.getDecompiledFunction().getC())
    else:
        out.append("// decompile failed: " + res.getErrorMessage())
    out.append("")

with open("analysis/output/display_flush.txt", "w") as f:
    f.write("\n".join(out))
print("wrote", len(out), "blocks")
