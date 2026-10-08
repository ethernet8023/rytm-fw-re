#!/usr/bin/env python3
"""Dump peripheral-referencing functions from the analyzed rytm174 ghidra project."""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/73qyyppnm3ygw5g50jwlm67s8qfj46hy-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.util.task import TaskMonitor
project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_3_MAIN_OS.bin", False)
if program is None:
    # fall back: get open program by name
    program = project.getProgram("section_3_MAIN_OS.bin")

fm = program.getFunctionManager()
refmgr = program.getReferenceManager()
af = program.getAddressFactory()

targets = [0xfc05c000, 0xfc05c02c, 0xfc05c034, 0xfc05c038,
           0xfc0cc000, 0xfc0b0000, 0xfc03c000, 0xfc04d000,
           0xec090000, 0xec09400d, 0xec094010, 0xec094048, 0xec09404b,
           0x4027aa28, 0x40272a58, 0x40287200, 0x4027c8ec]

fn_refs = {}
for t in targets:
    a = af.getAddress(hex(t)[2:])
    if a is None:
        continue
    for ref in refmgr.getReferencesTo(a):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        if fn is None:
            continue
        fn_refs.setdefault(fn.getEntryPoint().getOffset(), set()).add((fa.getOffset(), t))

print("=== functions referencing peripherals/globals ===")
for k in sorted(fn_refs):
    refs = fn_refs[k]
    tg = sorted(set(r[1] for r in refs))
    fn = fm.getFunctionAt(af.getAddress(hex(k)[2:]))
    name = fn.getName() if fn else "?"
    print(f"FN {name} @0x{k:08x} refs={len(refs)} targets={[hex(t) for t in tg]}")

print("\n=== callers ===")
for k in sorted(fn_refs):
    fn = fm.getFunctionAt(af.getAddress(hex(k)[2:]))
    if fn is None:
        continue
    callers = fn.getCallingFunctions(None)
    cl = sorted(c.getEntryPoint().getOffset() for c in callers)
    print(f"FN @0x{k:08x} called by {len(cl)}: {[hex(c) for c in cl]}")

n = sum(1 for _ in fm.getFunctions(True))
print(f"\ntotal functions: {n}")