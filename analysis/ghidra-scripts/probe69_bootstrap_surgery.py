#!/usr/bin/env python3
"""Bootstrap flash hunt, step 6: overlapping-stream surgery.
The region 0x80002d00-0x80003180 holds TWO instruction streams over the same
bytes: the startup-menu fn (ghidra's default flow, entered at 0x80002d42) and
the true flash driver (entered at 0x80002d36 page-program / 0x80002da2 erase /
0x80002dfa 0x80002e0e 0x80002e20 0x80002e34 ID readers — the actual upgrade
call targets). Ghidra can only hold one interpretation per byte, and the menu
flow won. Clear the region and re-disassemble from the DRIVER entries, then
dump + decompile the true write path.
"""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/hcbfjkvrc2lk0bzhv9b4yv7rrmc8qsmh-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_2_bootstrap.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()
listing = program.getListing()
mon = ConsoleTaskMonitor()

def addr(x):
    return af.getAddress(hex(x)[2:])

# 1. remove existing functions in the region, then clear instruction bytes
lo = addr(0x80002d00)
hi = addr(0x800031a0)

for f in list(fm.getFunctions(True)):
    ep = f.getEntryPoint().getOffset()
    if 0x80002d00 <= ep <= 0x800031a0:
        fm.removeFunction(f.getEntryPoint())

txid = program.startTransaction("boundary surgery")
try:
    # clear code units in region (keep data/labels)
    listing.clearCodeUnits(lo, hi, False)
    # 2. disassemble from the TRUE driver entries, in order
    for entry in [0x80002d36, 0x80002da2, 0x80002dfa, 0x80002e0e,
                  0x80002e20, 0x80002e34, 0x80002e1c]:
        cmd = DisassembleCommand(addr(entry), None, True)
        r = cmd.applyTo(program, mon)
        print(f"disasm @ 0x{entry:08x}: {r}")
    txid2 = program.endTransaction(txid, True)
except Exception as e:
    program.endTransaction(txid, False)
    raise

# 3. create functions at the entries + decompile
dec = DecompInterface()
dec.openProgram(program)
for entry in [0x80002d36, 0x80002da2, 0x80002dfa, 0x80002e0e, 0x80002e34]:
    a = addr(entry)
    print(f"\n######## fn 0x{entry:08x} ########")
    if fm.getFunctionAt(a) is None:
        CreateFunctionCmd(a).applyTo(program, mon)
    f = fm.getFunctionAt(a)
    if f is None:
        # dump raw stream instead
        n = 0
        for ins in listing.getInstructions(a, True):
            print(f"  0x{ins.getAddress().getOffset():08x}  {ins}")
            n += 1
            if n >= 50:
                break
        continue
    print(f"  body size: {f.getBody().getNumAddresses()}")
    res = dec.decompileFunction(f, 120, mon)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print(f"  // fail: {res.getErrorMessage()}")

project.saveAs(project.getProjectURI(), True)
project.close()
print("done")
