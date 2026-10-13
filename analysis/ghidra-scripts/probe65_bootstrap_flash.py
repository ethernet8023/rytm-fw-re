#!/usr/bin/env python3
"""Bootstrap flash hunt, step 2: decompile the DSPI driver family + the
mystery 0xec06 fns + the eSDHC users. Looking for SPI NOR command bytes
(0x9f jedec / 0x03 read / 0x02 program / 0xd8-0x20 erase / 0x05-0x06 status)
and the flash section layout.
"""
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/nix/store/hcbfjkvrc2lk0bzhv9b4yv7rrmc8qsmh-ghidra-12.1.2/lib/ghidra")

import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project = GhidraProject.openProject("/tmp/gproj", "rytm174", True)
program = project.openProgram("/", "section_2_bootstrap.bin", False)

af = program.getAddressFactory()
fm = program.getFunctionManager()

def addr(x):
    return af.getAddress(hex(x)[2:])

dec = DecompInterface()
dec.openProgram(program)
mon = ConsoleTaskMonitor()

targets = {
    "DSPI family": [0x800022f8, 0x8000233a, 0x8000238e, 0x8000248c,
                    0x8000254c, 0x80002852],
    "DSPI users": [0x80006690, 0x800068cc, 0x8000a3f4, 0x80005d66, 0x8000293a],
    "ec06 fns": [0x80006c3e, 0x80006cb0],
    "eSDHC users": [0x80001118, 0x80004170],
}

for group, entries in targets.items():
    print(f"\n######## {group} ########")
    for e in entries:
        f = fm.getFunctionAt(addr(e))
        if f is None:
            print(f"\n=== 0x{e:08x}: NOT A FUNCTION ===")
            continue
        res = dec.decompileFunction(f, 120, mon)
        print(f"\n=== 0x{e:08x} (size {f.getBody().getNumAddresses()}) ===")
        if res.decompileCompleted():
            print(res.getDecompiledFunction().getC())
        else:
            print(f"// decompile failed: {res.getErrorMessage()}")

project.close()
print("done")
