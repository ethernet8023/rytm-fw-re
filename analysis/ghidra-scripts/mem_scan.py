#!/usr/bin/env python3
"""Memory budget scan: collect every absolute address referenced by code/data
(code incl. immediates; 0x40000000-0x4fffffff DDR + 0x80000000-0x8000ffff FPGA
SRAM) and find the largest untouched holes.
Method: raw-scan the whole MAIN OS image for 4-byte BE words that look like
valid addresses; count per 64KB block. Holes = blocks with zero references,
bounded by referenced blocks. (Heuristic but effective; hardware probe will
confirm before use.)"""
data = open("/home/ethie/rytm-fw-re/extracted/section_3_MAIN_OS.bin", "rb").read()
IB = 0x40000400

from collections import Counter
ddr = Counter()   # 0x40000000-0x4fffffff
sram = Counter()  # 0x80000000-0x8000ffff

for off in range(0, len(data) - 3, 2):  # word-aligned-ish scan (2 for density)
    w = int.from_bytes(data[off:off+4], "big")
    if 0x40000000 <= w < 0x50000000:
        ddr[w >> 16] += 1
    elif 0x80000000 <= w < 0x80010000:
        sram[w >> 12] += 1

# known used ranges from STATUS/disasm (globals, stacks, scratch)
print("== DDR 64KB blocks with references (count) ==")
lo = min(ddr) if ddr else 0
hi = max(ddr) if ddr else 0
used = sorted(ddr)
print(f"referenced range: 0x{used[0]<<16:08x} - 0x{used[-1]<<16:08x}, {len(used)} blocks of 64K")
# find gaps
gaps = []
prev = used[0]
for b in used[1:]:
    if b - prev > 1:
        gaps.append((prev + 1, b - 1))
    prev = b
print("\n== internal gaps (64KB blocks, unreferenced) ==")
for g in gaps:
    size = (g[1] - g[0] + 1) * 64
    print(f"  0x{g[0]<<16:08x} - 0x{(g[1]<<16)+0xffff:08x}  ({size//1024} KB)")
# top region
top_used = used[-1]
print(f"\n== above last referenced block ==")
print(f"  0x{(top_used+1)<<16:08x} - 0x4fffffff  ({(0x50000000 - (top_used+1)*0x10000)//1024} KB)")

print("\n== FPGA SRAM 4KB blocks referenced ==")
for k in sorted(sram):
    print(f"  0x{k<<12:08x}: {sram[k]}")
