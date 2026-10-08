# DumpDisplayCandidates.py - Ghidra headless: dump DSPI-referencing functions + xref chains
# @category Analysis
# For the Elektron Rytm MKII MAIN OS image (ColdFire, base 0x40000400).

targets = [0xfc05c000, 0xfc05c02c, 0xfc05c034, 0xfc05c038]

def a2s(a):
    return "0x%08x" % a.getOffset()

fm = currentProgram.getFunctionManager()
refmgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
af = currentProgram.getAddressFactory()

# 1) functions referencing DSPI addrs
fns = {}
for t in targets:
    a = af.getAddress(hex(t)[2:].upper())
    for ref in refmgr.getReferencesTo(a):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        if fn is not None:
            fns.setdefault((fn.getName(), a2s(fn.getEntryPoint())), []).append((a2s(fa), hex(t)))

print("=== functions referencing DSPI regs ===")
for (name, ep), refs in sorted(fns.items(), key=lambda kv: int(kv[0][1], 16)):
    print("FN %s @ %s : %d refs, first %s" % (name, ep, len(refs), refs[0][0]))

# 2) for the top fn, list its callers
print("\n=== callers of those fns ===")
for (name, ep) in fns:
    entry = af.getAddress(hex(int(ep, 16))[2:].upper())
    fn = fm.getFunctionAt(entry)
    if fn is None: continue
    callers = set()
    for ref in fn.getCallingFunctions(None):
        callers.add((ref.getName(), a2s(ref.getEntryPoint())))
    print("%s @ %s <= called by %d fns: %s" % (name, ep, len(callers), sorted(callers)[:6]))

# 3) functions containing a loop over >=1024 bytes (cmpi #1024 or #128) AND a call to any DSPI fn
print("\n=== loop-bound fns (1024/128) ===")
for f in fm.getFunctions(True):
    hits = 0
    ins = listing.getInstructions(f.getBody(), True)
    while ins.hasNext():
        i = ins.next()
        s = i.toString()
        if ("#0x400" in s) or ("#0x200" in s) or ("#0x80" in s) or ("#1024" in s) or ("#128" in s):
            hits += 1
    if hits and any((f.getName(), a2s(f.getEntryPoint())) == k for k in fns):
        print("  %s @ %s has %d bound-refs" % (f.getName(), a2s(f.getEntryPoint()), hits))