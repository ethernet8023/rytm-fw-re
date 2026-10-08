# DumpDisplayCandidates.py - Ghidra/PyGhidra headless: dump fns referencing DSPI/GPIO/graphics globals
# @category Analysis
targets = [0xfc05c000, 0xfc05c02c, 0xfc05c034, 0xfc05c038,
           0xfc0cc000, 0xfc0b0000, 0xfc03c000, 0xfc04d000,
           0xec090000, 0xec09400d, 0xec094010, 0xec094048, 0xec09404b,
           0x4027aa28, 0x40272a58, 0x40287200, 0x4027c8ec]

def hx(v): return "0x%08x" % v

fm = currentProgram.getFunctionManager()
refmgr = currentProgram.getReferenceManager()
af = currentProgram.getAddressFactory()

fn_refs = {}
for t in targets:
    a = af.getAddress(hex(t)[2:])
    if a is None: continue
    for ref in refmgr.getReferencesTo(a):
        fa = ref.getFromAddress()
        fn = fm.getFunctionContaining(fa)
        if fn is None: continue
        fn_refs.setdefault(fn.getEntryPoint().getOffset(), set()).add((fa.getOffset(), t))

println("=== functions referencing peripherals/globals ===")
for k in sorted(fn_refs):
    refs = fn_refs[k]
    tg = sorted(set(r[1] for r in refs))
    fn = fm.getFunctionAt(af.getAddress(hex(k)[2:]))
    name = fn.getName() if fn else "?"
    println("FN %s @%s refs=%d targets=%s" % (name, hx(k), len(refs), [hx(t) for t in tg]))

println("")
println("=== callers ===")
for k in sorted(fn_refs):
    fn = fm.getFunctionAt(af.getAddress(hex(k)[2:]))
    if fn is None: continue
    callers = fn.getCallingFunctions(monitor)
    cl = sorted(c.getEntryPoint().getOffset() for c in callers)
    println("FN @%s called by %d: %s" % (hx(k), len(cl), [hx(c) for c in cl]))

n = 0
for f in fm.getFunctions(True): n += 1
println("")
println("total functions: %d" % n)