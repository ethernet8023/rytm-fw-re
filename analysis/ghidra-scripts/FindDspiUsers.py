# FindDspiUsers.py - Ghidra headless script: list functions referencing DSPI regs
# @category Analysis
# 针对: Elektron Rytm MKII MAIN OS (ColdFire, base 0x40000400)
targets = [0xfc05c000, 0xfc05c02c, 0xfc05c034, 0xfc05c038, 0xfc044000, 0xfc04c000, 0xfc048000, 0xfc04d000]

fm = currentProgram.getFunctionManager()
refmgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()

out = []
for f in fm.getFunctions(True):
    body = f.getBody()
    addr = f.getEntryPoint()
    hits = {}
    it = body.addresses() if hasattr(body, 'addresses') else None
    # iterate instructions
    ins = listing.getInstructions(body, True)
    while ins.hasNext():
        i = ins.next()
        for op in range(0, i.getNumOperands()):
            for ref in i.getOperandRefs(op) if hasattr(i, 'getOperandRefs') else []:
                pass
    # simpler: use reference manager for ref to targets
for t in targets:
    a = currentProgram.getAddressFactory().getAddress(hex(t)[2:])
    for ref in refmgr.getReferencesTo(a):
        from_addr = ref.getFromAddress()
        fn = fm.getFunctionContaining(from_addr)
        if fn:
            out.append((hex(t), hex(from_addr.getOffset()), fn.getName(), hex(fn.getEntryPoint().getOffset())))
# dedupe
seen = {}
for t, site, name, ep in out:
    seen.setdefault((name, ep), set()).add(t)
for (name, ep), ts in sorted(seen.items(), key=lambda kv: kv[0][1]):
    print("%s @%s -> refs: %s" % (name, ep, sorted(ts)))