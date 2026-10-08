# Analog Rytm MKII mod-core: interface draft (modwerk elemod shape)

Work-in-progress interface for a future Analog Rytm MKII core, in the shape
of modwerk's `core/interface.json` (see their digitakt core for the format).
All addresses are stock OS 1.74 facts; nothing here ships firmware.

## Events (hook sites found by RE)

| event | stock mechanism | hook |
|---|---|---|
| `ev_key` | view vtable +0x08, `int f(view, event)`; event {+0xc key, +0x10 flags bit0=pressed, long-press flag}; nonzero = consumed | wrap active view's vtable slot, or intercept queue-4 nodes |
| `ev_enc` | IRQ FUN_400040ae stores per-source deltas at 0x42f67a4c+(src&0x1f)*8; subscribers list 0x413db378 | subscribe to 0x413db378 list |
| `ev_draw` | view vtable +0x10 render(view,bmp); screen planes: 1024B @ front 0x4191fbc8 / back 0x4191ffc8 (column-major, MSB-top) | wrap vtable +0x10 or hook present fn FUN_40095a5e |
| `ev_tick` | prio-4 dispatcher FUN_40005380 walks 8 slot-pending bits 0x42f67b60; slot registration via FUN_40003c0a | register a slot callback (0x42f67b64+4*i) |
| `ev_settings` | view registry tables at 0x401c-0x401e (data-driven menus; base ctor FUN_400784c8, 61 view types) | append view entries |
| `ev_input_raw` | event queues: 8 queues, masks 0x401bf1b8, nodes {value,+8; cb,+9; arg,+0xc; magic 0xdead0001}, enqueue FUN_40003d24(queue,node), node alloc FUN_4000396a (pool 0x413db3a8) | enqueue nodes w own callbacks — the cleanest hook |

## Memory budgets (from reference scan, mem_scan2)

- **Mod memory (primary):** 0x41ad0000-0x42abffff — 16.3 MB contiguous,
  zero static references from stock OS. Candidate for core + mods code/data.
- Secondary: 0x407d0000-0x412cffff (11 MB), 0x413f0000-0x415dffff (2 MB),
  0x415f0000-0x417dffff (2 MB).
- **Fast memory:** FPGA SRAM 0x80000000-0x8000ffff: stock uses it densely
  (display, LED engine, event queues, codec buffers) — 0x8000c000-0x8000dfff
  are the sparsest blocks (99/56 refs); needs hardware probe before claim.
- Untested-above: 0x4b940000-0x4fffffff (70 MB) — unknown if mapped.
- **All static-analysis only**: heap arenas grow at runtime; probe on
  hardware (write/read/verify patterns from alpha OS) before claiming.

## Claims vocabulary (modwerk shape)

- view-slot (wrap active view vtable)
- event-queue id 0..7 (subscribe)
- encoder source 0..31 (0x42f67a4c)
- settings row (view registry entry)
- mod-memory region (bounded, from budget above)

## Patch-site extraction

Build spec needs address + length + SHA-256 of stock bytes per patch site.
Stock bytes never committed; the extractor (to write) reads them from the
owner's own extracted section 3. Candidate patch sites for the core:
- view-stack dispatch (active view global) — TBD after handoff link confirmed
- FUN_40004294 parser entry (intercept point)
- FUN_40095a5e present (draw hook)
- queue-4 pump loop in FUN_400050dc

## Open items (hardware or further RE)

1. view->key handoff: which parser handler builds {key@+0xc, flags@+0x10}
   and calls vtable+8 on the active view — trace FUN_40004192's subscribers
   or run with hardware logging.
2. packed event word -> physical button map (0x80060001..06 etc) — needs
   hardware: press buttons, log mailbox 0x42f67b54/58.
3. fast-SRAM safe blocks — write/read probe on hardware.
4. active-view global address — find the view-stack head (FUN_400784c8's
   registry or FUN_4007871e's member init) to know where to read/patch it.
