# Analog Rytm MKII UI view system (OS 1.74)

Decoded from static analysis; this is the surface a mod core would hook for
`ev_key` / `ev_draw` / `ev_settings` equivalents.

## View objects

Views are C++-style objects: word[0] = vtable pointer, installed by the base
ctor `FUN_400784c8(view, name)` (61 callers = one per view type). The base
vtable lives at `0x401d77d4`; views override it with their own (e.g. the
UI-test view's vtable at `0x40235f9c`).

Vtable layout (slots, offset from vtable base):

| slot | base impl | meaning |
|---|---|---|
| +0x00 | 0x4007871e | enter / install (inits member objects) |
| +0x04 | 0x400787d6 | push (calls enter + frees old) |
| +0x08 | 0x4007843a | **key handler** `int f(view, event)` |
| +0x0c | 0x400783fc | get-attr (returns view+0x28) |
| +0x10 | 0x40078406 | **render** `f(view, bmp)` |
| +0x14 | 0x40078408 | (nop default) |
| +0x18 | 0x4007880c | open modal: view+0x2c=arg, notify list at view+0x34..0x38 |
| +0x1c | 0x4007840a | (nop default) |
| +0x20 | 0x4007887c | modal teardown: notify list at view+0x40..0x44, clear arg |
| +0x24 | 0x40078416 | set flag (view+0x16) |
| +0x28 | 0x40078422 | get flag (view+0x16) |
| +0x2c | 0x40078624 | busy/lock check (uses FUN_40078600(view, 7)) |
| +0x30 | 0x4007842c | (nop default) |
| +0x34/+0x38/+0x3c | 0x4007842e/32/36 | **arrow key handlers** (default: return 0) |
| +0x40/+0x44 | 0x400789aa/b6 | modal helper (FUN_4018a69c) |
| +0x50/+0x54 | 0x400787b2/f0 | destructors (enter-inverse) |

## Key events

Event struct: `+0x0c` = key code (u32), `+0x10` = flags (bit0 = pressed).
Accessors (all take event ptr):
- `FUN_40071efc(e)` — key code
- `FUN_40071fa0(e)` — pressed
- `FUN_40071f70(e)` — released (`flags&1 ^ 1`)
- `FUN_40071f90(e)` — long-press / repeat flag

Key handler contract (from default `0x4007843a` and UI-test `0x4013dee6`):
- called as `int handler(view, event)`
- check pressed + long-press flags, switch on key code
- arrows (0x50 up / 0x51 left? / 0x52 right?) dispatch to vtable +0x34/+0x38/+0x3c
- **returns nonzero = event consumed** — the modwerk `ev_key` semantic

Known key codes (from the UI-test key table at 0x40235f00 and handler
switches): arrows 0xa0-0xa5 and 0x50/0x51/0x52, YES 0x44, encoders 0x40-0x45,
function keys 0xae/0xbb/0xbd-0xbf/0x50/0x70-0x73, trigs 0x10-0x1b.

## Post-key / dirty protocol

- `FUN_40078580(view)`: if not locked (view+0x17), set dirty flag view+0x14 = 1;
  if a modal arg is pending (view+0x2c), call `FUN_400790c6` (sets view+0x20 = 1).
- Every key handler calls `FUN_40078580` + `FUN_400785b8` at the end — the
  same "mark recompose" concept as Digitakt's `ctrl+0x20`.

## Input pipeline (FOUND — the producer + pump)

The complete chain, decoded end to end:

1. **FPGA -> SRAM**: input events land at FPGA SRAM `0x80002028/0x8000202c`
   (32-bit each, byte-swapped on pickup). The FPGA raises an interrupt via
   the EPORT-ish region `0xfc0b01xx`.
2. **IRQ handler `FUN_400040ae`** (installed via vector slot `_DAT_40000344`):
   reads `0xfc0b014c` (counter), stores per-source deltas at
   `0x42f67a4c + (src&0x1f)*8` (encoder positions, 32 sources), fires the
   subscriber list at `0x413db378`.
3. **Input pump `FUN_400050dc`** (zero callers, installed at vector
   `_DAT_40000218` — IRQ context): on FPGA-pending flag `0xfc0b01ac` it
   byteswaps `0x80002028/2c` into the mailbox `0x42f67b54/58`, then calls
4. **Event parser `FUN_40004294`**: dispatches on packed event words
   (`0x80060001..06`, `0x21200000`, `0x090000`, `0x10b0000`, `0x2030000`,
   `0x21010000`, `0x40030000`, ...) to per-type handlers; some go straight to
   view stack ops (`LAB_40004216/21c`), some to dedicated fns
   (`FUN_400041ce(value,arg)`, `FUN_400041e0`, `FUN_400035ca`).
5. **8 event queues** (`0x401bf1b8` = 8 masks; heads at `0x80002008+i*4`,
   tails `0x8000200c+i*4`, pending `0x80002030/34+i*4`; queue index map
   `0x401bf194[queue_id]`; IRQ acks `0xfc0b01b0/0xfc0b01b8`, timestamps
   `0xfc0b014c`): 0x40-byte nodes `{link(0), seq|flags(+4/+7), value(+8),
   callback(+9), arg(+0xc), pre-fn(+0xe), magic 0xdead0001}`, pool free-list
   at `0x413db3a8`, node dtor FUN_40003906.
6. **Queue 4 = UI events**: `FUN_400041e0` / `FUN_40004192` / `FUN_40003e80`
   build nodes with `node[8] = key value`, `node[9] = handler fn` and push
   them to queue 4; the pump fires `handler(value, arg)` from IRQ context.
   Event payload scratch: rotating 4-slot buffer at `_413db29c*0x1000 +
   0x4b823000`.

**Core hook candidates**: subscribe to the 8 event queues (natural mod
surface), or intercept `FUN_40004294` dispatch (patch site), or wrap the
view vtable key slot (+0x08) of the active view.

**Needs hardware**: mapping packed event words (0x8006xxxx etc) to physical
buttons/pads, and confirming which handler delivers to view->key with the
{key@+0xc, flags@+0x10} struct.
