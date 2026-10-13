# USB reflash: kill the DIN dependency

**Goal:** the custom OS owns USB — it receives an OS image over USB into RAM,
verifies it, writes the MAIN OS section to flash, and reboots. Every future
reflash becomes a 30-second USB job; the FT232RL DIN adapter retires to the
toolbox (kept as the safety net, never removed).

## Why this is tractable

1. **The bootstrap IS the flash driver spec.** `section_2_bootstrap.bin`
   (42 KB) contains the complete upgrade path: receive syx from MIDI UART →
   parse ELE3 container → per-packet checksums → decompress → write flash →
   reboot. RE it once and we know: flash controller type, erase/program
   command sequences, section layout on flash, acceptance checks. A 42 KB
   binary is a small RE target — the 3 MB MAIN OS was the hard one and it's
   done.
2. **The USB controller is documented publicly.** MCF5445x reference manual
   (NXP/Freescale, free PDF) has the full USB 2.0 OTG module programming
   model. We only need device mode + one bulk endpoint pair.
3. **No class compliance needed.** Host side is OUR `flash_rytm.py`. A
   vendor-specific bulk OUT (file data) + bulk IN (ack) interface is
   dramatically simpler than USB-MIDI class descriptors — and we control
   both ends forever.
4. **Staging memory is proven.** The 16.3 MB hole at 0x41ad0000
   (hardware memprobe PASS) holds the whole 1.88 MB stock image with room
   to spare.
5. **Stock init pokes are copyable.** Same trick as alpha4: pull the
   USB/clock/pinmux init pokes verbatim from stock's entry code.

## Safety argument (the invariant that matters)

- We flash ONLY the MAIN OS section (id 3). Bootstrap (id 2) + FPGA (id 1)
  ship byte-identical and are never written.
- Therefore FUNC+power → OS UPGRADE → DIN recovery remains available at
  every moment of the procedure, including mid-write power loss.
- Worst case (power loss during OS-section write) = corrupt OS section =
  exactly the state we already recovered from once, with a proven DIN rig.
- Every stage below is testable without writing a single flash byte until
  stage 4.

## Architecture

```
host (flash_rytm.py --usb, pyusb/libusb)
   │  vendor bulk OUT: file chunks (page-sized)
   │  vendor bulk IN:  per-chunk ack (crc32) / status
   ▼
device (our OS, running from DDR 0x40000400)
   1. USB device controller up (clock/PHY pokes verbatim from stock init;
      controller per MCF5445x RM: device mode, 1 config, bulk OUT+IN)
   2. receive chunks → ring buffer → assemble into 0x41ad0000 staging
   3. validate: ELE3 container + per-packet checksums + section CRCs
      (format fully decoded — same checks the bootstrap receiver does)
   4. flash-write MAIN OS section (driver RE'd from bootstrap stage 1)
   5. readback-verify the written section
   6. warm reboot → bootstrap loads new OS
```

Display shows progress at every step (we have the display driver).

## Work plan

### Stage 1 — RE, no hardware (solo-able)
- [x] Import `section_2_bootstrap.bin` into the ghidra project at base
      0x80000000 (it executes from SRAM there). DONE — 169 functions,
      full MMIO census in `analysis/output/bootstrap_mmio.txt`.
- [x] Find the flash writer: **SPI NOR on DSPI 0xfc05c000**, multi-vendor
      JEDEC (Winbond/Macronix/ISSI). **Flash layout decoded: bootstrap+FPGA
      at 0x0–0x7FFFF, MAIN OS at 0x80000+**; staged at DDR 0x3FF80008
      (size@0x40000000, checksum@0x40000004); erase 256KB blocks, program
      512B units. Deliverable: `docs/flash-driver.md`.
- [ ] Extract the bootstrap's acceptance checks (version >=, section count)
      so our receiver validates the same way.
- [ ] Pull MCF5445x RM USB chapter → register list + init sequence skeleton.
- [ ] In the 3 MB MAIN OS: locate stock's USB init (clock/pinmux/PHY pokes)
      and copy those poke sequences verbatim (same pattern as alpha4's
      display/clock pokes).

### Stage 2 — USB enumeration only (first hardware touch)
- [ ] alpha5-usb: minimal OS that brings up the USB device controller,
      enumerates with our descriptors, and shows "USB UP" on the display.
- [ ] Success = `lsusb` shows OUR vendor ID/device on the unit.
      Zero flash writes. Flash over USB (the normal path), test, DIN
      restore if needed (proven).

### Stage 3 — receive to RAM
- [ ] Extend: bulk OUT receive → staging buffer, per-chunk CRC32 ack on
      bulk IN. Host = `flash_rytm.py --usb --send FILE`.
- [ ] Success = display shows received byte count + container CRC OK for
      the full stock image. Still zero flash writes.

### Stage 4 — flash write + reboot (the feature IS the test)
- [ ] Port the stage-1 flash driver: erase OS section, program, readback.
- [ ] Receive stock 1.74 over USB, flash it, reboot → unit boots stock.
      Then flash our own OS back over USB the same way.
- [ ] Update `scripts/flash_rytm.py`, STATUS.md, the skill, and modwerk
      profile (recovery section gains the custom-OS USB path).

## Effort estimate (honest)

- Stage 1: ~2 evenings of RE. Bootstrap is 42 KB with a known job
  (receive→verify→write), and we already speak its container format.
- Stages 2–3: ~2–3 evenings of C++ + wire debugging (enumeration is the
  fiddly part — descriptor mistakes are cheap but tedious).
- Stage 4: 1 careful evening, flash write + readback + reboot.
- Total: roughly 1–2 weeks of evening sessions. Not one night, but every
  stage is independently shippable and none is risky until the last.

## Deferred / out of scope

- USB-MIDI *class* compliance (Transfer/C6/DAW visibility): the bulk stack
  built here is the foundation; class descriptors are a later rider.
- Writing bootstrap/FPGA sections: never. That's the safety net.
- +Drive-based upgrade path (bootstrap may or may not support reading an
  image from +Drive — worth a look during stage 1 as a curiosity, but the
  direct flash write is the design).
