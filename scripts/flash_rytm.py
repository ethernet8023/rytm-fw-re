#!/usr/bin/env python3
"""flash_rytm.py - send an OS .syx to the Analog Rytm MKII over USB MIDI.

Usage:
  nix shell nixpkgs#alsa-utils --run 'true'   # not needed, mido brings rtmidi? no:
  # deps: python3 with `mido` + `python-rtmidi`:
  #   nix shell --impure --expr 'with import <nixpkgs> {}; python3.withPackages (p: [p.mido p.python-rtmidi])' \
  #     -c python3 scripts/flash_rytm.py --send RytmFW-alpha3.syx

  --send FILE      send a .syx (paced)
  --probe          send a MIDI identity request, report reply/no-reply
  --wait-reboot    after --send, wait for the MIDI port to disappear and return
  --list           just list MIDI ports and exit
  --delay MS       inter-sysex-message delay (default 3 ms)

Notes:
  - The unit asks you to press YES to accept the upgrade; that press is
    manual by design (bootstrap safety gate). Everything else is automated.
  - Stock OS replies to the identity request; a from-source OS that has no
    MIDI handler will stay silent -- pair --probe with the screen pattern.
"""
import argparse
import sys
import time

import mido

RYTM_HINTS = ("rytm", "analog")

def find_rytm_out():
    names = mido.get_output_names()
    for n in names:
        low = n.lower()
        if any(h in low for h in RYTM_HINTS):
            return n
    return None

def find_rytm_in():
    names = mido.get_input_names()
    for n in names:
        low = n.lower()
        if any(h in low for h in RYTM_HINTS):
            return n
    return None

def load_sysex(path):
    """Parse a .syx into individual F0..F7 messages (bytes)."""
    data = open(path, "rb").read()
    msgs, start = [], None
    for i, b in enumerate(data):
        if b == 0xF0:
            start = i
        elif b == 0xF7 and start is not None:
            msgs.append(bytes(data[start:i + 1]))
            start = None
    if start is not None:
        print(f"warning: unterminated sysex ({len(data) - start} bytes) dropped")
    return msgs

def send(path, delay_ms, wait_reboot):
    msgs = load_sysex(path)
    print(f"{path}: {len(msgs)} sysex messages")
    port = find_rytm_out()
    if port is None:
        print("no Analog Rytm MIDI output port found; ports:")
        for n in mido.get_output_names():
            print("  ", n)
        sys.exit(1)
    print("sending to:", port)
    t0 = time.time()
    with mido.open_output(port) as out:
        for i, raw in enumerate(msgs):
            out.send(mido.Message.from_bytes(list(raw)))
            if i % 500 == 0:
                print(f"  {i}/{len(msgs)}  {time.time()-t0:.1f}s", flush=True)
            time.sleep(delay_ms / 1000.0)
    print(f"sent {len(msgs)} messages in {time.time()-t0:.1f}s")
    print("-> press YES on the unit to accept the upgrade")
    if wait_reboot:
        wait_reboot_()

def wait_reboot_(timeout=180):
    """Wait for the rytm MIDI port to disappear (reboot) and come back."""
    print("waiting for reboot (port drop + return)...")
    t0 = time.time()
    # phase 1: wait for disappearance
    while time.time() - t0 < timeout:
        if find_rytm_out() is None:
            print("  port gone: unit is rebooting")
            break
        time.sleep(0.5)
    else:
        print("  timeout waiting for reboot (did you press YES?)")
        return
    # phase 2: wait for return
    while time.time() - t0 < timeout:
        p = find_rytm_out()
        if p is not None:
            print(f"  port back after {time.time()-t0:.1f}s: {p}")
            return
        time.sleep(0.5)
    print("  timeout waiting for port to return")

def probe(timeout_s=5.0):
    """Generic MIDI identity request (F0 7E 0C 06 01 F7). Stock replies."""
    out_name, in_name = find_rytm_out(), find_rytm_in()
    if not out_name:
        print("no rytm output port")
        sys.exit(1)
    inp = mido.open_input(in_name) if in_name else None
    try:
        with mido.open_output(out_name) as out:
            if inp is not None:
                # drain clock/active-sensing noise for a moment first
                t_drain = time.time()
                while time.time() - t_drain < 0.5:
                    for msg in inp.iter_pending():
                        pass
            out.send(mido.Message.from_bytes([0xF0, 0x7E, 0x0C, 0x06, 0x01, 0xF7]))
            t0 = time.time()
            if inp is None:
                print("identity request sent (cannot listen for reply)")
                return
            while time.time() - t0 < timeout_s:
                for msg in inp.iter_pending():
                    if msg.type == "sysex":
                        print("identity reply:", " ".join(f"{b:02X}" for b in msg.bytes()))
                        return
                    # non-sysex (clock etc): ignore, keep listening
                time.sleep(0.1)
            print("no sysex reply (stock OS answers identity; a custom OS"
                  " with no MIDI handler stays silent)")
    finally:
        if inp is not None:
            inp.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--wait-reboot", action="store_true")
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    if a.list or (not a.send and not a.probe):
        for n in mido.get_output_names():
            print("out:", n)
        for n in mido.get_input_names():
            print("in: ", n)
        return
    if a.send:
        send(a.send, a.delay, a.wait_reboot)
    if a.probe:
        probe()

if __name__ == "__main__":
    main()
