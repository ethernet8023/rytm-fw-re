#!/usr/bin/env python3
"""midi_sweep.py - test an FT232RL-based USB-MIDI OUT adapter.

Sends a chromatic note sweep (MIDI note on/off pairs) through a serial
port at 31250 baud 8N1 — the MIDI DIN wire format, no ALSA involved.

Usage (nix):
  nix shell --impure --expr 'with import <nixpkgs> {}; python3.withPackages (p: [p.pyserial])' \\
    -c python3 scripts/midi_sweep.py --port /dev/ttyUSB0

  --port   serial device (default: first /dev/ttyUSB*)
  --lo/--hi  sweep range (default 36..84, C2..C6)
  --ms     note duration (default 150)
  --ch     MIDI channel 1-16 (default 1)
"""
import argparse
import glob
import sys
import time

import serial


def open_port(port, baud=31250):
    ser = serial.Serial(
        port=port,
        baudrate=baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=1,
    )
    return ser


def note_on(ser, ch, note, vel=100):
    ser.write(bytes([0x90 | (ch - 1), note & 0x7F, vel & 0x7F]))
    ser.flush()


def note_off(ser, ch, note, vel=0):
    ser.write(bytes([0x80 | (ch - 1), note & 0x7F, vel & 0x7F]))
    ser.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port")
    ap.add_argument("--lo", type=int, default=36)
    ap.add_argument("--hi", type=int, default=84)
    ap.add_argument("--ms", type=int, default=150)
    ap.add_argument("--ch", type=int, default=1)
    ap.add_argument("--repeat", type=int, default=1)
    a = ap.parse_args()

    port = a.port
    if not port:
        candidates = sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))
        if not candidates:
            print("no /dev/ttyUSB* or /dev/ttyACM* found")
            sys.exit(1)
        port = candidates[0]
        print(f"auto: {port}")

    ser = open_port(port)
    print(f"{port} @ 31250 8N1 — sweeping notes {a.lo}..{a.hi} on ch {a.ch}, "
          f"{a.ms} ms each")

    for r in range(a.repeat):
        for note in range(a.lo, a.hi + 1):
            note_on(ser, a.ch, note)
            time.sleep(a.ms / 1000.0)
            note_off(ser, a.ch, note)
            time.sleep(0.03)
            print(f"\r  note {note:3d}", end="", flush=True)
        # all-notes-off just in case the receiver sustains
        ser.write(bytes([0xB0 | (a.ch - 1), 0x7B, 0x00]))
        ser.flush()
        print(f"\r  pass {r + 1}/{a.repeat} done")

    ser.close()
    print("ok")


if __name__ == "__main__":
    main()
