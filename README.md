# CVE-2026-97631: pre-boot DXE memory reader

Tooling for the EDK II PXE Base Code driver ICMP error overflow
(`NetworkPkg/UefiPxeBcDxe`, GHSA-99cj-7hg9-mp4m, CVSS 4.0 9.5).

During a PXE boot the driver copies an ICMP error message into a fixed 504-byte
buffer. A longer message becomes a linear write past that buffer, into the DXE
pool. Because the write destination is the buffer's own address, the payload is
position independent: byte *i* of the datagram lands at `&Mode->IcmpError + i`.
The overflow plants a counterfeit `EFI_EVENT`; the DXE core dispatches it
through the normal `CoreSignalEvent` path; the payload restores the event from a
snapshot, walks operator-chosen memory ranges, and returns `EFI_SUCCESS` so the
boot continues.

Blast radius stays inside the firmware's own DXE memory. No flash write, no
persistence mechanism, no OS artifact.

## Layout

```
include/pxe_layout.h   EFI_PXE_BASE_CODE_ICMP_ERROR, IEVENT offsets, wire structs
include/craft.h        one packet = one primitive
include/graft.h        counterfeit event + payload parameter block
include/layout.h       the overflow region (single source of truth)
src/payload.S          ring-0 payload: restore, walk ranges, stream out
src/craft.c            packet construction, IPv4 + IPv6
src/graft.c            IEVENT overlay, parameter block
src/layout.c           overflow assembly, shared by sender and simulator
src/main.c             pxeinj: sniff xid, probe, send
src/net.c              raw L3 transport, DHCP xid sniffer
src/recv.c             pxerecv: serial collector, dump + map
sim/sim.c              host harness that proves the chain
tools/fw_offsets.py    pool offsets from a debug firmware build
```

## Build

Payload:

```
as --64 -o build/payload.o src/payload.S
ld -Ttext=0 -e payload_start --oformat elf64-x86-64 -o build/payload.elf build/payload.o
objcopy -O binary --only-section=.text build/payload.elf build/payload.bin
```

Result is 378 bytes, position independent, no relocations.

Sender and receiver are POSIX (`AF_PACKET`, `IP_HDRINCL`, termios) and build
with `make` on Linux. The simulator builds with MSVC via `Makefile.win`:

```
cl /nologo /W3 /O2 /Iinclude /Fe:build\sim.exe sim\sim.c src\craft.c src\graft.c src\layout.c
```

## The chain, as proven by the simulator

`build/sim.exe` maps a fake pool page, writes the overflow where the vulnerable
`memcpy` would, checks the resulting `IEVENT` would dispatch the payload, calls
the payload as real machine code, and then verifies:

- the event is restored byte for byte
- the dumped bytes equal the source range
- the open/close frames are intact, so a truncated dump is distinguishable
- a dead UART does not hang the call
- the ICMP datagram checksums verify and the overflow lands at the offset the
  driver copies from
- the embedded BOOTP xid survives verbatim

26 checks over layout, ABI, framing and packet construction. This proves the
parts agree with each other. It does not prove a specific firmware's pool
address, which is a runtime allocation.

## Operation

Two modes, used in order.

**Probe**: legal path only, no out-of-bounds write.

```
pxeinj --target 10.0.0.50 --spoof 10.0.0.1 --sniff --probe --send
```

A 504-byte, well-formed ICMP error. Same spoof, same embedded BOOTP transaction,
same everything. If the client keeps booting, the error was accepted and the
vulnerable copy loop was reached. Non-destructive confirmation, and it needs no
pool address.

**Overflow**: refuses to build until three things exist: the pool base
(`tools/fw_offsets.py`), the pristine event bytes (`--shadow`), and at least one
range.

```
pxeinj --target 10.0.0.50 --spoof 10.0.0.1 --xid 0xdeadbeef \
       --pool-base 0x7f12345000 --payload build/payload.bin \
       --ranges ranges.txt --shadow shadow.bin --uart 0x3f8 --send

pxerecv -d /dev/ttyUSB0 -o dump.bin -m dump.map
```

`ranges.txt` is one `START-END` per line, hex without `0x`; see
`ranges.example.txt` for the size and time budget. The v6 overflow path is
disabled: probe works over v6, the write does not, until the v6 copy bound has
been re-derived from the patched source.

## Why it is quiet

- no Boot Services allocation, logging, or lock inside the payload
- no IDT/GDT/CR/MSR edits, no interrupt hooks, no debug registers
- the object is restored before the dump starts, not after
- output is polled UART, so nothing lands in a firmware-managed buffer
- returns `EFI_SUCCESS` on the normal notify path, so the boot proceeds
- the event's `SignalLink` is self-consistent, so the list walk does not assert

Residual traces are inherent to the bug: the event was signalled at a time it
would not normally be, the pool page stays dirty, and if the platform measures
DXE with a TPM the PCR value is whatever it was when the boot started. Anything
beyond that is not a property of this bug.

## Safety rails in the code

- `--send` is required; the default is a dry run
- the overflow refuses to build without `--pool-base`, `--payload`, `--shadow`
  and a non-empty range list. Each of those has a specific way to corrupt the
  firmware if guessed, so none is optional
- `--shadow` must contain an `EFI_EVENT` signature at the expected offset, which
  catches a zero-filled file and a wrong `--event-off` in one check instead of
  at dispatch time
- the probe is a separate mode and cannot write out of bounds
- the UART poll is bounded, so a missing 16550 cannot hang a boot; once the
  estimate is exhausted the UART is dropped and the RAM sink, if any, carries on
- the close frame makes truncation visible instead of silent

## Limits

- The pool address of `Mode->IcmpError` is a runtime allocation and differs per
  firmware build. It cannot be derived from a link map. `tools/fw_offsets.py`
  gives the offsets; the base has to be measured on the target firmware, for
  example from a `DEBUG_POOL` trace, and then cached.
- `sizeof(EFI_PXE_BASE_CODE_MODE)` and `offsetof(..., IcmpError)` change between
  edk2 releases. The defaults in `tools/fw_offsets.py` are starting points, not
  values to trust.
- The exact expression the flawed copy bound is computed from is not stated in
  the advisory, and the fix (#13302) changes it. Read the two `DpcHandle`
  functions in the target tree before relying on the overflow offset.
- Restoring the event requires a snapshot taken before the overflow. Without it
  the restore writes zeroes and leaves a corrupt event in the core's signal
  list, which the next `CoreSignalEvent` walks into. The tool refuses to build
  without `--shadow` for this reason.
