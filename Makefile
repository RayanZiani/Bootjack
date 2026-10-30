# Makefile - CVE-2026-97631 DXE memory reader
#
# Linux host: build and run everything.
#   make                        payload.bin, pxeinj, pxerecv
#   make build/payload.bin      just the ring-0 blob
#
# Windows host: the simulator only, via Makefile.win.
#
# The sender and receiver are POSIX (AF_PACKET, IP_HDRINCL, termios) and are
# not expected to build on Windows; MSVC cannot compile them. The transmitter
# runs on the segment with the target, the simulator runs on the analysis
# machine.

CC      ?= cc
LD      ?= ld
OBJCOPY ?= objcopy
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -std=c11
CFLAGS  += -Iinclude -D_GNU_SOURCE
LDFLAGS ?=

BIN := build

all: $(BIN)/payload.bin $(BIN)/pxeinj $(BIN)/pxerecv

$(BIN):
	@mkdir -p $(BIN)

# ---- ring-0 blob -----------------------------------------------------------
# Assembled, linked at 0, then only .text extracted: no headers, no relocs, no
# padding.  Drops anywhere in a writable+executable DXE pool page.
$(BIN)/payload.o: src/payload.S | $(BIN)
	$(CC) -c -nostdlib -fPIC -o $@ $<

$(BIN)/payload.elf: $(BIN)/payload.o
	$(LD) -Ttext=0 -e payload_start --oformat elf64-x86-64 -o $@ $<

$(BIN)/payload.bin: $(BIN)/payload.elf
	$(OBJCOPY) -O binary --only-section=.text $< $@
	@printf "payload: %s bytes\n" "$$(wc -c < $@)"

# ---- host tools ------------------------------------------------------------
$(BIN)/pxeinj: src/main.c src/craft.c src/graft.c src/layout.c src/net.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN)/pxerecv: src/recv.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BIN)

.PHONY: all clean
