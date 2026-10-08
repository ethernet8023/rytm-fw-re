# Analog Rytm MKII replacement OS build
# Cross toolchain comes from nixpkgs pkgsCross.m68k; run via `nix-shell` or the
# just wrapper below. ColdFire v4 target: MCF5445x family (Rytm MKII).

CROSS   ?= m68k-unknown-linux-gnu-
CC      := $(CROSS)gcc
CXX     := $(CROSS)g++
# NOTE: the nixpkgs binutils *wrapper* ld segfaults on m68k; call ld.bfd from
# the binutils package directly (works, verified). gcc -c/-s are unaffected.
LD      := $(shell command -v $(CROSS)ld.bfd 2>/dev/null || echo $(CROSS)ld)
OBJDUMP := $(CROSS)objdump

ARCH    := -mcpu=54455
CFLAGS  := $(ARCH) -nostdlib -nostdinc -ffreestanding -fno-builtin \
           -fno-exceptions -fno-rtti -fno-unwind-tables -fno-asynchronous-unwind-tables \
           -fno-stack-protector -fno-pic -fdata-sections -ffunction-sections \
           -Wall -Wextra -O2 -g
LDFLAGS := $(ARCH) -nostdlib -Wl,--no-undefined -Wl,--gc-sections -T ld/rytm.ld \
           -Wl,-Map,rytmfw.map -Wl,--print-memory-usage

OBJS    := build/crt0.o build/hal.o build/display.o build/memprobe.o build/main.o

all: rytmfw.bin

build:
	mkdir -p build

build/%.o: src/%.s | build
	$(CC) $(ARCH) -c $< -o $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: src/%.cpp | build
	$(CXX) $(CFLAGS) -c $< -o $@

rytmfw.elf: $(OBJS) ld/rytm.ld
	$(LD) -T ld/rytm.ld --gc-sections -Map rytmfw.map $(OBJS) -o $@

rytmfw.bin: rytmfw.elf
	$(CROSS)objcopy -O binary $< $@
	@echo "== image head =="
	@$(OBJDUMP) -s -j .header $< || true
	@xxd -l 32 $@ 2>/dev/null || od -A x -t x1 -N 32 $@

disasm: rytmfw.elf
	$(OBJDUMP) -d rytmfw.elf | head -200

clean:
	rm -rf build rytmfw.elf rytmfw.bin rytmfw.map

.PHONY: all disasm clean
