# Convenience build wrapper for the firmware/ workspace.
#
# All real work is done by `cargo`; this Makefile exists so a single
# `make` produces both the linked ELF and the stripped flat `.bin`
# the flasher consumes. It also wraps the lint gates so CI can call
# `make lint` and get a single pass-or-fail.

CARGO         ?= cargo
PYTHON        ?= python3
RUSTDOCFLAGS  := -D warnings

# Locate `llvm-objcopy` from the rustup nightly toolchain (installed
# by the `llvm-tools-preview` component pinned in rust-toolchain.toml).
LLVM_OBJCOPY  := $(shell rustup which --toolchain nightly-2026-05-20 llvm-objcopy 2>/dev/null \
                  || find "$$HOME/.rustup/toolchains" -name llvm-objcopy -type f 2>/dev/null | head -1)

TARGET        := armv5te-none-eabi
TARGET_DIR    := target/$(TARGET)/release
ELF           := $(TARGET_DIR)/dumper
BIN           := $(TARGET_DIR)/dumper.bin

.PHONY: all build bin lint clippy doc fmt fmt-check test audit clean help

all: bin  ## build + strip (default target)

build:  ## cargo build --release
	$(CARGO) build --release

bin: build  ## strip the linked ELF to a flat .bin for flashing
	@if [ -z "$(LLVM_OBJCOPY)" ]; then \
	    echo "error: llvm-objcopy not found — install with: rustup component add llvm-tools-preview --toolchain nightly-2026-05-20" >&2; \
	    exit 1; \
	fi
	$(LLVM_OBJCOPY) -O binary $(ELF) $(BIN)
	@printf "%s: %d bytes\n" "$(BIN)" "$$(wc -c < $(BIN))"

clippy:  ## strict clippy (deny warnings)
	$(CARGO) clippy --release -- -D warnings

doc:  ## strict cargo doc (warnings are errors)
	RUSTDOCFLAGS="$(RUSTDOCFLAGS)" $(CARGO) doc --no-deps

fmt:  ## apply rustfmt
	$(CARGO) fmt --all

fmt-check:  ## verify rustfmt would not change anything
	$(CARGO) fmt --all -- --check

lint: clippy doc fmt-check  ## full lint gate (clippy + doc + fmt-check)
	@echo "lint: OK"

test: bin  ## unit-test boot-image audit regressions
	$(PYTHON) -m unittest discover -v -s tests -p 'test_*.py'

audit: bin  ## post-build safety audit (header/layout, DDR, NOR inventory)
	@$(PYTHON) audit.py

clean:  ## cargo clean
	$(CARGO) clean

help:  ## list targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
