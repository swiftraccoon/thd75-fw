# TH-D75 firmware/

Bare-metal ARM payloads for the TH-D75 (OMAP-L138, ARM926EJ-S). They can be
built and resolved into an offline `thd75-flash --dry-run --raw` plan, but raw
hardware writes are disabled until a payload has an allowed, verified USB-C or
Bluetooth return transport and a pinned artifact hash.

## Crates

| Crate         | Lints                   | Role                                                                                                                          |
| ------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `dumper-omap` | `deny(unsafe_code)`     | SoC register definitions + safe MMIO wrappers. The *only* crate where `unsafe { … }` blocks live, behind one reasoned allow.  |
| `dumper`      | `deny(unsafe_code)`     | NOR-flash dumper application. Zero `unsafe { … }` blocks; four reasoned allows on the unsafe *attributes* Rust 2024 mandates. |

Both crates target `armv5te-none-eabi` (Rust Tier-3). The nightly
toolchain pinned in `rust-toolchain.toml` is required because `core`
must be rebuilt from source for the Tier-3 target.

## Building

```bash
cd firmware
make            # cargo build --release + llvm-objcopy → target/.../dumper.bin
make lint       # cargo clippy + cargo doc + cargo fmt --check, all strict
make test       # regression tests for every boot-visible header/layout invariant
make audit      # inspect the built ELF + .bin and reject unsafe layout drift
make help       # list every target
```

First-time setup (one-time, by `rust-toolchain.toml`):

```bash
rustup show       # auto-installs the pinned nightly + components
```

## Hardware status: no-go

Do not flash the current `dumper.bin`. It is the existing NOR/framing payload
with a legacy physical-UART backend, not a USB dumper:

| Gate | Current evidence |
| --- | --- |
| Data source | Existing code reads the selected EMIFA-mapped NOR window. |
| USB-C transport | Missing. No USB controller, PHY, endpoint, descriptor, or CDC initialization exists. |
| UART0 route | Service manual: main MPU ↔ sub MPU, not USB-C. |
| UART1 route | Service manual: GPS AI2. |
| UART2 route | Service manual: Bluetooth HCI, not an external serial dump endpoint. |
| Boot image | Stock-shaped bytes pass static checks; actual D75 boot acceptance and descriptor semantics remain unconfirmed. |
| Host capture | `capture_dump.py` supports legacy `D75D`, strict raw `9R` modes, and USB-only `gm-nor-check`/`gm-nor-dump` for the exact `normal-gm-nor-read` artifact. None authorizes a device write. |

The CLI enforces this no-go: every `--raw` invocation is offline dry-run-only.
Only seven separately allowlisted plaintext KEX hashes can reach a real
hardware-write path: stock V1.03, service-9R, normal-GM DDR, normal-GM NOR,
normal-GM NOR USB-recovery V18, Azimuth automation, and Azimuth plus
orange-on-black. Each modified artifact
has a dedicated artifact-family acknowledgement; generic
`--yes` cannot satisfy it.

If native USB becomes necessary, it must refactor this payload's transport
backend rather than create another dumper. Build and audit commands are useful offline, but a
passing `make audit` proves static layout consistency only, not that the D75
will boot the image or enumerate USB.

Before native USB work reaches hardware, the required order is untouched-stock
raw `9R` baseline over USB-C; fixed SETUP positive controls; in a separate
power-cycled session, the exact mismatch/repeat control with expected result
`(1,0)`; retention of a verified stock restore artifact; and only then
consideration of the audited 19-byte modified-main `9R` path. The evidence
ledger and hardware session records for this work are kept outside the
repository.

The `9r-baseline` mode is the next untouched-stock USB-C check after explicit
authorization and recorded front-panel preflight: Menu 980 COM, Menus 405/590
PC Output Off, KISS/DV/DR inactive, and DV Gateway/interface recorded. The CLI
requires `--acknowledge-cat-preflight`, closes out shared-client ambiguity with
an exclusive exact-VID/PID USB open, and checks exact read-only `ID TH-D75` and
`FV 1.03` before service entry plus ID after exact exit. Because those handlers
also exist in service mode, clean entry must be silent; exact `0G` means the
session was already dirty and requires cleanup plus a full power-cycle. Baseline
also requires `--acknowledge-stock-v103-restored`, then performs duplicate
one-byte and one 256-byte `9R` reads. The standalone `9r-patched-check` remains
the first post-flash service operation. The full-dump mode is separately gated
to an already audited patched handler, re-runs the complete 1/16/256-byte and
bounds check, proves exact service exit and normal-CAT return, then enters a
fresh service session for its first full-read request and requires two identical
passes. No service `9E` command is implemented in this host tool.

The normal-GM NOR route stays in ordinary CAT and exposes no arbitrary address
argument. It first attests the exact flashed patch, then permits only the low
2 MiB candidate window. Its dump mode captures that range twice and publishes
only a byte-for-byte match. That exact route is now hardware-qualified:
`gm-nor-check` passed after a full power cycle, and two matching passes captured
the Boot Program and FLDM loader.

The exact `normal-gm-nor-read-usb-recover` V18 artifact is a separate
hardware-qualified main-firmware patch, not the bare-metal `dumper.bin`.
It corrects stock V1.03's off-by-one advertised SD capacity, preserves the
asynchronous storage lease, and services every multi-sector host READ through
bounded repeated stock CMD17 operations. On the tested TH-D75A and FAT32 card,
macOS automatically enumerated USB mass storage, mounted the volume, and
completed 93 read operations over 2,604 sectors with no firmware-side failure
or recovery.

## What gets dumped

If an allowed transport is implemented, the existing compile-time selection in
`dumper/src/main.rs::REGION` controls the source bytes:

* `LowNorCandidate` — CPU window `0x6000_0000..0x6020_0000` (2 MiB),
  covering the low NOR region excluded from normal main-firmware updates.
  This is the current default and candidate first capture; its D75 contents
  and partition boundaries are not yet known.
* `FullNor` — CPU window `0x6000_0000..0x6200_0000` (32 MiB).
* `Custom { start, len }` — arbitrary window (clamped to NOR).

## Architecture references

* Candidate boot-image layout: the closely related TH-D74 analysis documents
  `firmware_image_descriptor` / `firmware_image_finalization`; applying its
  runtime semantics to D75 remains a hypothesis. D75-specific byte positions
  are verified against official V1.03 update resources:
  vectors at `0x00`, FINAL_ZZZ at `0x40`, CHECKBYTES `B0 1D` at `0x62`,
  version at `0x80`, descriptors at `0xC0` and `0xE0`, erased padding
  through `0x1FF`, and code beginning at `0x200`.
  See acknowledgements in the top-level README for the prior D74
  reverse-engineering work this builds on.
* OMAP-L138 UART, NOR window, clock tree: TI OMAP-L138 TRM (SPRUH77).
* The flasher protocol the delivery rides on: `thd75-fw` crate's
  `flash/` subpackage; protocol-level notes are inline in the relevant
  source files (`flash/handshake.py`, `flash/protocol.py`,
  `flash/session.py`, `flash/segments.py`).

## Safety story

* `dumper-omap` contains all the `unsafe { … }` in this firmware workspace
  (three blocks, all in `registers.rs`). Each is paired with a
  `// SAFETY:` comment articulating the invariant. `#![deny(unsafe_code)]`
  + a single reasoned `#![expect]` on the module.
* `dumper` has zero `unsafe { … }` blocks. The crate's
  `#![deny(unsafe_code)]` is opted out of exactly four times, all on
  `#[unsafe(no_mangle)]` / `#[unsafe(link_section = "…")]` attributes
  that Rust 2024 requires for bare-metal entry/header placement —
  metadata declarations, not runtime unsafety. Each carries a reasoned
  `#[expect(unsafe_code, reason = "…")]`.
* `cargo clippy --release -- -D warnings` clean under
  `clippy::{all, pedantic, nursery, cargo}` denies (with one
  documented exception: `redundant_pub_crate` is allowed in the
  binary crate where it conflicts with `unreachable_pub`).
* `cargo doc --no-deps` clean under `RUSTDOCFLAGS="-D warnings"`.
* `cargo fmt --all -- --check` clean.
* The post-build NOR-address scan is an inventory, not a proof that every
  access is a read. The stronger runtime guard is `Reg32::write`, which
  refuses every address inside `0x6000_0000..0x6200_0000`; source review and
  disassembly inspection remain required before any hardware attempt.
