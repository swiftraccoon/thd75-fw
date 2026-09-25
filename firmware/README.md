# Firmware development and capture tools

[Project](../README.md) · [Patch catalog](../src/thd75_fw/patches/README.md) ·
[Flashing and recovery](../docs/FLASHING.md)

This directory contains the retained bare-metal Rust dumper, its static audit,
and the Python host capture tool. These are repository-checkout tools; they are
not installed by `pip install thd75-fw`.

| Task | Guide |
| --- | --- |
| Build and audit the Rust payload offline | [Building](#building) and [hardware status](#hardware-status-no-go) below |
| Check or capture low NOR using an existing supported firmware artifact | [Host capture](CAPTURE.md) |
| Build or implement a host for the Azimuth automation overlay | [Azimuth protocol and build reference](RADIO_AUTOMATION.md) |
| Choose a firmware patch or inspect its compatibility | [Patch catalog](../src/thd75_fw/patches/README.md) |

## Rust workspace

The payload targets the TH-D75's OMAP-L138 ARM926EJ-S. Both crates use
`armv5te-none-eabi`, a Rust Tier-3 target. The nightly toolchain pinned in
[`rust-toolchain.toml`](rust-toolchain.toml) is required to rebuild `core`.

| Crate | Role |
| --- | --- |
| [`dumper-omap`](dumper-omap/) | SoC register definitions and MMIO wrappers; contains the workspace's reviewed `unsafe` blocks. |
| [`dumper`](dumper/) | NOR dump framing and application; no `unsafe` blocks. |

## Building

Use a repository checkout with Rust installed through rustup, Make, and Python
3.10 or newer. Use the rustup-managed `cargo` and `rustc` on `PATH` so the local
toolchain pin takes effect. Install the Python package in your development
environment for the host-tool tests' dependencies:

```bash
python3 -m pip install -e .
cd firmware
rustup show     # install/select the pinned nightly and components
make            # release build + llvm-objcopy → target/.../dumper.bin
make lint       # strict clippy, rustdoc, and rustfmt checks
make test       # Python audit and capture-tool regression tests
make audit      # inspect the built ELF and .bin for layout drift
make help       # list targets
```

For descriptor and packet inspection without a serial connection, from the
repository root:

```bash
thd75-flash --dry-run --raw firmware/target/armv5te-none-eabi/release/dumper.bin \
  --flash-addr 0x00200000 --complete-code 0x1DB0
```

## Hardware status: no-go

Do not flash the current `dumper.bin`. Its return transport is a legacy physical
UART backend, and raw hardware writes are disabled by `thd75-flash`.

| Gate | Current evidence |
| --- | --- |
| Data source | Reads the selected EMIFA-mapped NOR window. |
| USB-C transport | No USB controller, PHY, endpoint, descriptor, or CDC initialization exists. |
| UART0 route | Service manual: main MPU ↔ sub MPU. |
| UART1 route | Service manual: GPS AI2. |
| UART2 route | Service manual: Bluetooth HCI, not an external serial dump endpoint. |
| Boot image | Stock-shaped bytes pass static checks; actual D75 boot acceptance and descriptor semantics remain unconfirmed. |

A passing `make audit` proves static layout consistency. It does not establish
that the radio will boot the payload or enumerate USB. Any future native USB
implementation belongs in this payload's transport backend and needs separate
artifact and transport qualification before hardware use.

The Python capture routes use supported stock or patched main firmware and have
their own [prerequisites and evidence](CAPTURE.md). Their status does not clear
the Rust payload for flashing. See the [flashing guide](../docs/FLASHING.md) for
the real-write policy and [stock recovery](../docs/FLASHING.md#stock-recovery).

## Dump regions

If an allowed transport is implemented, the compile-time selection in
[`dumper/src/main.rs`](dumper/src/main.rs) controls the source bytes:

- `LowNorCandidate` — CPU window `0x6000_0000..0x6020_0000` (2 MiB), the
  default low-NOR region excluded from normal main-firmware updates. This region
  has been captured through the separate normal-GM route; see
  [capture evidence](CAPTURE.md#capture-evidence) for known slot boundaries.
- `FullNor` — CPU window `0x6000_0000..0x6200_0000` (32 MiB).
- `Custom { start, len }` — a selected window clamped to NOR.

## Architecture and audit limits

The candidate boot-image layout draws on related TH-D74 analysis. Applying its
runtime semantics to D75 remains a hypothesis. D75-specific byte positions are
verified against official V1.03 update resources: vectors at `0x00`, FINAL_ZZZ at
`0x40`, CHECKBYTES `B0 1D` at `0x62`, version at `0x80`, descriptors at `0xC0` and
`0xE0`, erased padding through `0x1FF`, and code beginning at `0x200`. The captured
low-NOR bytes establish slot boundaries; exact boot validation, copy length, and
entry semantics remain unresolved.

Both Rust crates deny unsafe code. The MMIO module contains three reviewed
`unsafe` blocks with `SAFETY` comments. The application has four reasoned
exceptions for Rust 2024 entry-point and linker-section attributes. The
post-build NOR-address scan is an inventory, not proof that every access is a
read. `Reg32::write` rejects addresses inside `0x6000_0000..0x6200_0000`; source
review and disassembly inspection remain necessary before any hardware attempt.

See the [format and memory-map reference](../docs/FORMAT.md), the
[prior-work references](../docs/FORMAT.md#references-and-prior-work), and the
[`flash` Python package](../src/thd75_fw/flash/) for the updater protocol.
