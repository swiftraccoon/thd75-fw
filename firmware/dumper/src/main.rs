//! TH-D75 NOR-flash dumper payload.
//!
//! # What this is
//!
//! A bare-metal ARM candidate intended to replace the main-firmware slot,
//! run from DDR (`0xC000_0000`), and stream a chosen slice of the radio's
//! 32 MiB NOR flash out a transport. Whether the uncaptured D75 bootloader
//! accepts and loads this stock-shaped candidate remains unproven.
//! The retained implementation still writes physical UART0 and therefore
//! cannot be captured over the TH-D75 USB-C connector.
//!
//! **Do not flash this build.** The service manual shows UART0 connects the
//! main MPU to the sub MPU; USB-C D+/D- connect directly to the OMAP USB0
//! controller. A native USB backend is required for the allowed capture path.
//!
//! # Boot contract
//!
//! The following behavior is inherited from the D74 analysis and encoded as
//! a D75 candidate image; it has not been confirmed from a captured D75
//! bootloader:
//!
//! 1. Validates the `final_zzz` string at flash offset `0x6020_0040`
//!    (the `FINALIZATION` static in [`mod@crate::header`]).
//! 2. Reads `load_address` (`0xC000_0000`) and `copy_length` (the size
//!    of our image) from the descriptor at `0x6020_0080+` (the
//!    `BODY` static in [`mod@crate::header`]).
//! 3. Copies our image to DDR, then jumps to offset 0 of the loaded
//!    image — the reset vector slot in `start::__vector_table`, which
//!    branches to `_reset` in [`mod@crate::start`].
//!
//! `_reset` initializes the stack pointer, zeros `.bss`, and calls
//! [`kmain`].
//!
//! # Safety
//!
//! No `unsafe { ... }` blocks anywhere in this crate. The only `unsafe`
//! opt-ins are three reasoned `#[allow(unsafe_code, reason = "…")]` on
//! the `#[unsafe(link_section = "…")]` attributes Rust 2024 requires
//! for static placement (see [`crate::header`]) and one on the
//! `#[unsafe(no_mangle)]` on [`kmain`]. All hardware access goes
//! through the safe API in `dumper-omap`.
//!
//! # Restoring the radio
//!
//! Flashing this payload would overwrite the main firmware. The intended
//! recovery is to re-flash official V1.03 via `thd75-flash`, but recovery from
//! an accepted arbitrary candidate has not yet been demonstrated on a D75.
//! Do not rely on that recovery path until the flasher and candidate boot
//! contract have passed their remaining hardware gates.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

mod dump;
mod framing;
mod header;
mod start;

use core::panic::PanicInfo;

use dumper_omap::uart::{BaudRate, Uart, UartId};

use crate::dump::DumpRegion;

/// Compile-time NOR region selection — edit this one line + rebuild
/// to dump a different slice. The streaming loop in [`dump::drive`]
/// is region-agnostic.
pub(crate) const REGION: DumpRegion = DumpRegion::LowNorCandidate;

/// Compile-time UART baud — edit + rebuild to switch rates.
pub(crate) const BAUD: BaudRate = BaudRate::B115200;

/// Rust entry point. Called from `_reset` (see [`crate::start`]).
///
/// The `#[unsafe(no_mangle)]` attribute is required by Rust 2024 to
/// export the function with a stable C-ABI symbol so the asm in
/// `start.rs` can `bl kmain`. The function body is safe Rust; the
/// `unsafe` is *only* the attribute marker the edition mandates.
#[expect(
    unsafe_code,
    reason = "Rust 2024 requires `#[unsafe(no_mangle)]` to export a \
              C-ABI symbol for the asm reset handler to call. The \
              function body itself is fully safe."
)]
#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
    // Legacy compile-only backend. UART0 is the documented main-MPU ↔
    // sub-MPU link, not a USB-C bridge. Its inherited PSC/pinmux/clock
    // assumptions are unverified and this call must be replaced by the
    // native USB backend before another hardware attempt.
    //
    // Region + baud chosen for the smallest useful first dump:
    // 2 MiB at 115200 ≈ 3 min. This is the low-NOR area omitted from
    // stock update images and is the D74-derived candidate boot/loader area;
    // the D75 contents and partition boundaries are not yet known.
    let uart = Uart::init(UartId::Uart0, BAUD);
    dump::drive(uart, REGION);
}

/// Panic handler — required for any `no_std` binary.
///
/// The dumper never panics intentionally; if Rust panics (e.g. a debug
/// assertion fires), we flush nothing and just spin so the host can
/// notice the absence of further bytes and conclude something went
/// wrong. No diagnostic output: the UART may already be the source of
/// the byte stream the host is decoding, and dumping panic prose in
/// the middle of the dump would corrupt it.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
