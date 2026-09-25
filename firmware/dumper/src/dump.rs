//! Dump-region selection and the streaming loop itself.
//!
//! Kept in its own module so the `main` entry point reads as a
//! configuration choice followed by a single function call:
//!
//! ```text
//! fn kmain() -> ! {
//!     let uart = init_uart();
//!     drive(uart, DumpRegion::FullNor);
//! }
//! ```
//!
//! `#![forbid(unsafe_code)]` is stronger than the crate-level
//! `deny(unsafe_code)`: it cannot be overridden by an inner
//! `#[allow]`/`#[expect]`. The streaming loop has no business
//! reaching for unsafe — every byte goes through the safe API in
//! `dumper-omap`.

#![forbid(unsafe_code)]

use dumper_omap::nor;
use dumper_omap::omap_l138::{NOR_WINDOW_BASE, NOR_WINDOW_LEN};
use dumper_omap::uart::Uart;

use crate::framing;

/// Which slice of the NOR flash to stream.
///
/// The dumper's [`crate::REGION`] picks one variant at compile time;
/// the others remain part of the type so a one-line edit + rebuild
/// switches between regions without touching the streaming loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    dead_code,
    reason = "Variants are the typed configuration surface — only one \
              is selected by `crate::REGION` per build, but the others \
              must remain part of the enum so an operator can edit \
              `REGION` and rebuild without touching this module."
)]
pub(crate) enum DumpRegion {
    /// Stream the entire 32 MiB NOR window
    /// (`0x6000_0000..0x6200_0000`). The slow path — useful when we
    /// genuinely want everything; ≈6 min at 921 600 bps.
    FullNor,
    /// Stream just the first 2 MiB (`0x6000_0000..0x6020_0000`).
    /// Stock updater images begin at `0x6020_0000`, so this low-NOR area is
    /// omitted from them. D74 evidence makes it the candidate boot/loader
    /// area, but the D75 contents and internal boundaries are unconfirmed.
    /// ≈20 s at 921 600 bps.
    LowNorCandidate,
    /// Operator-supplied window. `start` is an absolute CPU address;
    /// `len` is in bytes. Clamped at runtime to the NOR window.
    ///
    /// **`start` should be word-aligned** (a multiple of 4). The
    /// streaming loop in [`drive`] walks word-by-word and the
    /// `dumper_omap::nor::read_word` helper aligns the address
    /// down to a word boundary internally. A non-aligned `start`
    /// will emit the bytes from `start & !0b11` instead — silent
    /// off-by-one to off-by-three at the head of the stream. The
    /// shipped `FullNor` and `LowNorCandidate` variants are word-
    /// aligned by construction, so this only affects operator-
    /// edited builds that pick a non-aligned start.
    Custom {
        /// Absolute CPU address to start the dump at. Must be
        /// word-aligned for byte-accurate output (see variant doc).
        start: u32,
        /// Number of bytes to stream.
        len: u32,
    },
}

impl DumpRegion {
    /// The clamped `(start, length)` this region resolves to.
    #[must_use]
    pub(crate) const fn resolve(self) -> (u32, u32) {
        match self {
            Self::FullNor => (NOR_WINDOW_BASE, NOR_WINDOW_LEN),
            Self::LowNorCandidate => (NOR_WINDOW_BASE, 0x0020_0000),
            Self::Custom { start, len } => {
                // Clamp start to the closed interval [window base, window
                // end]. The previous lower-bound-only clamp underflowed in
                // release builds when an operator supplied start > end.
                let window_end = NOR_WINDOW_BASE + NOR_WINDOW_LEN;
                let start = if start < NOR_WINDOW_BASE {
                    NOR_WINDOW_BASE
                } else if start > window_end {
                    window_end
                } else {
                    start
                };
                let max_len = window_end - start;
                let len = if len > max_len { max_len } else { len };
                (start, len)
            }
        }
    }
}

/// Streams the selected region out the UART: 12-byte header
/// ([`framing::build_header`]) followed by raw bytes, byte-by-byte.
///
/// This function never returns; on completion it flushes the UART and
/// spins forever, so the host can power-cycle the radio at its leisure.
pub(crate) fn drive(uart: Uart, region: DumpRegion) -> ! {
    let (start, length) = region.resolve();

    // Header so the host can identify the stream and verify the size.
    let header = framing::build_header(start, length);
    uart.write_all(&header);

    // Streaming loop. Walking words is one bus transaction per 4
    // bytes — markedly faster than per-byte reads at high baud rates
    // and the natural unit of NOR access.
    let end = start.saturating_add(length);
    let mut addr = start;
    while addr < end {
        // Word-aligned reads; trailing tail (length not divisible by 4)
        // is handled by clamping `addr + 4` against `end`.
        let word = nor::read_word(addr as usize);
        let bytes = word.to_le_bytes();
        let remaining = end - addr;
        let to_emit = if remaining < 4 { remaining as usize } else { 4 };
        // `to_emit` is in 1..=4 so the slice index is in-range by
        // construction.
        uart.write_all(&bytes[..to_emit]);
        addr = addr.saturating_add(4);
    }

    uart.flush();
    loop {
        // Yield nothing — the OMAP has no `wfi` analogue at ARMv5TE
        // user level worth invoking from safe Rust; a tight spin is
        // acceptable for a single-purpose payload that runs until the
        // operator power-cycles the radio.
        core::hint::spin_loop();
    }
}
