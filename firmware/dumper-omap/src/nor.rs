//! Safe word- and byte-level reads from the OMAP-L138 EMIFA-mapped NOR
//! flash window.
//!
//! The TH-D75 service manual proves a 256-Mbit flash is connected to
//! EMIF `/CS2`; it does not disclose the exact part. OMAP-L138 maps that
//! CS2 window at [`NOR_WINDOW_BASE`], and the stock main firmware's MMU
//! tables identity-map it for ordinary non-cacheable reads. Whether an
//! untested replacement payload inherits every required initialization
//! remains a separate runtime question.
//! These helpers wrap private `Reg32` reads so the dumper application can
//! work in safe Rust without touching raw pointers.
//!
//! `#![forbid(unsafe_code)]` (rather than the crate-level `deny`)
//! guarantees no `unsafe` opt-in can ever be introduced in this
//! module without removing the attribute — a stronger property than
//! the crate-level lint, which `registers.rs` overrides with
//! `#![expect(unsafe_code)]` for its audited MMIO calls.

#![forbid(unsafe_code)]

use crate::omap_l138::{NOR_WINDOW_BASE, NOR_WINDOW_LEN};
use crate::registers::Reg32;

/// Base of the NOR window as `usize`. The public constant is `u32` to
/// fit the streaming protocol; pointer-math here needs `usize`. The
/// cast is widening on every platform this workspace runs on.
const NOR_WINDOW_BASE_USIZE: usize = NOR_WINDOW_BASE as usize;

/// Last addressable byte of the NOR window (inclusive).
const NOR_WINDOW_END: usize = NOR_WINDOW_BASE_USIZE + NOR_WINDOW_LEN as usize - 1;

/// Last addressable word in the NOR window (inclusive).
const NOR_WINDOW_LAST_WORD: usize = NOR_WINDOW_END & !0b11;

/// Reads a single byte from the NOR flash at the given absolute
/// address, clamping to the window if `address` is out of range.
///
/// Out-of-range addresses are *not* an error: the function clamps to
/// the nearest in-window address. This makes the streaming loop in
/// [`crate::nor`] consumers trivially correct (the loop just walks
/// `NOR_WINDOW_BASE..NOR_WINDOW_BASE + NOR_WINDOW_LEN` and never has
/// to think about boundary cases).
///
/// # Examples
///
/// ```ignore
/// use dumper_omap::nor;
/// use dumper_omap::omap_l138::NOR_WINDOW_BASE;
/// let first_byte = nor::read_byte(NOR_WINDOW_BASE as usize);
/// ```
#[must_use]
pub fn read_byte(address: usize) -> u8 {
    let clamped = clamp_to_window(address);
    let word_addr = clamped & !0b11;
    let byte_index = clamped & 0b11;
    let word = Reg32::new(word_addr).read();
    let bytes = word.to_le_bytes();
    // `byte_index` is `clamped & 0b11`, i.e. 0..=3, so indexing is
    // statically in range; using `to_le_bytes()` avoids any cast.
    bytes[byte_index]
}

/// Reads a 32-bit aligned word from the NOR flash at the given
/// absolute address. The address is clamped to the window and aligned
/// down to the nearest word boundary before the read.
///
/// Prefer this over four [`read_byte`] calls when streaming large
/// regions — one bus transaction instead of four.
#[must_use]
pub fn read_word(address: usize) -> u32 {
    let clamped = clamp_to_window(address).min(NOR_WINDOW_LAST_WORD);
    let word_addr = clamped & !0b11;
    Reg32::new(word_addr).read()
}

/// Clamps an arbitrary address into the NOR window
/// `[NOR_WINDOW_BASE, NOR_WINDOW_END]`.
const fn clamp_to_window(address: usize) -> usize {
    if address < NOR_WINDOW_BASE_USIZE {
        NOR_WINDOW_BASE_USIZE
    } else if address > NOR_WINDOW_END {
        NOR_WINDOW_END
    } else {
        address
    }
}
