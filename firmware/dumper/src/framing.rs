//! Tiny stream-header frame the dumper emits before raw NOR bytes, so
//! the host capture script can sanity-check that what arrived on the
//! wire actually came from the dumper and is the size it expects.
//!
//! Wire format (12 bytes, little-endian):
//!
//! ```text
//! +----+----+----+----+----+----+----+----+----+----+----+----+
//! | MAGIC                 | BASE_ADDR             | LENGTH    |
//! | (4 bytes, "D75D")     | (4 bytes, u32)        | (4 bytes) |
//! +----+----+----+----+----+----+----+----+----+----+----+----+
//! ```
//!
//! Choosing a magic that doubles as readable ASCII (`D75D` = "D75D")
//! makes a serial-monitor capture trivially identifiable.
//!
//! `#![forbid(unsafe_code)]` because there is no reason a const-fn
//! byte-array constructor would ever need an unsafe block; this
//! module is the simplest possible thing.

#![forbid(unsafe_code)]

/// Magic prefix of every dumper stream — ASCII `"D75D"`.
pub(crate) const MAGIC: [u8; 4] = *b"D75D";

/// Length of the on-wire header (magic + base + length).
pub(crate) const HEADER_LEN: usize = MAGIC.len() + 4 + 4;

/// Builds the 12-byte header for a dump of `length` bytes starting at
/// the NOR address `base_addr`. Returns a stack-allocated byte array
/// the caller streams to the UART before the raw payload.
#[must_use]
pub(crate) const fn build_header(base_addr: u32, length: u32) -> [u8; HEADER_LEN] {
    let base = base_addr.to_le_bytes();
    let len = length.to_le_bytes();
    [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], base[0], base[1], base[2], base[3], len[0], len[1],
        len[2], len[3],
    ]
}
