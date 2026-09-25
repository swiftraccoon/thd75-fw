//! Firmware-image header placed at DDR offset 0 by the linker script.
//!
//! Layout, byte-for-byte, in `linker.ld`:
//!
//! ```text
//! 0x0000 .. 0x0040 : .firmware_header.vectors      — 8 vectors + literals
//! 0x0040 .. 0x0080 : .firmware_header.finalization — ZZZ + complete/checkword
//! 0x0080 .. 0x0100 : .firmware_header.body         — version + 2 descriptors
//! 0x0100 .. 0x0200 : erased (`0xFF`) header padding
//! ```
//!
//! The offsets and bytes below are confirmed from the official V1.03 update
//! resources. Their runtime interpretation by the D75's uncaptured early
//! bootloader is not yet confirmed. The working hypothesis that FINAL_ZZZ
//! gates normal boot and that the primary descriptor controls copy/jump is
//! inherited from `OpenWood`'s TH-D74 analysis.
//!
//! The C-struct layouts here (`firmware_image_descriptor`,
//! `firmware_image_finalization`, and `firmware_image_version`) and the
//! ZZZ-marker string were
//! extracted directly from the bytes the official Kenwood TH-D75
//! firmware updater writes to NOR. The primary descriptor lives at NOR
//! offset `0x002000C0`, a secondary descriptor occupies `0x002000E0`,
//! the ZZZ marker is written as its own segment at `0x00200040`, and
//! V1.03's two CHECKBYTES (`B0 1D`) are stamped at `0x00200062`.
//! See acknowledgements in the top-level project README.

/// Exact D75 V1.03 FINAL_ZZZ resource. The 32 bytes were extracted from the dedicated
/// ZZZ segment the official Kenwood TH-D75 firmware updater writes
/// at NOR offset `0x00200040` (separate from the main-firmware
/// segment that occupies the surrounding bytes).
///
/// D74 analysis identifies this as the normal-boot validity marker. That
/// consumer behavior remains a D75 hypothesis until the bootloader is read.
pub(crate) const FINAL_ZZZ_D75: &[u8; 32] = b"ZZzo..(-_- ) EX-5210 2022-07-20\x00";

/// V1.03 CHECKBYTES as they appear on the radio after the official updater
/// has written its two-byte overlay at NOR offset `0x0020_0062`.
///
/// The official updater writes this value as a separate overlay. Whether the
/// D75 bootloader consumes it, and whether a custom image may safely retain
/// the stock value, are not established.
pub(crate) const CHECKBYTES_D75_V103: [u8; 2] = [0xB0, 0x1D];

/// The 64-byte finalization block at image offsets `0x40..0x80`.
///
/// The official updater writes the FIRMWARE body with this whole region
/// erased, then overlays FINAL_ZZZ at `0x40..0x60` and CHECKBYTES at
/// `0x62..0x64`. Embedding the final bytes in the flat custom image produces
/// the same post-update state; the host flasher still defers FINAL_ZZZ until
/// its last segment so an interrupted write remains recoverable.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Finalization {
    /// `"ZZzo..(-_- ) EX-5210 2022-07-20\0"` — see [`FINAL_ZZZ_D75`].
    pub(crate) final_zzz: [u8; 32],
    /// Update-complete word at offset `0x60`; erased in stock V1.03.
    pub(crate) complete_word: u16,
    /// V1.03 CHECKBYTES at offset `0x62`; little-endian bytes `B0 1D`.
    pub(crate) checkword: u16,
    /// Erased remainder of the fixed-size finalization block.
    pub(crate) reserved: [u8; 28],
}

/// Stock-shaped 32-byte name + 32-byte version fields. Their D75 runtime
/// consumer and significance are not established.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Version {
    /// Human-readable firmware name.
    pub(crate) name: [u8; 32],
    /// Version string, typically formatted `V-.--.---`.
    pub(crate) version: [u8; 32],
}

/// Stock V1.03 image-descriptor layout at NOR offset `0x002000C0`.
///
/// `OpenWood`'s D74 analysis says `load_address` and `copy_length` drive the
/// early copy/jump. Applying that interpretation to D75 is a hypothesis;
/// this type preserves every observed field rather than marking the others
/// ignored.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ImageDescriptor {
    /// Observed stock image start in the CPU-visible NOR window.
    pub(crate) flash_start_addr: u32,
    /// Observed stock flash-limit field.
    pub(crate) flash_limit_addr: u32,
    /// Candidate DDR load address; D74 analysis also treats it as the entry
    /// base. For this image it is `0xC000_0000`.
    pub(crate) load_address: u32,
    /// Observed stock image-length field.
    pub(crate) image_length: u32,
    /// Candidate copy length. `make audit` proves only that the linked flat
    /// image fits within this value; it cannot prove D75 bootloader semantics.
    pub(crate) copy_length: u32,
    /// Reserved (typically 0xFFFFFFFF).
    pub(crate) reserved: [u32; 3],
}

/// Header body placed at DDR offset `0x80`: version then two descriptors.
///
/// Stock D75 V1.03 carries both descriptors at offsets `0xC0` and `0xE0`.
/// `OpenWood`'s D74 analysis labels the secondary descriptor unused, but that
/// conclusion has not been established for the D75, so both stock-shaped
/// descriptor slots are retained.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Body {
    /// Cosmetic version metadata.
    pub(crate) version: Version,
    /// Primary observed descriptor at offset `0xC0`; D75 copy/jump semantics
    /// remain unconfirmed.
    pub(crate) descriptor_primary: ImageDescriptor,
    /// Secondary copy/jump descriptor at offset `0xE0`.
    pub(crate) descriptor_secondary: ImageDescriptor,
}

/// Build a NUL-terminated 32-byte metadata field with erased (`0xFF`)
/// padding, matching the official D75 header's string convention.
const fn erased_c_string(source: &[u8]) -> [u8; 32] {
    assert!(source.len() < 32, "header metadata must leave room for NUL");
    let mut field = [0xFF; 32];
    let mut index = 0;
    while index < source.len() {
        field[index] = source[index];
        index += 1;
    }
    field[source.len()] = 0;
    field
}

// ───── Statics placed by the linker ─────────────────────────────────

// SAFETY note: the two `#[unsafe(link_section = ...)]` attributes
// below are required by Rust 2024 edition. They are not `unsafe { }`
// blocks — they are attributes that opt into placing a static in a
// named ELF section. The crate's `#![deny(unsafe_code)]` would
// otherwise reject them, so each carries a reasoned allow.

// NOTE: the exception vector table itself is now defined in
// `start.rs` as the `__vector_table` symbol (8 × PC-relative `ldr pc`
// instructions plus the 8-word literal pool that holds the handler
// addresses, totalling 64 bytes = the full 0x00-0x40 slot the
// stock image reserves before offset 0x40). That pattern matches OpenWood's
// `firmware/lib/vectors.S` and is proven on D74 only.
// We previously had a hardcoded `static VECTORS` here, but `b .`
// loop slots aren't sufficient — exceptions need real addresses for
// the high-vectors copy in `start.rs::_reset` to point at.

/// Stock-shaped finalization block at offset `0x40`.
///
/// The claim that D75 checks FINAL_ZZZ before loading is a D74-derived
/// hypothesis, not a result from a captured D75 bootloader.
#[expect(
    unsafe_code,
    reason = "Rust 2024 unsafe-attribute requirement; same justification \
              as `VECTORS` — placing the static at the stock-observed \
              candidate offset is what the linker layout encodes."
)]
#[unsafe(link_section = ".firmware_header.finalization")]
#[used]
static FINALIZATION: Finalization = Finalization {
    final_zzz: *FINAL_ZZZ_D75,
    complete_word: 0xFFFF,
    checkword: u16::from_le_bytes(CHECKBYTES_D75_V103),
    reserved: [0xFF; 28],
};

/// Header body at offset 0x80. Loaded address is the start of DDR
/// (`0xC000_0000`).
///
/// The fields believed copy-relevant from D74 exactly match stock D75 V1.03:
/// candidate load at
/// `0xC000_0000`, copy the complete 3 MiB main-firmware slot. Bytes past
/// the small custom payload are never executed or read by the dumper.
///
/// `make audit` enforces static size and byte parity only. It does not prove
/// that the D75 bootloader accepts or interprets either descriptor this way.
#[expect(
    unsafe_code,
    reason = "Rust 2024 unsafe-attribute requirement; see `VECTORS`."
)]
#[unsafe(link_section = ".firmware_header.body")]
#[used]
static BODY: Body = Body {
    version: Version {
        name: erased_c_string(b"thd75-fw dumper"),
        version: erased_c_string(b"V0.1.0"),
    },
    descriptor_primary: ImageDescriptor {
        flash_start_addr: 0x6020_0000,
        flash_limit_addr: 0x6100_0000,
        load_address: 0xC000_0000,
        image_length: 0x0050_0000,
        copy_length: 0x0030_0000,
        reserved: [0xFFFF_FFFF; 3],
    },
    descriptor_secondary: ImageDescriptor {
        flash_start_addr: 0x6020_0000,
        flash_limit_addr: 0x6060_0000,
        load_address: 0xC000_0000,
        image_length: 0x0050_0000,
        copy_length: 0x0030_0000,
        reserved: [0xFFFF_FFFF; 3],
    },
};
