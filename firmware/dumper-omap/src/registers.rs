//! Volatile memory-mapped I/O primitive: [`Reg32`].
//!
//! This module is the **only** place in the `dumper-omap` crate that
//! contains `unsafe` blocks. Every block is wrapped in a thin safe
//! helper, every `unsafe` opt-in carries a reasoned
//! [`#[allow(unsafe_code, reason = "…")]`][allow] attribute, and every
//! block has a `// SAFETY:` comment articulating the invariant the
//! caller (or in this case, the [`Reg32::new`] address-validity contract)
//! upholds. Keeping the trusted surface to a single file makes audits
//! tractable.
//!
//! [allow]: https://doc.rust-lang.org/reference/attributes/diagnostics.html#lint-check-attributes
//!
//! # Why hand-rolled rather than `volatile-register`
//!
//! The standard embedded-Rust approach is to pull in the
//! [`volatile-register`](https://docs.rs/volatile-register) crate, which
//! provides `RW<T>`, `RO<T>`, `WO<T>` types that wrap the same
//! [`core::ptr::read_volatile`] / [`core::ptr::write_volatile`] calls.
//! For the TH-D75 dumper we keep zero runtime dependencies — the
//! trusted surface is two `unsafe` lines, easily reviewed in place;
//! taking on a third-party dep would expand the trust boundary for
//! marginal ergonomic gain.

#![expect(
    unsafe_code,
    reason = "Audited MMIO boundary. Every `unsafe` block in this file \
              is paired with a `// SAFETY:` comment articulating the \
              invariant the caller upholds. See module-level docs."
)]
#![allow(
    clippy::redundant_pub_crate,
    reason = "Reg32 must be visible to sibling `nor`/`uart` modules while the \
              raw-address module remains private to consumer crates"
)]

/// Crate-private handle to a 32-bit memory-mapped hardware register.
///
/// Wraps a raw address so callers cannot accidentally pass an
/// `*mut u8`, a misaligned pointer, or a non-`'static` reference.
/// This raw-address constructor is deliberately unavailable to consumer
/// crates. The audited `nor` and `uart` modules construct it only from fixed
/// OMAP-L138 windows and expose bounded, device-specific safe APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reg32 {
    address: usize,
}

impl Reg32 {
    /// Constructs a register handle at the given absolute address.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `address` is not 4-byte aligned —
    /// unaligned 32-bit access on ARM926EJ-S is undefined behavior at
    /// the hardware level.
    #[must_use]
    pub(super) const fn new(address: usize) -> Self {
        debug_assert!(
            address.is_multiple_of(4),
            "Reg32::new: address must be word-aligned",
        );
        Self { address }
    }

    /// Reads the current 32-bit value of the register.
    ///
    /// Volatile so the compiler will not elide, reorder, or coalesce
    /// reads — important for clear-on-read status bits and FIFO data
    /// registers.
    #[must_use]
    pub(super) fn read(self) -> u32 {
        // SAFETY: `self.address` was produced by `Reg32::new`, whose
        // documented contract is that the caller passes the absolute
        // address of a 32-bit MMIO register inside the SoC's peripheral
        // window. Word alignment is checked at construction. Volatile
        // reads of MMIO are side-effect-free at the Rust abstract-
        // machine level; any hardware-visible consequences (e.g.
        // clear-on-read flags) are the consumer's intentional choice.
        unsafe { core::ptr::read_volatile(self.address as *const u32) }
    }

    /// Writes a 32-bit value into the register.
    ///
    /// Volatile so the compiler will not elide or reorder the write —
    /// important for stateful peripherals where write order matters
    /// (UART DLAB / divisor sequence, e.g.).
    ///
    /// # Panics
    ///
    /// Panics if `self.address` falls inside the NOR-flash window
    /// (`0x6000_0000..0x6200_0000`). `Reg32::write` exists for SoC
    /// peripheral registers (UART, GPIO, EMIFA config); NOR uses a
    /// CFI command-sequence protocol where a single MMIO write is a
    /// no-op at the chip level. Catching the address here makes any
    /// future code that confuses `Reg32` for a flash-write primitive
    /// fail loudly rather than silently — defense in depth against
    /// the one class of mistake that could corrupt the bootloader.
    /// Panic handler is `loop { spin }` (see `dumper::panic`); the
    /// dumper hangs instead of issuing the write.
    pub(super) fn write(self, value: u32) {
        // NOR window constants are inlined rather than imported from
        // `crate::omap_l138` to keep `registers.rs` SoC-agnostic; the
        // chip-specific definitions in `omap_l138.rs` match.
        const NOR_LO: usize = 0x6000_0000;
        const NOR_HI: usize = 0x6200_0000;
        assert!(
            self.address < NOR_LO || self.address >= NOR_HI,
            "Reg32::write into NOR window — Reg32 is for peripheral registers, \
             not flash. NOR programming requires a CFI command sequence the \
             dumper does not implement."
        );

        // SAFETY: see [`Reg32::read`] — the address is a 32-bit MMIO
        // register supplied via `Reg32::new`. Volatile writes are
        // hardware-visible by design and otherwise side-effect-free in
        // the Rust model.
        unsafe { core::ptr::write_volatile(self.address as *mut u32, value) }
    }
}
