//! OMAP-L138 SoC register definitions and safe MMIO wrappers for the
//! TH-D75 firmware payloads.
//!
//! This is the *platform* crate of the `firmware/` workspace. It is
//! the only crate that contains `unsafe { ... }` blocks; every block
//! is in the private `registers` module, wrapped in a thin safe helper, and paired with
//! a `// SAFETY:` comment articulating the invariant the caller
//! upholds. Application crates ([`dumper`](https://docs.rs/dumper))
//! sit on top of this safe API.
//!
//! # Modules
//!
//! * `registers` — the crate-private audited MMIO boundary.
//! * [`omap_l138`] — addresses and bit positions verified against the
//!   OMAP-L138 Technical Reference Manual (TI SPRUH77).
//! * [`uart`] — safe 16550-style UART API ([`uart::Uart`],
//!   [`uart::BaudRate`], [`uart::UartId`]).
//! * [`nor`] — safe reads of the EMIFA NOR-flash window
//!   ([`nor::read_byte`], [`nor::read_word`]).
//!
//! # Safety story
//!
//! Every public function in this crate is safe to call. The internal
//! `unsafe` blocks rely on these invariants:
//!
//! * Every crate-internal `Reg32` construction passes the absolute
//!   address of a 32-bit memory-mapped peripheral register inside the
//!   SoC's peripheral window (`0x01C0_0000..0x01F0_0000`) or the EMIFA
//!   NOR window (`0x6000_0000..0x6200_0000`). All callers within this
//!   crate use named constants from [`omap_l138`].
//! * Word alignment is checked in debug builds at construction.
//!
//! Consumer crates use `#![deny(unsafe_code)]` and never call
//! `unsafe { ... }` blocks of their own — they ride entirely on this
//! crate's safe API.

#![no_std]
#![deny(unsafe_code)]

pub mod nor;
pub mod omap_l138;
mod registers;
pub mod uart;
