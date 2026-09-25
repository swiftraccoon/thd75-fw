//! Constants for the Texas Instruments OMAP-L138 SoC (ARM926EJ-S core).
//!
//! Addresses and bit positions verified against the TI OMAP-L138
//! Technical Reference Manual (SPRUH77). Only the peripherals the
//! dumper actually touches (NOR flash window, UART0/1/2) are declared
//! here — adding others is straightforward and welcome.
//!
//! All constants in this module are plain integer literals; no
//! `unsafe` code is involved (the addresses become MMIO handles only
//! when wrapped in the private `Reg32` type). `#![forbid(unsafe_code)]`
//! makes the "constants only" invariant unforgeable.

#![forbid(unsafe_code)]

/// Base address of the EMIFA NOR-flash window.
///
/// The TH-D75 service manual identifies a 256-Mbit flash on EMIF `/CS2`
/// but redacts IC2008's exact part number. TI's OMAP-L138 memory map places
/// EMIFA asynchronous CS2 at this address, and the extracted D75 main image
/// contains matching absolute addresses and an explicit identity MMU mapping.
/// The prior S29GL256S attribution came from TH-D74/OpenWood evidence and is
/// not a confirmed TH-D75 component identity.
///
/// Typed `u32` so the streaming protocol (which carries 32-bit base/
/// length fields) can use it without a `usize → u32` cast that would
/// trip `clippy::cast_possible_truncation` on 64-bit hosts. Callers
/// who need a `usize` for pointer math cast via `as usize`, which is
/// widening on every platform the workspace ever runs on.
pub const NOR_WINDOW_BASE: u32 = 0x6000_0000;

/// Size of the NOR-flash window (32 MiB). See [`NOR_WINDOW_BASE`] for
/// the choice of `u32` over `usize`.
pub const NOR_WINDOW_LEN: u32 = 0x0200_0000;

/// Base address of OMAP-L138 UART0 register block.
pub const UART0_BASE: usize = 0x01C4_2000;

/// Base address of OMAP-L138 UART1 register block.
pub const UART1_BASE: usize = 0x01D0_C000;

/// Base address of OMAP-L138 UART2 register block.
pub const UART2_BASE: usize = 0x01D0_D000;

/// Provisional UART input-clock assumption: 150 MHz.
///
/// **This value is not derived from D75 clock-register observations, and
/// the dumper does not enable the UART's PSC module or configure pinmux.**
/// It is retained only for the experimental physical-UART backend. A future
/// hardware observation must replace it before that backend can be called
/// validated; it has no bearing on native USB CDC transport.
pub const UART_INPUT_CLOCK_HZ: u32 = 150_000_000;

/// OMAP-L138 16550-compatible UART register offsets.
///
/// Offsets are relative to the UART base address. The chip's UART is a
/// TI-extended 16550, so most offsets match the standard but `MDR`,
/// `PWREMU_MGMT`, and the FIFO trigger registers are TI additions.
pub mod uart_offsets {
    /// Transmit Holding / Receive Buffer / Divisor Latch Low.
    pub const THR_RBR_DLL: usize = 0x00;
    /// Interrupt Enable / Divisor Latch High.
    pub const IER_DLH: usize = 0x04;
    /// Interrupt Identification (read) / FIFO Control (write).
    pub const IIR_FCR: usize = 0x08;
    /// Line Control Register.
    pub const LCR: usize = 0x0C;
    /// Modem Control Register.
    pub const MCR: usize = 0x10;
    /// Line Status Register.
    pub const LSR: usize = 0x14;
    /// Modem Status Register.
    pub const MSR: usize = 0x18;
    /// Scratch Register.
    pub const SCR: usize = 0x1C;
    /// Mode Definition Register (TI extension — IrDA/CIR/UART selector).
    pub const MDR: usize = 0x20;
    /// Power & Emulation Management (TI extension). The UART will not
    /// transmit unless `UTRST` and `URRST` are both set here.
    pub const PWREMU_MGMT: usize = 0x30;
}

/// LCR (Line Control Register) bit definitions.
pub mod lcr_bits {
    /// Word Length Select: 8 data bits per character.
    pub const WLS_8: u32 = 0b11;
    /// Stop Bits: 1 stop bit (cleared bit 2).
    pub const STB_ONE: u32 = 0;
    /// Parity Enable: disabled (cleared bit 3).
    pub const PEN_DISABLED: u32 = 0;
    /// Divisor Latch Access Bit: when set, DLL/DLH are accessible at
    /// THR/IER addresses. Must be cleared before normal TX/RX.
    pub const DLAB: u32 = 1 << 7;
}

/// LSR (Line Status Register) bit definitions.
pub mod lsr_bits {
    /// Transmit Holding Register Empty — set when the THR is ready for
    /// another byte. The dumper polls this before each write.
    pub const THRE: u32 = 1 << 5;
    /// Transmit Empty — set when both THR and the shift register are
    /// empty (i.e. nothing is being shifted out).
    pub const TEMT: u32 = 1 << 6;
}

/// FCR (FIFO Control Register) bit definitions.
pub mod fcr_bits {
    /// Enable both transmit and receive FIFOs.
    pub const FIFOEN: u32 = 1 << 0;
    /// Clear the receive FIFO (self-clearing).
    pub const RXCLR: u32 = 1 << 1;
    /// Clear the transmit FIFO (self-clearing).
    pub const TXCLR: u32 = 1 << 2;
}

/// PWREMU_MGMT (Power & Emulation Management) bit definitions.
pub mod pwremu_bits {
    /// UART Transmitter Reset — write 1 to take the TX out of reset.
    pub const UTRST: u32 = 1 << 14;
    /// UART Receiver Reset — write 1 to take the RX out of reset.
    pub const URRST: u32 = 1 << 13;
    /// Free-running on emulation halt — leave the UART running when
    /// the emulator stops the core (set on safety grounds; harmless
    /// when no emulator is connected).
    pub const FREE: u32 = 1 << 0;
}

/// MDR (Mode Definition Register) values.
pub mod mdr_modes {
    /// UART mode (no IrDA, no CIR). The only mode the dumper uses.
    pub const UART: u32 = 0;
}
