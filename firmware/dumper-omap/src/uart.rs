//! Safe API over the OMAP-L138's TI-16550-compatible UART.
//!
//! The OMAP-L138 has three physical UART peripherals (`UART0`, `UART1`,
//! `UART2`) at fixed base addresses (see [`crate::omap_l138`]). These are
//! distinct from the SoC's USB controller. There is currently no evidence
//! that the TH-D75 bridges any UART to its USB-C CDC endpoints, so this
//! backend is provisional and must not be treated as USB output.
//!
//! All public functions in this module are safe Rust; the underlying
//! MMIO is performed through the private `Reg32` type, which is the
//! sole audited `unsafe` boundary of the crate. `#![forbid(unsafe_code)]`
//! locks that contract in: a future change cannot quietly add an
//! `unsafe { ... }` block here without first removing the attribute.

#![forbid(unsafe_code)]

use crate::omap_l138::{
    UART_INPUT_CLOCK_HZ, UART0_BASE, UART1_BASE, UART2_BASE, fcr_bits, lcr_bits, lsr_bits,
    mdr_modes, pwremu_bits, uart_offsets,
};
use crate::registers::Reg32;

/// Identifies one of the OMAP-L138's three UART peripherals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UartId {
    /// UART0 — base address [`UART0_BASE`].
    Uart0,
    /// UART1 — base address [`UART1_BASE`].
    Uart1,
    /// UART2 — base address [`UART2_BASE`].
    Uart2,
}

impl UartId {
    /// Returns the absolute base address of this UART's register block.
    #[must_use]
    pub const fn base(self) -> usize {
        match self {
            Self::Uart0 => UART0_BASE,
            Self::Uart1 => UART1_BASE,
            Self::Uart2 => UART2_BASE,
        }
    }
}

/// Selectable line baud rates.
///
/// The OMAP-L138 UART derives its bit clock by dividing
/// [`UART_INPUT_CLOCK_HZ`] by `16 × baud`; not all rates are exactly
/// representable. [`BaudRate::actual`] gives the rate the hardware
/// will produce for the chosen divisor — useful when sanity-checking
/// against the host side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    /// 9 600 bps — slow, included for parity with the FLDM ladder.
    B9600,
    /// 57 600 bps — top of the FLDM ladder.
    B57600,
    /// 115 200 bps — a common high serial rate.
    B115200,
    /// 921 600 bps — the dumper's default.
    B921600,
    /// 1 500 000 bps — fastest commonly-supported rate.
    B1500000,
    /// Operator-supplied rate (bits per second).
    Custom(u32),
}

impl BaudRate {
    /// Returns the nominal bit rate in bits per second.
    #[must_use]
    pub const fn rate(self) -> u32 {
        match self {
            Self::B9600 => 9_600,
            Self::B57600 => 57_600,
            Self::B115200 => 115_200,
            Self::B921600 => 921_600,
            Self::B1500000 => 1_500_000,
            Self::Custom(r) => r,
        }
    }

    /// Computes the baud-rate divisor for the OMAP-L138 UART.
    ///
    /// `divisor = input_clock / (16 × baud)`, clamped to `[1, 0xFFFF]`.
    /// A divisor of 0 would mean an unachievably-high rate; a divisor
    /// above 0xFFFF would mean an unachievably-low rate. The value is
    /// 16-bit by the hardware contract; we return `u32` so the divisor
    /// composes with the surrounding `u32` register writes without a
    /// narrowing cast (`u16::try_from` is not yet const-stable).
    #[must_use]
    pub const fn divisor(self) -> u32 {
        let target = self.rate();
        let raw = UART_INPUT_CLOCK_HZ / (16 * target);
        if raw == 0 {
            1
        } else if raw > 0xFFFF {
            0xFFFF
        } else {
            raw
        }
    }

    /// The bit rate actually produced by the hardware given the
    /// integer divisor (the difference between [`rate`] and `actual`
    /// is the truncation error, useful for diagnosing host-side
    /// framing issues).
    ///
    /// [`rate`]: BaudRate::rate
    #[must_use]
    pub const fn actual(self) -> u32 {
        let div = self.divisor();
        UART_INPUT_CLOCK_HZ / (16 * div)
    }
}

/// A configured UART, ready to transmit.
///
/// Construct via [`Uart::init`]; the constructor performs the full
/// programming sequence (power on, divisor, frame format, FIFO reset)
/// so callers do not have to remember the order. The resulting handle
/// is `Copy` and can be passed around freely.
#[derive(Debug, Clone, Copy)]
pub struct Uart {
    base: usize,
}

impl Uart {
    /// Initialize the given UART with 8-N-1 framing at `baud` and
    /// return a handle ready for transmission.
    ///
    /// The programming sequence matches the OMAP-L138 TRM (SPRUH77)
    /// Section 35.2.6.1 "Programming Sequence":
    ///
    /// 1. Bring the TX and RX out of reset and disable the
    ///    free-running-on-emulation-halt feature
    ///    ([`uart_offsets::PWREMU_MGMT`]).
    /// 2. Set the mode to plain UART (no IrDA / CIR) via
    ///    [`uart_offsets::MDR`].
    /// 3. Set DLAB, write the divisor to DLL/DLH, clear DLAB and set
    ///    the line-control register to 8-N-1.
    /// 4. Enable and clear both FIFOs.
    #[must_use]
    pub fn init(id: UartId, baud: BaudRate) -> Self {
        let base = id.base();

        // (1) Power up the TX/RX path.
        Reg32::new(base + uart_offsets::PWREMU_MGMT)
            .write(pwremu_bits::UTRST | pwremu_bits::URRST | pwremu_bits::FREE);

        // (2) UART mode (vs IrDA / CIR).
        Reg32::new(base + uart_offsets::MDR).write(mdr_modes::UART);

        // (3) Set DLAB to load the divisor.
        Reg32::new(base + uart_offsets::LCR).write(lcr_bits::DLAB);
        let div = baud.divisor();
        Reg32::new(base + uart_offsets::THR_RBR_DLL).write(div & 0x00FF);
        Reg32::new(base + uart_offsets::IER_DLH).write(div >> 8);

        // Clear DLAB, set 8-N-1.
        Reg32::new(base + uart_offsets::LCR)
            .write(lcr_bits::WLS_8 | lcr_bits::STB_ONE | lcr_bits::PEN_DISABLED);

        // (4) Enable + clear both FIFOs.
        Reg32::new(base + uart_offsets::IIR_FCR)
            .write(fcr_bits::FIFOEN | fcr_bits::RXCLR | fcr_bits::TXCLR);

        Self { base }
    }

    /// Block until the transmit holding register can accept a byte,
    /// then write one byte.
    ///
    /// Polls [`uart_offsets::LSR`] for [`lsr_bits::THRE`]; the OMAP
    /// UART asserts THRE within a few bit times of the previous byte
    /// shifting into the line. There is no timeout — for the dumper
    /// this is fine; the radio is the only consumer of the line and
    /// blocking is the right behavior.
    pub fn write_byte(self, byte: u8) {
        let lsr = Reg32::new(self.base + uart_offsets::LSR);
        let thr = Reg32::new(self.base + uart_offsets::THR_RBR_DLL);
        while (lsr.read() & lsr_bits::THRE) == 0 {}
        thr.write(u32::from(byte));
    }

    /// Write every byte of `data` in order.
    pub fn write_all(self, data: &[u8]) {
        for &byte in data {
            self.write_byte(byte);
        }
    }

    /// Block until the transmitter is completely idle (both the
    /// holding register and the shift register are empty).
    ///
    /// Use this after the last byte of a long transmission to be sure
    /// nothing is mid-shift when the host stops listening.
    pub fn flush(self) {
        let lsr = Reg32::new(self.base + uart_offsets::LSR);
        let both_empty = lsr_bits::THRE | lsr_bits::TEMT;
        while (lsr.read() & both_empty) != both_empty {}
    }
}
