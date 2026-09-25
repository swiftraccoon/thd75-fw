//! Reset entry, exception-vector table, and CPU init — structurally based on
//! `OpenWood`'s working TH-D74 firmware-payload library.
//!
//! The first TH-D75 attempt went dark and did not enumerate USB. There is no
//! trace proving whether the image booted, faulted, or was rejected, so this
//! module must not present an unclocked-UART data abort as the diagnosis.
//! The banked stacks and explicit vector handlers remove one class of early
//! fault ambiguity, but they do not validate the D75 boot contract or provide
//! a USB transport.
//!
//! `OpenWood`'s ARM9 init pattern (also in `openwood/firmware/lib/
//! {startup.S, cpu.c, vectors.S}`) is a D74-proven reference and the current
//! D75 candidate minimum, not proof of the uncaptured D75 entry contract:
//!
//! 1. Initialize the banked SP for every exception mode so an early
//!    exception has a valid stack to push CPSR onto.
//! 2. Switch to SYSTEM mode (unprivileged-equivalent with full
//!    privileges) and keep IRQ/FIQ masked until firmware explicitly
//!    enables them.
//! 3. Zero `.bss` so Rust statics start from a defined value.
//! 4. Copy our vector table into `LOCAL_RAM` at `0xFFFF_0000` before
//!    selecting high vectors.
//! 5. Set the CP15 high-exception-vector bit and clear MMU/D-cache/
//!    I-cache. High vectors then resolve to the table copied in step 4.
//! 6. Branch to Rust `kmain`.
//!
//! Symbols this file defines:
//! * `_reset` — the full reset entry described above.
//! * `__vector_table` — the 8-vector ARM exception table.
//! * `_undef_loop` / `_swi_loop` / `_pabt_loop` / `_dabt_loop` /
//!   `_resv_loop` / `_irq_loop` / `_fiq_loop` — placeholder
//!   exception handlers (infinite loops). Replace with real handlers
//!   once the dumper does something interesting on faults.

#![expect(
    unsafe_code,
    reason = "Current Rust nightly treats `global_asm!` as subject to \
              the `unsafe_code` lint even though no `unsafe { ... }` \
              block is syntactically present. The asm body is small \
              and audited — see module-level docs for the boot-init \
              steps and the openwood reference."
)]

// ─── ARM9 CPSR mode constants (mirror openwood/firmware/lib/cpu.h) ─────
//
// The `set_mode_stack` macro switches CPSR to the named mode (with
// IRQ+FIQ masked), assigns the banked SP from r0, then reserves
// 1 KiB of stack space for the next mode below it. After all five
// banked modes are initialized, the residual r0 is the SP for
// SYSTEM mode (the mode firmware runs in).

core::arch::global_asm!(
    r#"
    .section .firmware_header.vectors, "ax"
    .arm

    /* Under the D74-derived candidate contract, the bootloader jumps to
       offset 0 of the loaded image, making this the reset-vector slot.
       Explicit labels make the literal-pool placement deterministic and
       match OpenWood's D74 vectors.S. D75 behavior is unconfirmed. */
    .global __vector_table
    .type __vector_table, %object
__vector_table:
    ldr pc, reset_handler
    ldr pc, undefined_instruction_handler
    ldr pc, software_interrupt_handler
    ldr pc, prefetch_abort_handler
    ldr pc, data_abort_handler
    ldr pc, reserved_vector_handler
    ldr pc, irq_handler
    ldr pc, fiq_handler

reset_handler:                  .word _reset
undefined_instruction_handler:  .word _undef_loop
software_interrupt_handler:     .word _swi_loop
prefetch_abort_handler:         .word _pabt_loop
data_abort_handler:             .word _dabt_loop
reserved_vector_handler:        .word _resv_loop
irq_handler:                    .word _irq_loop
fiq_handler:                    .word _fiq_loop

    .size __vector_table, . - __vector_table
    .section .text._reset, "ax"
    .arm
    .global _reset

_reset:
    /* Stack pointer values come from the linker. We reserve
       1 KiB for each ARM exception mode's banked SP, walking r0
       downward as we go. ARM9_EXCEPTION_STACK_SIZE = 0x400.
       After the five banked modes are set, r0 still points to the
       SYSTEM-mode stack base. */
    ldr     r0, =__stack_top

    /* UNDEFINED mode (CPSR.M = 0x1B), interrupts masked. */
    msr     cpsr_c, #0xDB           /* mode=0x1B | I=1 | F=1 */
    mov     sp, r0
    sub     r0, r0, #0x400

    /* ABORT mode (CPSR.M = 0x17), interrupts masked. */
    msr     cpsr_c, #0xD7
    mov     sp, r0
    sub     r0, r0, #0x400

    /* FIQ mode (CPSR.M = 0x11), interrupts masked. */
    msr     cpsr_c, #0xD1
    mov     sp, r0
    sub     r0, r0, #0x400

    /* IRQ mode (CPSR.M = 0x12), interrupts masked. */
    msr     cpsr_c, #0xD2
    mov     sp, r0
    sub     r0, r0, #0x400

    /* SUPERVISOR mode (CPSR.M = 0x13), interrupts masked. */
    msr     cpsr_c, #0xD3
    mov     sp, r0
    sub     r0, r0, #0x400

    /* SYSTEM mode (CPSR.M = 0x1F), interrupts masked.
       Firmware runs in SYSTEM mode using the remaining stack. */
    msr     cpsr_c, #0xDF
    mov     sp, r0

    /* Zero .bss. */
    ldr     r0, =__bss_start
    ldr     r1, =__bss_end
    mov     r2, #0
1:  cmp     r0, r1
    strlo   r2, [r0], #4
    blo     1b

    /* Copy our vector table (64 bytes) from the loaded image's
       offset 0 to LOCAL_RAM at 0xFFFF_0000. ARM9 high-vector mode
       will fetch exception vectors from there after the following
       CP15 update. Copy first so we never select an uninitialized
       high-vector table; this matches OpenWood's D74 ordering. */
    ldr     r0, =__vector_table         /* source = DDR + 0 */
    ldr     r1, =0xFFFF0000              /* destination = LOCAL_RAM */
    mov     r2, #16                       /* 16 words = 64 bytes */
2:  ldr     r3, [r0], #4
    str     r3, [r1], #4
    subs    r2, r2, #1
    bne     2b

    /* Disable MMU + D-cache + I-cache, then select the now-populated
       high-vector table (CP15 control bit 13). IRQ/FIQ remain masked,
       so only a synchronous exception can observe this transition. */
    mrc     p15, 0, r0, c1, c0, 0       /* r0 = CP15 control */
    bic     r0, r0, #0x0001              /* clear MMU enable (bit 0) */
    bic     r0, r0, #0x0004              /* clear D-cache enable (bit 2) */
    bic     r0, r0, #0x1000              /* clear I-cache enable (bit 12) */
    orr     r0, r0, #0x2000              /* set HIGH_EXCEPTION_VECTORS (bit 13) */
    mcr     p15, 0, r0, c1, c0, 0       /* write back */

    /* Hand off to Rust. kmain() -> ! so it never returns. */
    bl      kmain

3:  b       3b

    /* ─── Exception handlers (placeholders) ──────────────────────
       Spin forever on any exception. The exception kind is
       discoverable post-mortem by reading the PC in the saved
       CPSR-banked LR — but for now the goal is "don't silently
       jump to random memory." Replace with real handlers once the
       dumper has UART output and can log faults. */
    .global _undef_loop
    .global _swi_loop
    .global _pabt_loop
    .global _dabt_loop
    .global _resv_loop
    .global _irq_loop
    .global _fiq_loop
_undef_loop: b _undef_loop
_swi_loop:   b _swi_loop
_pabt_loop:  b _pabt_loop
_dabt_loop:  b _dabt_loop
_resv_loop:  b _resv_loop
_irq_loop:   b _irq_loop
_fiq_loop:   b _fiq_loop
    "#
);
