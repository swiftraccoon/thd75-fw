/*
 * Shared linker script for the TH-D75 firmware payloads (dumper, etc.).
 *
 * Candidate TH-D75 image layout. The byte offsets and stock descriptor
 * values are confirmed from the official V1.03 update resources. The claim
 * that the D75 early bootloader copies the main-firmware slot to DDR and
 * jumps to its first word is inherited from TH-D74 reverse engineering and
 * remains unconfirmed until the D75 bootloader is captured.
 *
 * The DDR layout, load address, copy-length field, and ZZZ-marker
 * string `"ZZzo..(-_- ) EX-5210 2022-07-20\0"` were verified
 * against bytes extracted from the official Kenwood TH-D75 firmware
 * updater (the descriptor at NOR offset `0x002000C0` of the main
 * firmware section decodes to the same field arrangement the layout
 * below produces. Fields believed boot-relevant from the D74 analysis —
 * load address `0xC0000000` and copy length — match exactly).
 */

/* Match the D74-derived first-word jump hypothesis. Making the ELF agree
 * lets static tooling catch internal drift; it is not proof of D75 behavior. */
ENTRY(__vector_table)

MEMORY
{
    /* NOR flash main-firmware slot. We don't actually link into FLASH.
     * Recording the slot here lets tools cross-reference the candidate
     * source location; the D74-derived copy-to-DDR behavior is unconfirmed
     * on D75. */
    FLASH (rx)  : ORIGIN = 0x60200000, LENGTH = 0x00280000  /* exact stock V1.03 main envelope */
    DDR   (rwx) : ORIGIN = 0xC0000000, LENGTH = 0x04000000  /* 64 MiB */
}

SECTIONS
{
    . = ORIGIN(DDR);
    __ddr_start = ORIGIN(DDR);
    __ddr_end = ORIGIN(DDR) + LENGTH(DDR);

    /* The firmware header MUST be at the start of the image:
     *   0x00 .. 0x40 : ARM exception vectors (8 × 4-byte branches)
     *   0x40 .. 0x80 : ZZZ marker (firmware_image_finalization)
     *   0x80 .. 0x100: version + primary and secondary descriptors
     *   0x100.. 0x200: erased padding; stock code begins at 0x200
     * D74 analysis assigns boot semantics to the descriptor and ZZZ fields;
     * the D75 consumer behavior remains to be captured. */
    .firmware_header ORIGIN(DDR) : ALIGN(4)
    {
        /* lld treats FILL as a four-byte pattern. FILL(0xFF) expands to
         * 00 00 00 FF, not four erased bytes; spell out all 32 bits. */
        FILL(0xFFFFFFFF)
        KEEP(*(.firmware_header.vectors))
        . = ORIGIN(DDR) + 0x40;
        KEEP(*(.firmware_header.finalization))
        . = ORIGIN(DDR) + 0x80;
        KEEP(*(.firmware_header.body))
        /* Stock D75 code begins at image offset 0x200. Keep the full gap
         * in this loadable section so llvm-objcopy preserves it as 0xFF. */
        . = ORIGIN(DDR) + 0x200;
    } > DDR

    .text ORIGIN(DDR) + 0x200 : ALIGN(4)
    {
        __image_start = .;
        *(.text._reset)        /* reset handler first so it's easy to spot in objdump */
        *(.text .text.*)
        *(.rodata .rodata.*)
        . = ALIGN(4);
    } > DDR

    .data : ALIGN(4)
    {
        *(.data .data.*)
        . = ALIGN(4);
    } > DDR

    __image_end    = .;
    __copy_length  = __image_end - ORIGIN(DDR);
    __flash_image_end = ORIGIN(FLASH) + __copy_length;

    .bss (NOLOAD) : ALIGN(4)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > DDR

    /* Stack lives at the top of DDR and grows downward. 64 KiB of stack
     * is wildly more than the dumper needs, but DDR is plentiful and the
     * generous margin makes a stray recursion bug fail loudly rather
     * than quietly corrupt the BSS. */
    __stack_top = ORIGIN(DDR) + LENGTH(DDR);

    /DISCARD/ :
    {
        /* Strip every unwinding / exception-table section — we panic-abort
         * and have no unwinder. Leaving these in would silently bloat
         * the .bin. */
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.note .note.*)
        *(.comment)
        *(.debug_*)
    }
}

ASSERT(SIZEOF(.firmware_header) == 0x200,
       "firmware header must occupy offsets 0x000..0x1FF")
ASSERT(ADDR(.text) == ORIGIN(DDR) + 0x200,
       "firmware text must begin at stock D75 image offset 0x200")
ASSERT(__copy_length <= LENGTH(FLASH),
       "payload exceeds the TH-D75 main-firmware slot")
