# @category TH-D75
# @author thd75-fw
# @description Annotates ARM exception vectors and configures section
#              metadata for binaries produced by thd75-extract.
"""Ghidra post-import script for thd75-fw firmware sections.

USAGE
-----
1. Place this file in your `~/ghidra_scripts/` directory (or any
   directory configured under Window > Script Manager > Manage Script
   Directories).
2. Import the binary in Ghidra:
     File > Import File... > select FIRMWARE_0x00200000.bin
   At the import dialog, set:
     - Format: Raw Binary
     - Language: ARM:LE:32:v5t   (the OMAP-L138's ARM926EJ-S supports v5te)
     - Block name: ROM (or whatever you prefer)
     - Base Address: 0x00000000   (the script will rebase automatically)
3. After auto-analysis, open Window > Script Manager and run this script.

The script extracts the flash address from the filename
(e.g., 0x00200000 from FIRMWARE_0x00200000.bin) and rebases the
image automatically so addresses in Ghidra match the README's section
table. Set REBASE_TO_FLASH_ADDRESS = False below to skip the rebase.

For FIRMWARE: also marks the 8 ARM exception vectors as code, names
them, and disassembles. Other sections are data blobs — pointed at
the right `thd75-fw` CLI tool for structured access.
"""

# Auto-rebase the image to the flash address parsed from the filename.
# When True (default): segment ends up at e.g. 0x00200000 for FIRMWARE,
# matching the addresses in README's section table.
REBASE_TO_FLASH_ADDRESS = True


import os
import re

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.listing import CodeUnit


# (offset, label, plate_comment). Slot at 0x14 is reserved on ARMv5+.
VECTORS = [
    (0x00, "reset_vector", "Reset"),
    (0x04, "undef_vector", "Undefined Instruction"),
    (0x08, "svc_vector", "Supervisor Call (SWI)"),
    (0x0C, "prefetch_abort_vector", "Prefetch Abort"),
    (0x10, "data_abort_vector", "Data Abort"),
    (0x18, "irq_vector", "IRQ"),
    (0x1C, "fiq_vector", "FIQ"),
]

_FILENAME_RE = re.compile(
    r"^(?P<name>[A-Z0-9_]+?)_0x(?P<addr>[0-9A-Fa-f]{8})\.bin$"
)


def detect_section():
    """Return (section_name, flash_address) parsed from the program name."""
    name = currentProgram.getDomainFile().getName()
    match = _FILENAME_RE.match(name)
    if not match:
        return (None, None)
    return (match.group("name"), int(match.group("addr"), 16))


def annotate_arm_vectors(base):
    """Mark the 8 ARM vector slots as code and name each one."""
    listing = currentProgram.getListing()
    for offset, label, plate in VECTORS:
        ea = base.add(offset)
        # Disassemble at the vector
        cmd = DisassembleCommand(ea, None, True)
        cmd.applyTo(currentProgram)
        # Name the vector slot
        try:
            createLabel(ea, label, True, SourceType.USER_DEFINED)
        except Exception as exc:  # noqa: BLE001
            print("could not label {}: {}".format(label, exc))
        # Plate comment
        listing.setComment(ea, CodeUnit.PLATE_COMMENT, plate)


def rebase_image(target_offset):
    """Set the program's image base so the first block lands at target_offset."""
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    new_base = space.getAddress(target_offset)
    try:
        currentProgram.setImageBase(new_base, True)
        print("Rebased image to 0x{:08X}".format(target_offset))
        return True
    except Exception as exc:  # noqa: BLE001
        print("Rebase failed: {}".format(exc))
        return False


def main():
    lang_id = currentProgram.getLanguageID().getIdAsString()
    print("Loaded language: {}".format(lang_id))
    if "ARM" not in lang_id:
        print("WARNING: program isn't loaded as ARM. Re-import with language ARM:LE:32:v5t.")
        return

    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    if not blocks:
        print("No memory blocks found.")
        return

    section_name, flash_addr = detect_section()
    if section_name is None:
        print("Filename didn't match thd75-extract pattern; skipping section-specific setup.")
        return

    print("Detected section: {} (flash 0x{:08X})".format(section_name, flash_addr))

    if REBASE_TO_FLASH_ADDRESS and blocks[0].getStart().getOffset() != flash_addr:
        if not rebase_image(flash_addr):
            return
        # Refresh blocks reference after rebase
        blocks = memory.getBlocks()

    base = blocks[0].getStart()
    print("Base address: {}".format(base))

    if section_name == "FIRMWARE":
        annotate_arm_vectors(base)
        print("ARM exception vectors annotated.")
        print("Note: handler addresses (0xC0xxxxxx) point into OMAP-L138 DDR,")
        print("outside this segment. The DDR-resident image is loaded by the")
        print("bootloader at runtime, not contained in this flash blob.")
        print("Trigger 'Auto Analyze' from the Analysis menu to cascade.")
    elif section_name in ("DATA_0160", "IMAGE_DATA", "FONT_DATA", "DATA_00E0"):
        print("{} is a data blob, not executable code.".format(section_name))
        print("Use the appropriate thd75-fw extractor for structured access:")
        print("  - DATA_0160 (voice prompts):  thd75-extract-voice")
        print("  - IMAGE_DATA (PNG images):    thd75-extract-images")
        print("  - DATA_00E0 (AMBE2+ DSP):     no extractor (proprietary)")
        print("  - FONT_DATA (Shift-JIS):       no extractor yet")
    elif section_name == "CHECKBYTES":
        print("CHECKBYTES is a 2-byte bootloader integrity checksum.")
    elif section_name == "FINAL_ZZZ":
        print("FINAL_ZZZ is a 32-byte build marker written last to confirm")
        print("update completion.")


main()
