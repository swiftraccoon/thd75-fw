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

The filename address is a NOR-relative source offset. For ``FIRMWARE``,
the script maps flat-image offset zero to runtime DDR ``0xC0000000`` so
``0xC0000000 + flat_offset`` pointers resolve to bytes in this same blob.
Other extracted sections are mapped to their CPU-visible NOR addresses
(``0x60000000 + filename_offset``). Set
``REBASE_TO_ANALYSIS_ADDRESS = False`` below to keep file-offset zero.

For FIRMWARE: also marks the 8 ARM exception vectors as code, names
them, and disassembles. Other sections are data blobs — pointed at
the right `thd75-fw` CLI tool for structured access.
"""

import re

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

# The extracted filename stores a NOR-relative source offset. Main-firmware
# code and data use a flat runtime mapping at DDR_BASE; standalone data blobs
# use their CPU-visible NOR address so code xrefs can resolve if later imported
# into a shared program. The exact low-boot copy/entry implementation remains
# unknown until the D75 bootloader is captured.
NOR_WINDOW_BASE = 0x60000000
FIRMWARE_RUNTIME_BASE = 0xC0000000
REBASE_TO_ANALYSIS_ADDRESS = True


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

_FILENAME_RE = re.compile(r"^(?P<name>[A-Z0-9_]+?)_0x(?P<addr>[0-9A-Fa-f]{8})\.bin$")


def detect_section():
    """Return (section_name, NOR-relative offset) from the program name."""
    name = currentProgram.getDomainFile().getName()
    match = _FILENAME_RE.match(name)
    if not match:
        return (None, None)
    return (match.group("name"), int(match.group("addr"), 16))


def analysis_base(section_name, flash_offset):
    """Return the address at which this flat blob should be analyzed."""
    if section_name == "FIRMWARE":
        return FIRMWARE_RUNTIME_BASE
    return NOR_WINDOW_BASE + flash_offset


# Ghidra's Java methods take positional flags only (Jython cannot pass them by
# keyword), so each flag is named here.
FOLLOW_FLOW = True  # DisassembleCommand(start, restrictedSet, followFlow)
MAKE_PRIMARY = True  # createLabel(address, name, makePrimary, sourceType)
COMMIT_IMAGE_BASE = True  # Program.setImageBase(base, commit)


def annotate_arm_vectors(base):
    """Mark the 8 ARM vector slots as code and name each one."""
    listing = currentProgram.getListing()
    for offset, label, plate in VECTORS:
        ea = base.add(offset)
        # Disassemble at the vector
        cmd = DisassembleCommand(ea, None, FOLLOW_FLOW)
        cmd.applyTo(currentProgram)
        # Name the vector slot
        try:
            createLabel(ea, label, MAKE_PRIMARY, SourceType.USER_DEFINED)
        # Ghidra raises Java exceptions here; log and keep labelling the rest.
        except Exception as exc:  # noqa: BLE001
            print("could not label {}: {}".format(label, exc))
        # Plate comment
        listing.setComment(ea, CodeUnit.PLATE_COMMENT, plate)


def rebase_image(target_offset):
    """Set the program's image base so the first block lands at target_offset."""
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    new_base = space.getAddress(target_offset)
    try:
        currentProgram.setImageBase(new_base, COMMIT_IMAGE_BASE)
        print("Rebased image to 0x{:08X}".format(target_offset))
    # Ghidra raises Java exceptions here; report the failure to the caller.
    except Exception as exc:  # noqa: BLE001
        print("Rebase failed: {}".format(exc))
        return False
    else:
        return True


def main():
    """Configure the loaded thd75-fw section: rebase it and annotate vectors."""
    lang_id = currentProgram.getLanguageID().getIdAsString()
    print("Loaded language: {}".format(lang_id))
    if "ARM" not in lang_id:
        print(
            "WARNING: program isn't loaded as ARM. Re-import with language ARM:LE:32:v5t."
        )
        return

    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    if not blocks:
        print("No memory blocks found.")
        return

    section_name, flash_offset = detect_section()
    if section_name is None:
        print(
            "Filename didn't match thd75-extract pattern; skipping section-specific setup."
        )
        return

    nor_source = NOR_WINDOW_BASE + flash_offset
    target_base = analysis_base(section_name, flash_offset)
    print(
        "Detected section: {} (NOR offset 0x{:08X}, source 0x{:08X})".format(
            section_name, flash_offset, nor_source
        )
    )

    if REBASE_TO_ANALYSIS_ADDRESS and blocks[0].getStart().getOffset() != target_base:
        if not rebase_image(target_base):
            return
        # Refresh blocks reference after rebase
        blocks = memory.getBlocks()

    base = blocks[0].getStart()
    print("Base address: {}".format(base))

    if section_name == "FIRMWARE":
        annotate_arm_vectors(base)
        print("ARM exception vectors annotated.")
        print("Mapped the flat main image at runtime DDR 0xC0000000.")
        print("A pointer 0xC0000000 + N now resolves to flat-image offset N;")
        print("the updater stores the same image at NOR source 0x60200000.")
        print(
            "The uncaptured D75 low bootloader's exact copy/entry checks remain unknown."
        )
        print("Trigger 'Auto Analyze' from the Analysis menu to cascade.")
    elif section_name in ("DATA_0160", "IMAGE_DATA", "FONT_DATA", "DATA_00E0"):
        print("{} is a data blob, not executable code.".format(section_name))
        print("Use the appropriate thd75-fw extractor for structured access:")
        print("  - DATA_0160 (voice prompts):  thd75-extract-voice")
        print("  - IMAGE_DATA (PNG images):    thd75-extract-images")
        print("  - DATA_00E0 (AMBE2+ DSP):     no extractor (proprietary)")
        print("  - FONT_DATA (Shift-JIS):       no extractor yet")
    elif section_name == "CHECKBYTES":
        print("CHECKBYTES is the stock V1.03 B0 1D overlay written at 0x60200062.")
        print("Its D75 early-boot consumer and meaning are not yet confirmed.")
    elif section_name == "FINAL_ZZZ":
        print("FINAL_ZZZ is the stock 32-byte overlay written last at 0x60200040.")
        print("Its D75 early-boot consumer and meaning are not yet confirmed.")


main()
