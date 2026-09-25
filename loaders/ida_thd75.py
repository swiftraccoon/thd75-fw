"""IDA Pro setup script for thd75-fw firmware sections.

Drop into IDA's `python/` or run via File > Script File... after opening
a section binary (e.g., FIRMWARE_0x00200000.bin). Detects which section
is loaded by filename and applies appropriate configuration:

  - Sets segment permissions to RWX (IDA refuses code creation otherwise)
  - Sets segment bitness to 32-bit (ARM)
  - Maps `FIRMWARE` at runtime DDR `0xC0000000`, so a pointer of the
    form `0xC0000000 + flat_offset` resolves inside the extracted blob.
    Other sections map to CPU-visible NOR (`0x60000000 + filename offset`).
  - For FIRMWARE: marks the 7 active ARM exception vector slots as code
    (slot 0x14 is reserved on ARMv5+ and decoded as data), names each,
    labels the literal pool, and triggers cascade auto-analysis —
    typically yielding 15,000+ functions on V1.03.

USAGE
-----

If the database is fresh (just opened), ideally launch IDA with
``-pARM`` so the processor is already correct::

    ida -A -pARM FIRMWARE_0x00200000.bin

Then run this script. If you opened without ``-pARM``, the script will
attempt to switch processor — but IDA only allows that on a fresh DB,
so you may need to delete the .i64 and reopen with ``-pARM``.

CONFIGURATION
-------------

Set ``REBASE_TO_ANALYSIS_ADDRESS = False`` below to skip the auto-rebase
and keep the segment at file-offset 0. The filename value (for example,
``0x00200000`` in ``FIRMWARE_0x00200000.bin``) remains the NOR-relative
source offset; it is not the main image's runtime code address.
"""

from __future__ import annotations

import re
from pathlib import Path

import ida_auto
import ida_bytes
import ida_idp
import ida_name
import ida_segment
import ida_ua
import idc

# The updater stores section addresses as offsets within the CPU-visible NOR
# window. Main-firmware pointers instead follow the flat DDR mapping
# C0000000+file_offset. Mapping that blob at DDR makes its handler pointers and
# service tables resolve without inventing a separate runtime blob. This does
# not prove the uncaptured D75 low bootloader's exact copy/entry semantics.
NOR_WINDOW_BASE: int = 0x6000_0000
FIRMWARE_RUNTIME_BASE: int = 0xC000_0000
REBASE_TO_ANALYSIS_ADDRESS: bool = True

# Each entry is a vector offset, its label, and its plate comment.
# Slot at 0x14 is reserved on ARMv5+ (was "address exception" in ARMv4 and
# earlier) and is conventionally left as zero / DCB 0.
VECTORS: list[tuple[int, str, str]] = [
    (0x00, "reset_vector", "Reset"),
    (0x04, "undef_vector", "Undefined Instruction"),
    (0x08, "svc_vector", "Supervisor Call (SWI)"),
    (0x0C, "prefetch_abort_vector", "Prefetch Abort"),
    (0x10, "data_abort_vector", "Data Abort"),
    (0x18, "irq_vector", "IRQ"),
    (0x1C, "fiq_vector", "FIQ"),
]

# Pattern matches filenames produced by `thd75-extract`,
# e.g. "FIRMWARE_0x00200000.bin", "DATA_0160_0x01600000.bin".
_FILENAME_RE = re.compile(r"^(?P<name>[A-Z0-9_]+?)_0x(?P<addr>[0-9A-Fa-f]{8})\.bin$")


def _msg(text: str) -> None:
    """Print to IDA's output window."""
    print(f"[thd75-fw] {text}")


def _ensure_arm_processor() -> bool:
    """Return True if the processor is ARM (or we successfully switched)."""
    if ida_idp.get_idp_name() == "arm":
        return True

    _msg(f"current processor is '{ida_idp.get_idp_name()}', not arm")
    _msg("attempting to switch to ARM (only works on fresh databases)...")
    if ida_idp.set_processor_type("arm", ida_idp.SETPROC_USER):
        _msg("processor switched to arm")
        return True

    _msg("processor switch failed. Recover by:")
    _msg("  1. File > Save (or close without save)")
    _msg("  2. Quit IDA")
    _msg("  3. Delete the .i64 file next to the .bin")
    _msg("  4. Reopen with: ida -A -pARM <file.bin>")
    return False


def _configure_segment(seg: ida_segment.segment_t) -> None:
    """Set RWX permissions and 32-bit bitness so IDA accepts code creation."""
    seg.perm = (
        ida_segment.SEGPERM_EXEC | ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE
    )
    seg.type = ida_segment.SEG_CODE
    seg.bitness = 1  # 0=16, 1=32, 2=64
    seg.update()


def _annotate_arm_vectors(base: int) -> None:
    """Mark the 8 vector slots as code, name them, comment them.

    Each LDR instruction at vector slot N references a literal pool
    entry at base+0x20+(N*4-ish); IDA resolves these automatically once
    the slot is decoded as an instruction.
    """
    for offset, label, plate in VECTORS:
        ea = base + offset
        ida_ua.create_insn(ea)
        ida_name.set_name(ea, label, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
        idc.set_cmt(ea, plate, 0)

    # Reserved slot at 0x14 is conventionally zero on ARMv5+
    ida_bytes.create_dword(base + 0x14, 4)
    idc.set_cmt(base + 0x14, "(reserved on ARMv5+)", 0)

    # Literal pool: 8 dwords of handler addresses at base+0x20..base+0x3C
    for off in range(0x20, 0x40, 4):
        ida_bytes.create_dword(base + off, 4)


def _detect_section() -> tuple[str, int] | None:
    """Parse the loaded filename for section name + NOR-relative offset."""
    path = idc.get_input_file_path()
    if not path:
        return None
    match = _FILENAME_RE.match(Path(path).name)
    if not match:
        return None
    return (match.group("name"), int(match.group("addr"), 16))


def _analysis_base(section_name: str, flash_offset: int) -> int:
    """Return the address at which this flat blob should be analyzed."""
    if section_name == "FIRMWARE":
        return FIRMWARE_RUNTIME_BASE
    return NOR_WINDOW_BASE + flash_offset


def _rebase_to(target_addr: int, current_seg: ida_segment.segment_t) -> bool:
    """Rebase the program so the first segment starts at ``target_addr``.

    Returns True if a rebase happened (or no-op if already correct);
    False on failure.
    """
    if current_seg.start_ea == target_addr:
        _msg(f"segment already at 0x{target_addr:08X}; no rebase needed")
        return True
    delta = target_addr - current_seg.start_ea
    rc = ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE)
    if rc != 0:
        _msg(f"rebase to 0x{target_addr:08X} failed (code {rc})")
        return False
    _msg(f"rebased segment to 0x{target_addr:08X} (delta 0x{delta:08X})")
    return True


def main() -> None:
    """Configure the loaded thd75-fw section: segment, rebase and vectors."""
    if not _ensure_arm_processor():
        return

    seg = ida_segment.get_first_seg()
    if seg is None:
        _msg("no segment found in database")
        return

    _configure_segment(seg)
    _msg(f"segment configured: {hex(seg.start_ea)}-{hex(seg.end_ea)} RWX 32-bit")

    detected = _detect_section()
    if detected is None:
        _msg(
            "filename did not match thd75-extract pattern; "
            "skipping section-specific setup"
        )
        return

    section_name, flash_offset = detected
    nor_source = NOR_WINDOW_BASE + flash_offset
    target_base = _analysis_base(section_name, flash_offset)
    _msg(
        f"detected section: {section_name} "
        f"(NOR offset 0x{flash_offset:08X}, source 0x{nor_source:08X})"
    )

    # Map main code at runtime DDR; map standalone data at CPU-visible NOR.
    if REBASE_TO_ANALYSIS_ADDRESS:
        if not _rebase_to(target_base, seg):
            return
        # After rebase, refresh our segment handle since start_ea changed.
        seg = ida_segment.get_first_seg()

    base = seg.start_ea  # this is now flash_addr if we rebased, else 0

    if section_name == "FIRMWARE":
        _annotate_arm_vectors(base)
        _msg("ARM exception vectors annotated; running auto-analysis...")
        ida_auto.plan_and_wait(seg.start_ea, seg.end_ea)
        _msg("done. flat offset N is mapped to runtime address 0xC0000000 + N")
        _msg(
            "the updater stores this image at NOR source 0x60200000; exact "
            "D75 low-boot copy/entry checks remain unconfirmed"
        )
    elif section_name in ("DATA_0160", "IMAGE_DATA", "FONT_DATA", "DATA_00E0"):
        _msg(f"{section_name} is a data blob, not code — no analysis applied.")
        _msg("use the appropriate thd75-fw extractor for structured access:")
        _msg("  - DATA_0160 (voice prompts):  thd75-extract-voice")
        _msg("  - IMAGE_DATA (PNG images):    thd75-extract-images")
        _msg("  - DATA_00E0 (AMBE2+ DSP):     no extractor (proprietary format)")
        _msg("  - FONT_DATA (Shift-JIS bitmaps):  no extractor yet")
    elif section_name == "CHECKBYTES":
        _msg(
            "CHECKBYTES is the stock V1.03 B0 1D overlay at 0x60200062; "
            "its D75 early-boot consumer and meaning are unconfirmed"
        )
        ida_bytes.create_word(base, 2)
    elif section_name == "FINAL_ZZZ":
        _msg(
            "FINAL_ZZZ is the stock 32-byte overlay written last at "
            "0x60200040; its D75 early-boot meaning is unconfirmed"
        )


if __name__ == "__main__":
    main()
