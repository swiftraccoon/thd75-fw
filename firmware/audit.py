#!/usr/bin/env python3
"""Post-build safety audit for the TH-D75 NOR-flash dumper image.

Confirms invariants about the linked `dumper` ELF and flat binary that cannot be
expressed in source-code lints:

1. **Sections in DDR**: every loadable section (text, rodata, data,
   firmware_header) has a load address inside the DDR window
   (`0xC000_0000`-`0xC400_0000`). Catches a misplaced
   `#[link_section]` that would otherwise quietly drop code into the
   NOR window that precedes the official main-firmware image. Its D75 contents
   and partition boundaries are not yet known.

2. **NOR literal-pool inventory**: every NOR-window address
   (`0x6000_0000`-`0x6200_0000`) that appears anywhere in the binary
   is enumerated and the operator reviews the list. The dumper
   *reads* NOR by design; this surface lists which addresses the
   compiled code knows about so a future "I added a flash-erase
   helper" mistake shows up here as a new NOR address.

3. **Stock-image byte parity**: the ELF entry point, vector table, D75
   FINAL_ZZZ/CHECKBYTES overlays, two copy descriptors, erased padding,
   and code offset match the layout observed in stock V1.03. This does not
   establish which fields the uncaptured D75 bootloader consumes.

4. **Copy bounds**: the flat image fits within both descriptor copy
   lengths, the D75 main-firmware slot, and the DDR window.

Run via `make audit`. Exits 0 on PASS, non-zero on any failure.
Designed to run in CI; produces machine-readable section blocks plus
a human-readable summary.
"""

from __future__ import annotations

import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Final, NoReturn

# DDR window the firmware/linker.ld script targets. Loadable sections
# must live entirely inside this range.
DDR_START: int = 0xC000_0000
DDR_END: int = 0xC400_0000  # 64 MiB

# NOR window mapped by EMIFA chip-select 2 on the OMAP-L138. Source
# code in `dumper-omap/src/omap_l138.rs` declares the same range
# as `NOR_WINDOW_BASE` and `NOR_WINDOW_LEN`.
NOR_START: int = 0x6000_0000
NOR_END: int = 0x6200_0000  # 32 MiB

# D75 main-firmware boot-image layout, verified against the V1.03 FIRMWARE,
# FINAL_ZZZ, and CHECKBYTES resources under ``ref/extracted``.
FLASH_SLOT_START: int = 0x6020_0000
# The official V1.03 FIRMWARE block declares $EL=$CL=0x280000.  Keep
# that writable envelope separate from the stock image descriptor's
# larger 0x300000 copy_length: the two values are both real, but they
# establish different bounds.
STOCK_UPDATE_ENVELOPE_END: int = FLASH_SLOT_START + 0x0028_0000
DESCRIPTOR_COPY_END: int = FLASH_SLOT_START + 0x0030_0000
HEADER_SIZE: int = 0x200
TEXT_OFFSET: int = 0x200
FINALIZATION_OFFSET: int = 0x40
VERSION_OFFSET: int = 0x80
PRIMARY_DESCRIPTOR_OFFSET: int = 0xC0
SECONDARY_DESCRIPTOR_OFFSET: int = 0xE0
DESCRIPTOR_SIZE: int = 0x20
# Value of an erased NOR/flash byte. The updater fills unused header and
# metadata regions with this byte after the NUL terminator.
ERASED_BYTE: Final = 0xFF
FINAL_ZZZ_D75: bytes = b"ZZzo..(-_- ) EX-5210 2022-07-20\x00"
CHECKBYTES_D75_V103: bytes = b"\xb0\x1d"
VECTOR_OPCODE: bytes = struct.pack("<I", 0xE59F_F018)  # ldr pc, [pc, #0x18]
_DESCRIPTOR_STRUCT: struct.Struct = struct.Struct("<8I")
EXPECTED_PRIMARY_DESCRIPTOR: tuple[int, ...] = (
    0x6020_0000,
    0x6100_0000,
    0xC000_0000,
    0x0050_0000,
    0x0030_0000,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
)
EXPECTED_SECONDARY_DESCRIPTOR: tuple[int, ...] = (
    0x6020_0000,
    0x6060_0000,
    0xC000_0000,
    0x0050_0000,
    0x0030_0000,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
)

# These are the NOR addresses the dumper is *expected* to reference
# (reads only). Anything outside this set is flagged for human review.
# Match the values the source code carries — see
# `dumper-omap/src/omap_l138.rs::NOR_WINDOW_BASE` and the various
# `DumpRegion` arithmetic in `dumper/src/dump.rs`.
#
# The set covers both selectable regions (LowNorCandidate and FullNor)
# so the audit is region-independent: changing `crate::REGION` in
# `dumper/src/main.rs` does not require updating this list.
_LOW_NOR_CANDIDATE_LEN: int = 0x0020_0000
EXPECTED_NOR_ADDRS: frozenset[int] = frozenset(
    {
        NOR_START,  # NOR window base
        NOR_START + _LOW_NOR_CANDIDATE_LEN,  # candidate end (exclusive)
        NOR_START + _LOW_NOR_CANDIDATE_LEN - 1,  # candidate last byte
        NOR_START + _LOW_NOR_CANDIDATE_LEN - 4,  # candidate last word
        NOR_END,  # NOR window end (FullNor end)
        NOR_END - 1,  # NOR_WINDOW_END inclusive
        NOR_END - 4,  # NOR_WINDOW_LAST_WORD
    }
)

ELF_PATH: Path = (
    Path(__file__).parent / "target" / "armv5te-none-eabi" / "release" / "dumper"
)


@dataclass(frozen=True, slots=True)
class Section:
    """A `llvm-objdump -h` entry the audit cares about."""

    name: str
    size: int
    vma: int  # virtual memory address (= load address for our linker)
    flags: str


def _run(tool: str, *args: str) -> str:
    """Run `tool args...`, returning captured stdout. Exit on failure."""
    try:
        # The executable is a full path discovered under the developer's own
        # rustup toolchain directory and every argument is a string literal, so
        # no untrusted input reaches the process. S603 cannot be resolved
        # otherwise because the toolchain path is not a compile-time literal.
        return subprocess.check_output(  # noqa: S603
            [tool, *args],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except FileNotFoundError:
        _fail(
            f"{tool} not found on PATH. Install with: "
            f"rustup component add llvm-tools-preview --toolchain "
            f"nightly-2026-05-20",
        )
    except subprocess.CalledProcessError as exc:
        _fail(f"{tool} failed:\n{exc.output}")


def _fail(msg: str) -> NoReturn:
    """Print FAIL line and exit non-zero. Never returns."""
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _llvm_objdump() -> str:
    """Locate the llvm-objdump binary from the pinned nightly toolchain.

    `rustup which` only exposes the standard cargo/rustc/rustdoc set,
    not the `llvm-tools-preview` binaries — those live under the
    toolchain's `lib/rustlib/<host-triple>/bin/` directory. We mirror
    the discovery pattern the Makefile uses for `llvm-objcopy`.
    """
    home = Path.home() / ".rustup" / "toolchains"
    if not home.exists():
        _fail(f"rustup toolchains directory not found at {home}")
    candidates = sorted(home.glob("nightly-2026-05-20*/lib/rustlib/*/bin/llvm-objdump"))
    if not candidates:
        # Fall back to any nightly's copy.
        candidates = sorted(home.glob("nightly*/lib/rustlib/*/bin/llvm-objdump"))
    if not candidates:
        _fail(
            "llvm-objdump not found in any nightly toolchain. Install with: "
            "rustup component add llvm-tools-preview --toolchain "
            "nightly-2026-05-20",
        )
    return str(candidates[0])


def parse_sections(objdump_h_output: str) -> list[Section]:
    """Parse `llvm-objdump -h dumper` into Section records.

    The format is fixed-column-ish but tolerant of varying name widths:

        Idx Name              Size     VMA              Type
          0                   00000000 0000000000000000
          1 .firmware_header  00000088 00000000c0000000 DATA
          2 .text             0000034c 00000000c0000200 TEXT

    We keep only entries with a non-empty name and non-zero size — the
    section-header table has padding rows we ignore.
    """
    sections: list[Section] = []
    pattern = re.compile(
        r"^\s*\d+\s+(\.\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s*(\S+)?",
    )
    for line in objdump_h_output.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        name, size_hex, vma_hex, flags = m.groups()
        size = int(size_hex, 16)
        if size == 0:
            continue
        sections.append(
            Section(
                name=name,
                size=size,
                vma=int(vma_hex, 16),
                flags=flags or "",
            )
        )
    return sections


# Sections we don't care about — they don't get loaded onto the
# radio (debug, symbol table, etc.) so their VMA is irrelevant
# (typically 0). Module-level so both display and audit code agree.
NON_LOAD_PREFIXES: tuple[str, ...] = (
    ".debug_",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".comment",
    ".ARM.attributes",
    ".note",
)


def _is_loadable(name: str) -> bool:
    return not any(name.startswith(p) for p in NON_LOAD_PREFIXES)


def audit_sections(sections: list[Section]) -> list[str]:
    """Return a list of failure messages; empty list = PASS."""
    failures: list[str] = []
    loadable = [section for section in sections if _is_loadable(section.name)]
    for s in loadable:
        if not (DDR_START <= s.vma < DDR_END):
            failures.append(
                f"section {s.name} at 0x{s.vma:08X} (size 0x{s.size:X}) "
                f"is outside DDR window [0x{DDR_START:08X}..0x{DDR_END:08X})",
            )
        # Also catch sections that start in DDR but extend past it.
        end = s.vma + s.size
        if end > DDR_END:
            failures.append(
                f"section {s.name} extends past DDR end "
                f"(0x{s.vma:08X}+0x{s.size:X} = 0x{end:08X} > 0x{DDR_END:08X})",
            )

    by_name = {section.name: section for section in loadable}
    failures.extend(_audit_required_section_offsets(by_name))

    # A linker-script regression must not be able to overlap two loadable
    # sections while each independently remains inside DDR.
    ordered = sorted(loadable, key=lambda section: section.vma)
    for previous, current in pairwise(ordered):
        previous_end = previous.vma + previous.size
        if previous_end > current.vma:
            failures.append(
                f"loadable sections {previous.name} and {current.name} overlap "
                f"at 0x{current.vma:08X}",
            )
    return failures


def _audit_required_section_offsets(by_name: dict[str, Section]) -> list[str]:
    """Require the header and text sections at their fixed DDR offsets.

    Args:
        by_name: Loadable sections indexed by section name.

    Returns:
        A list of failure messages; an empty list means the required
        sections are present at their expected offsets.

    """
    failures: list[str] = []
    header = by_name.get(".firmware_header")
    text = by_name.get(".text")
    if header is None:
        failures.append("required .firmware_header section is missing")
    else:
        if header.vma != DDR_START:
            failures.append(
                ".firmware_header must start at "
                f"0x{DDR_START:08X}, got 0x{header.vma:08X}",
            )
        if header.size != HEADER_SIZE:
            failures.append(
                ".firmware_header must be exactly "
                f"0x{HEADER_SIZE:X} bytes, got 0x{header.size:X}",
            )
    if text is None:
        failures.append("required .text section is missing")
    elif text.vma != DDR_START + TEXT_OFFSET:
        failures.append(
            f".text must start at stock image offset 0x{TEXT_OFFSET:X} "
            f"(VMA 0x{DDR_START + TEXT_OFFSET:08X}), got 0x{text.vma:08X}",
        )
    return failures


def parse_start_address(objdump_f_output: str) -> int | None:
    """Extract the ELF start address from ``llvm-objdump -f`` output."""
    match = re.search(
        r"^start address:\s*(0x[0-9a-fA-F]+)\s*$", objdump_f_output, re.MULTILINE
    )
    return int(match.group(1), 16) if match else None


def audit_start_address(start_address: int | None) -> list[str]:
    """Require the ELF entry to agree with the candidate first-word jump."""
    if start_address is None:
        return ["could not parse ELF start address from llvm-objdump -f"]
    if start_address != DDR_START:
        return [
            f"ELF entry point must be vector-table base 0x{DDR_START:08X}, "
            f"got 0x{start_address:08X}",
        ]
    return []


def collect_nor_addresses(objdump_d_output: str) -> set[int]:
    """Scan disassembly for any value in the NOR window.

    ARM literal pools surface as hex constants in the disassembly's
    comment column, e.g.:

        ldr r0, [pc, #0x100]    @ 0x60000000

    We match any 8-hex-digit value that falls in the NOR window —
    regardless of context. A few false positives are acceptable
    (e.g. a non-NOR constant that happens to look like one); a missed
    real one is not.
    """
    found: set[int] = set()
    # Match 0x followed by exactly 8 hex digits; or a bare 8-digit
    # hex value preceded by `#` (immediate constant).
    for match in re.finditer(r"\b(?:0x|#)?([0-9a-fA-F]{8})\b", objdump_d_output):
        try:
            value = int(match.group(1), 16)
        except ValueError:
            continue
        if NOR_START <= value < NOR_END:
            found.add(value)
    # llvm-objdump renders ARM modified-immediate constants in decimal,
    # e.g. ``mov r5, #1610612736`` for NOR base 0x60000000.
    for match in re.finditer(r"#([0-9]{7,10})\b", objdump_d_output):
        value = int(match.group(1), 10)
        if NOR_START <= value < NOR_END:
            found.add(value)
    return found


def audit_nor_addresses(addrs: set[int]) -> list[str]:
    """Flag any NOR address that isn't in EXPECTED_NOR_ADDRS."""
    unexpected = sorted(addrs - EXPECTED_NOR_ADDRS)
    if not unexpected:
        return []
    return [
        f"unexpected NOR address 0x{a:08X} referenced in compiled output "
        f"(not in EXPECTED_NOR_ADDRS — verify it's used for a *read*, not a "
        f"write/erase, then add it to EXPECTED_NOR_ADDRS)"
        for a in unexpected
    ]


def _audit_metadata_field(field: bytes, name: str) -> list[str]:
    """Require a NUL-terminated field followed only by erased bytes."""
    try:
        terminator = field.index(0)
    except ValueError:
        return [f"{name} metadata field has no NUL terminator"]
    if any(byte != ERASED_BYTE for byte in field[terminator + 1 :]):
        return [f"{name} metadata padding after NUL is not all 0xFF"]
    return []


def _unpack_descriptor(bin_bytes: bytes, offset: int) -> tuple[int, ...]:
    """Decode one little-endian D75 image descriptor."""
    return _DESCRIPTOR_STRUCT.unpack_from(bin_bytes, offset)


def audit_binary_layout(bin_bytes: bytes) -> list[str]:
    """Validate boot-visible bytes and bounds in the flat image.

    Args:
        bin_bytes: The flat ``dumper.bin`` image.

    Returns:
        A list of failure messages; an empty list means every boot-visible
        byte range and copy bound matches stock V1.03.

    """
    if len(bin_bytes) <= TEXT_OFFSET:
        return [
            f"dumper.bin is only {len(bin_bytes)} bytes; it must contain "
            f"the 0x{HEADER_SIZE:X}-byte header and non-empty code",
        ]
    failures: list[str] = []
    failures.extend(_audit_vector_table(bin_bytes))
    failures.extend(_audit_finalization(bin_bytes))
    failures.extend(_audit_metadata_fields(bin_bytes))
    failures.extend(_audit_descriptors(bin_bytes))
    failures.extend(_audit_header_and_text_padding(bin_bytes))
    return failures


def _audit_vector_table(bin_bytes: bytes) -> list[str]:
    """Require eight deterministic vector slots and in-image handlers."""
    failures: list[str] = []
    expected_vectors = VECTOR_OPCODE * 8
    if bin_bytes[:0x20] != expected_vectors:
        failures.append(
            "vector instructions at offsets 0x00..0x1F are not eight "
            "deterministic ARM `ldr pc, [pc, #0x18]` slots",
        )
    handlers = struct.unpack_from("<8I", bin_bytes, 0x20)
    image_limit = DDR_START + len(bin_bytes)
    for index, handler in enumerate(handlers):
        if handler % 4 != 0 or not (DDR_START + TEXT_OFFSET <= handler < image_limit):
            failures.append(
                f"vector {index} handler 0x{handler:08X} is not a word-aligned "
                f"address inside loaded image text",
            )
    if handlers[0] != DDR_START + TEXT_OFFSET:
        failures.append(
            f"reset vector must target 0x{DDR_START + TEXT_OFFSET:08X}, "
            f"got 0x{handlers[0]:08X}",
        )
    return failures


def _audit_finalization(bin_bytes: bytes) -> list[str]:
    """Require the exact FINAL_ZZZ + CHECKBYTES finalization block at 0x40."""
    expected_finalization = (
        FINAL_ZZZ_D75 + b"\xff\xff" + CHECKBYTES_D75_V103 + b"\xff" * 28
    )
    actual_finalization = bin_bytes[FINALIZATION_OFFSET:VERSION_OFFSET]
    if actual_finalization != expected_finalization:
        return [
            "finalization bytes at 0x40..0x7F do not match D75 V1.03 "
            "FINAL_ZZZ + erased complete word + CHECKBYTES B0 1D + erased padding",
        ]
    return []


def _audit_metadata_fields(bin_bytes: bytes) -> list[str]:
    """Require NUL-terminated, erased-padded name and version fields."""
    failures: list[str] = []
    failures.extend(
        _audit_metadata_field(
            bin_bytes[VERSION_OFFSET : VERSION_OFFSET + 0x20], "name"
        ),
    )
    failures.extend(
        _audit_metadata_field(
            bin_bytes[VERSION_OFFSET + 0x20 : PRIMARY_DESCRIPTOR_OFFSET],
            "version",
        ),
    )
    return failures


def _audit_descriptors(bin_bytes: bytes) -> list[str]:
    """Require both copy descriptors and the primary descriptor's bounds."""
    failures: list[str] = []
    primary = _unpack_descriptor(bin_bytes, PRIMARY_DESCRIPTOR_OFFSET)
    secondary = _unpack_descriptor(bin_bytes, SECONDARY_DESCRIPTOR_OFFSET)
    if primary != EXPECTED_PRIMARY_DESCRIPTOR:
        failures.append("primary descriptor does not match D75 V1.03 layout")
    if secondary != EXPECTED_SECONDARY_DESCRIPTOR:
        failures.append("secondary descriptor does not match D75 V1.03 layout")
    failures.extend(_audit_primary_descriptor_bounds(primary, len(bin_bytes)))
    return failures


def _audit_primary_descriptor_bounds(
    primary: tuple[int, ...], image_size: int
) -> list[str]:
    """Require the primary descriptor's addresses and copy-length bounds.

    Args:
        primary: The decoded primary copy descriptor.
        image_size: The length of the flat ``dumper.bin`` image in bytes.

    Returns:
        A list of failure messages; an empty list means the descriptor's
        addresses and copy bounds are all within the stock envelopes.

    """
    failures: list[str] = []
    (
        flash_start,
        _flash_limit,
        load_address,
        image_length,
        copy_length,
        reserved_0,
        reserved_1,
        reserved_2,
    ) = primary
    if flash_start != FLASH_SLOT_START:
        failures.append(
            f"descriptor flash_start_addr must be 0x{FLASH_SLOT_START:08X}, "
            f"got 0x{flash_start:08X}",
        )
    if load_address != DDR_START:
        failures.append(
            f"descriptor load_address must be 0x{DDR_START:08X}, "
            f"got 0x{load_address:08X}",
        )
    if image_length < image_size:
        failures.append(
            f"descriptor image_length {image_length:,} is smaller than "
            f"dumper.bin ({image_size:,} bytes)",
        )
    if copy_length < image_size:
        failures.append(
            f"descriptor copy_length {copy_length:,} would truncate "
            f"dumper.bin ({image_size:,} bytes)",
        )
    if image_size > STOCK_UPDATE_ENVELOPE_END - FLASH_SLOT_START:
        failures.append(
            "dumper.bin exceeds the exact 2.5 MiB V1.03 FIRMWARE update envelope",
        )
    if copy_length > DESCRIPTOR_COPY_END - FLASH_SLOT_START:
        failures.append(
            "descriptor copy_length exceeds the stock 3 MiB copy envelope",
        )
    if copy_length > DDR_END - DDR_START:
        failures.append("descriptor copy_length exceeds the 64 MiB DDR window")
    if (reserved_0, reserved_1, reserved_2) != (0xFFFF_FFFF,) * 3:
        failures.append("descriptor reserved words are not all 0xFFFFFFFF")
    return failures


def _audit_header_and_text_padding(bin_bytes: bytes) -> list[str]:
    """Require an erased header gap and a non-empty code payload."""
    failures: list[str] = []
    erased_gap = bin_bytes[SECONDARY_DESCRIPTOR_OFFSET + DESCRIPTOR_SIZE : TEXT_OFFSET]
    if erased_gap != b"\xff" * len(erased_gap):
        failures.append("header padding at 0x100..0x1FF is not all erased 0xFF")
    if bin_bytes[TEXT_OFFSET:] == b"\xff" * (len(bin_bytes) - TEXT_OFFSET):
        failures.append(".text payload is entirely erased bytes")
    return failures


def audit_binary_size_vs_sections(
    bin_bytes: bytes, sections: list[Section]
) -> list[str]:
    """Require objcopy output to include every loadable byte exactly once."""
    # ``.bss`` is part of a PT_LOAD memory image but has no file bytes; startup
    # zeroes it. llvm-objdump labels these entries ``BSS`` in the Type column.
    file_backed = [
        section
        for section in sections
        if _is_loadable(section.name) and section.flags.upper() != "BSS"
    ]
    if not file_backed:
        return ["no loadable sections available for flat-binary size check"]
    expected_size = (
        max(section.vma + section.size for section in file_backed) - DDR_START
    )
    if len(bin_bytes) != expected_size:
        return [
            f"dumper.bin is {len(bin_bytes):,} bytes but ELF loadable sections "
            f"span {expected_size:,} bytes from DDR base",
        ]
    return []


def _print_section_report(sections: list[Section], start_address: int | None) -> None:
    """Print the loadable-section placement table and the ELF entry point."""
    print()
    print("== loadable sections (must be in DDR) ==")
    for s in sections:
        if not _is_loadable(s.name):
            print(f"  [meta] {s.name:<24s} 0x{s.vma:08X} +0x{s.size:X}")
            continue
        in_ddr = DDR_START <= s.vma < DDR_END
        mark = "OK  " if in_ddr else "FAIL"
        print(f"  [{mark}] {s.name:<24s} 0x{s.vma:08X} +0x{s.size:X}")
    if start_address is not None:
        print(f"  [entry] ELF start address       0x{start_address:08X}")


def _print_nor_report(nor_addrs: set[int]) -> None:
    """Print the inventory of NOR-window addresses seen in the disassembly."""
    print()
    print("== NOR addresses referenced in compiled output ==")
    if nor_addrs:
        for a in sorted(nor_addrs):
            tag = "expected" if a in EXPECTED_NOR_ADDRS else "UNEXPECTED"
            print(f"  [{tag}] 0x{a:08X}")
    else:
        print("  (none)")


def _print_image_report(bin_bytes: bytes) -> None:
    """Print the flat boot-image layout summary."""
    primary = _unpack_descriptor(bin_bytes, PRIMARY_DESCRIPTOR_OFFSET)
    print()
    print("== flat stock-shaped candidate image ==")
    print(f"  size:            {len(bin_bytes):,} bytes (0x{len(bin_bytes):X})")
    print(f"  vector table:    0x000..0x03F ({len(VECTOR_OPCODE) * 16} bytes)")
    print(f"  FINAL_ZZZ:       0x{FINALIZATION_OFFSET:03X} ({FINAL_ZZZ_D75!r})")
    print(f"  CHECKBYTES:      0x062 ({CHECKBYTES_D75_V103.hex(' ').upper()})")
    print(
        f"  descriptors:     0x{PRIMARY_DESCRIPTOR_OFFSET:03X}, "
        f"0x{SECONDARY_DESCRIPTOR_OFFSET:03X}"
    )
    print(f"  load address:    0x{primary[2]:08X}")
    print(f"  copy length:     {primary[4]:,} bytes (0x{primary[4]:X})")
    print(f"  .text offset:    0x{TEXT_OFFSET:03X}")


def main() -> int:
    """Run every post-build audit and return the process exit code.

    Returns:
        ``0`` when all audits pass, ``1`` when any audit reports a failure.
        Missing build artifacts or tools exit non-zero via :func:`_fail`.

    """
    if not ELF_PATH.exists():
        _fail(
            f"ELF not found at {ELF_PATH}. Build first: "
            f"`make build` in the firmware/ directory.",
        )

    bin_path = ELF_PATH.with_suffix(".bin")
    if not bin_path.exists():
        _fail(f"flat binary not found at {bin_path}. Build first: `make bin`.")
    bin_bytes = bin_path.read_bytes()

    print(f"audit: {ELF_PATH}")
    objdump = _llvm_objdump()

    # --- Section audit ----------------------------------------------------
    sections_out = _run(objdump, "-h", str(ELF_PATH))
    sections = parse_sections(sections_out)
    if not sections:
        _fail("no sections parsed from objdump -h output")

    section_failures = audit_sections(sections)
    start_address = parse_start_address(_run(objdump, "-f", str(ELF_PATH)))
    start_failures = audit_start_address(start_address)
    _print_section_report(sections, start_address)

    # --- NOR literal-pool audit -------------------------------------------
    dis_out = _run(objdump, "-d", str(ELF_PATH))
    nor_addrs = collect_nor_addresses(dis_out)
    nor_failures = audit_nor_addresses(nor_addrs)
    _print_nor_report(nor_addrs)

    # --- Flat boot-image layout audit ------------------------------------
    binary_failures = audit_binary_layout(bin_bytes)
    binary_size_failures = audit_binary_size_vs_sections(bin_bytes, sections)
    _print_image_report(bin_bytes)

    # --- Verdict ----------------------------------------------------------
    print()
    failures = (
        section_failures
        + start_failures
        + nor_failures
        + binary_failures
        + binary_size_failures
    )
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print("audit: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
