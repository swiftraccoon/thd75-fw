#!/usr/bin/env python3
"""Reproducibly build and audit the TH-D75 USB-storage recovery overlay.

The assembly is linked at its final CPU addresses.  This tool builds it twice,
requires byte-identical objects and ELFs, parses the ELF directly, and overlays
only the explicitly allowlisted allocated sections onto the exact
normal-gm-nor-read flat image.  It never treats gaps between linked sections as
firmware bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Final

# Shared with the sibling ``build_radio_automation.py`` stage, which links its
# overlay on top of this one and reuses these helpers.
__all__ = [
    "ElfSection",
    "elf_sections",
    "firmware_checksum",
    "resolve_executable",
    "run_logged",
]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ASSEMBLY = _REPO_ROOT / "scripts" / "usb_storage_recovery.s"
_LINKER_SCRIPT = _REPO_ROOT / "scripts" / "usb_storage_recovery.ld"
_CPU_IMAGE_BASE = 0xC000_0000
_SOURCE_SIZE = 0x28_0000
_SOURCE_SHA256 = "2eddf487e985861c95fb4212d0f7eabfb57c648eee06f3141819582226fd6ea0"

# ELF32 little-endian layout values checked while parsing the linked output
# (System V ABI, ELF chapter).
_ELF32_HEADER_SIZE: Final = 52
_ELF_MACHINE_ARM: Final = 40
_ELF32_SECTION_HEADER_SIZE: Final = 40

# Each section must start exactly where the reviewed linker script places it
# and must remain inside its independently identified instruction/data cave.
_SECTION_BOUNDS: dict[str, tuple[int, int]] = {
    ".trigger": (0xC002_EC0E, 0xC002_EC4E),
    ".gw_entry": (0xC002_F368, 0xC002_F36A),
    ".storage_helper": (0xC002_F36A, 0xC002_F3A4),
    ".gw_literal": (0xC002_F6E8, 0xC002_F6EC),
    ".gm_ddr_base": (0xC006_F8A0, 0xC006_F8A2),
    ".storage_set_desired": (0xC008_D830, 0xC008_D858),
    ".storage_call": (0xC008_D9F8, 0xC008_D9FE),
    ".shutdown_gate": (0xC00D_95CE, 0xC00D_95D6),
    ".physical_command_single_call": (0xC00F_E5AA, 0xC00F_E5AE),
    ".physical_count_single_call": (0xC00F_E5CA, 0xC00F_E5CE),
    ".physical_command_multi_call": (0xC00F_E60E, 0xC00F_E612),
    ".physical_count_multi_call": (0xC00F_E62E, 0xC00F_E632),
    ".capacity_count_fix": (0xC010_1178, 0xC010_117A),
    ".physical_read_call": (0xC010_11E8, 0xC010_11EC),
    ".fifo_hook": (0xC010_1D5A, 0xC010_1D5E),
    ".sem_hook": (0xC010_1ECC, 0xC010_1ED0),
    ".media_status_call": (0xC017_1B56, 0xC017_1B5A),
    ".media_status_guard": (0xC017_1B5C, 0xC017_1B5E),
    ".worker_startup_call": (0xC017_1DFA, 0xC017_1DFE),
    ".read10_backend_call": (0xC017_205A, 0xC017_205E),
    ".read10_send_call": (0xC017_20A4, 0xC017_20A8),
    ".attach_call": (0xC017_D910, 0xC017_D918),
    ".teardown_call": (0xC017_D956, 0xC017_D95A),
    ".storage_lease_call": (0xC017_D992, 0xC017_D996),
    ".phase2_gate": (0xC017_D99E, 0xC017_D9A6),
    ".msc_probe": (0xC019_C360, 0xC019_C390),
    ".runtime_telemetry": (0xC019_C390, 0xC019_C67C),
    ".phase2_runtime": (0xC019_C67C, 0xC019_C700),
    ".worker_runtime": (0xC019_C700, 0xC019_C860),
    ".shutdown_runtime": (0xC019_C860, 0xC019_CA00),
    ".lease_runtime": (0xC019_CA00, 0xC019_CB00),
    ".fifo_recovery_runtime": (0xC019_CB00, 0xC019_D000),
}


@dataclass(frozen=True, slots=True)
class ElfSection:
    """One allocated PROGBITS section extracted from a linked ELF."""

    name: str
    address: int
    data: bytes


def _sha256(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def firmware_checksum(image: bytes) -> int:
    """Return the 16-bit little-endian word-sum checksum of ``image``.

    Args:
        image: The flat firmware bytes to sum.

    Returns:
        The truncated 16-bit sum of every little-endian 16-bit word, with a
        trailing odd byte added on its own.

    """
    total = sum(
        image[offset] | (image[offset + 1] << 8)
        for offset in range(0, len(image) - 1, 2)
    )
    if len(image) % 2:
        total += image[-1]
    return total & 0xFFFF


def resolve_executable(explicit: str | None, candidates: tuple[str, ...]) -> str:
    """Resolve an executable path from an explicit choice or a candidate list.

    Args:
        explicit: A user-supplied executable name or path, or ``None``.
        candidates: Fallback executables tried in order when ``explicit`` is
            ``None``; absolute files are used directly, others via ``PATH``.

    Returns:
        The resolved executable path.

    Raises:
        ValueError: If ``explicit`` cannot be resolved, or if no candidate is
            found.

    """
    if explicit is not None:
        resolved = shutil.which(explicit)
        if resolved is None:
            msg = f"executable not found: {explicit}"
            raise ValueError(msg)
        return resolved
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
        resolved = shutil.which(candidate)
        if resolved is not None:
            return resolved
    msg = f"none of these executables was found: {', '.join(candidates)}"
    raise ValueError(msg)


def run_logged(command: list[str], log: list[str]) -> None:
    """Run ``command``, appending the invocation and its output to ``log``.

    Args:
        command: The argument vector to execute.
        log: A running build log that receives the command and its captured
            standard output and error.

    Raises:
        RuntimeError: If the command exits with a non-zero status.

    """
    log.append("$ " + " ".join(command))
    # The command is a fixed audit tool resolved by ``resolve_executable`` with
    # a static argument list and no shell; no untrusted input reaches it.
    completed = subprocess.run(  # noqa: S603
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.stdout:
        log.append(completed.stdout.rstrip())
    if completed.stderr:
        log.append(completed.stderr.rstrip())
    if completed.returncode != 0:
        msg = f"command exited {completed.returncode}: {' '.join(command)}"
        raise RuntimeError(msg)


def _build_once(
    directory: Path,
    *,
    clang: str,
    linker: str,
    log: list[str],
) -> tuple[Path, Path]:
    """Assemble and link the overlay once into ``directory``.

    Args:
        directory: A new directory to hold this build's object and ELF.
        clang: The ARM-capable clang executable.
        linker: The ld.lld executable.
        log: A running build log for the compile and link commands.

    Returns:
        The assembled object path and the linked ELF path.

    """
    directory.mkdir()
    object_path = directory / "usb_storage_recovery.o"
    elf_path = directory / "usb_storage_recovery.elf"
    run_logged(
        [
            clang,
            "--target=arm-none-eabi",
            "-mcpu=arm926ej-s",
            "-mthumb",
            "-c",
            str(_ASSEMBLY),
            "-o",
            str(object_path),
        ],
        log,
    )
    run_logged(
        [
            linker,
            "--build-id=none",
            "-T",
            str(_LINKER_SCRIPT),
            str(object_path),
            "-o",
            str(elf_path),
        ],
        log,
    )
    return object_path, elf_path


def _parse_elf_section_table(elf: bytes) -> tuple[int, int, int]:
    """Validate an ELF32 little-endian header and locate its section table.

    Args:
        elf: The full linked ELF image.

    Returns:
        The section-header table's byte offset, the number of section headers,
        and the index of the section-name string table.

    Raises:
        ValueError: If the image is not a little-endian ARM ELF32 file, or its
            section table lies outside the image.

    """
    if len(elf) < _ELF32_HEADER_SIZE or elf[:4] != b"\x7fELF":
        msg = "linked output is not an ELF file"
        raise ValueError(msg)
    if elf[4] != 1 or elf[5] != 1:
        msg = "linked output must be ELF32 little-endian"
        raise ValueError(msg)
    header: tuple[int, ...] = struct.unpack_from("<HHIIIIIHHHHHH", elf, 16)
    machine = header[1]
    section_offset = header[5]
    section_entry_size = header[10]
    section_count = header[11]
    names_index = header[12]
    if machine != _ELF_MACHINE_ARM:
        msg = f"linked output machine is {machine}, expected ARM ({_ELF_MACHINE_ARM})"
        raise ValueError(msg)
    if section_entry_size != _ELF32_SECTION_HEADER_SIZE:
        msg = (
            f"ELF section entry size is {section_entry_size}, "
            f"expected {_ELF32_SECTION_HEADER_SIZE}"
        )
        raise ValueError(msg)
    table_end = section_offset + section_entry_size * section_count
    if table_end > len(elf) or names_index >= section_count:
        msg = "ELF section table is out of bounds"
        raise ValueError(msg)
    return section_offset, section_count, names_index


def _elf_section_name(names: bytes, offset: int) -> str:
    """Return the NUL-terminated ASCII section name at ``offset``.

    Args:
        names: The section-name string table.
        offset: A byte offset into ``names``.

    Returns:
        The decoded section name.

    Raises:
        ValueError: If ``offset`` is out of range or the name is unterminated.

    """
    if offset >= len(names):
        msg = "ELF section name offset is out of bounds"
        raise ValueError(msg)
    end = names.find(b"\0", offset)
    if end < 0:
        msg = "ELF section name is unterminated"
        raise ValueError(msg)
    return names[offset:end].decode("ascii")


def elf_sections(elf: bytes) -> tuple[list[ElfSection], list[str]]:
    """Extract allocated PROGBITS sections and any relocation section names.

    Args:
        elf: The full linked ELF image.

    Returns:
        The allocated PROGBITS sections and the names of any retained
        relocation sections.

    Raises:
        ValueError: If the ELF header, name table, or a section is malformed.

    """
    section_offset, section_count, names_index = _parse_elf_section_table(elf)
    raw_headers: list[tuple[int, ...]] = [
        struct.unpack_from(
            "<IIIIIIIIII",
            elf,
            section_offset + index * _ELF32_SECTION_HEADER_SIZE,
        )
        for index in range(section_count)
    ]
    names_header = raw_headers[names_index]
    names_offset, names_size = names_header[4], names_header[5]
    names = elf[names_offset : names_offset + names_size]
    if len(names) != names_size:
        msg = "ELF section-name table is out of bounds"
        raise ValueError(msg)

    allocated: list[ElfSection] = []
    relocations: list[str] = []
    for raw in raw_headers:
        name_offset, section_type, flags, address, offset, size = raw[:6]
        name = _elf_section_name(names, name_offset)
        if section_type in (4, 9) and size:
            relocations.append(name)
        if section_type != 1 or not flags & 0x2 or size == 0:
            continue
        data = elf[offset : offset + size]
        if len(data) != size:
            msg = f"ELF section {name} is out of file bounds"
            raise ValueError(msg)
        allocated.append(ElfSection(name=name, address=address, data=data))
    return allocated, relocations


def _validate_sections(sections: list[ElfSection]) -> None:
    """Check that the linked sections match the reviewed layout allowlist.

    Args:
        sections: Allocated sections parsed from the linked ELF.

    Raises:
        ValueError: If names are duplicated, the section set differs from the
            allowlist, a section is misplaced or oversized, or sections
            overlap.

    """
    by_name = {section.name: section for section in sections}
    if len(by_name) != len(sections):
        msg = "linked ELF contains duplicate allocated section names"
        raise ValueError(msg)
    expected = set(_SECTION_BOUNDS)
    actual = set(by_name)
    if actual != expected:
        msg = (
            "allocated section set mismatch: "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )
        raise ValueError(msg)
    occupied: list[tuple[int, int, str]] = []
    for name, (required_start, limit) in _SECTION_BOUNDS.items():
        section = by_name[name]
        end = section.address + len(section.data)
        if section.address != required_start or end > limit:
            msg = (
                f"{name} linked at 0x{section.address:08X}..0x{end:08X}, "
                f"required start 0x{required_start:08X} and limit 0x{limit:08X}"
            )
            raise ValueError(msg)
        occupied.append((section.address, end, name))
    occupied.sort()
    for before, after in pairwise(occupied):
        if before[1] > after[0]:
            msg = f"allocated sections overlap: {before[2]} and {after[2]}"
            raise ValueError(msg)


def _overlay(source: bytes, sections: list[ElfSection]) -> bytes:
    """Overlay the allocated sections onto ``source`` at their flat offsets.

    Args:
        source: The exact source flat firmware image.
        sections: Allocated sections to write, keyed by CPU address.

    Returns:
        A new flat image with each section written at its mapped offset.

    Raises:
        ValueError: If a section maps outside the flat image.

    """
    result = bytearray(source)
    for section in sections:
        offset = section.address - _CPU_IMAGE_BASE
        end = offset + len(section.data)
        if offset < 0 or end > len(result):
            msg = (
                f"{section.name} maps outside the flat image: "
                f"0x{section.address:08X}+0x{len(section.data):X}"
            )
            raise ValueError(msg)
        result[offset:end] = section.data
    return bytes(result)


def _section_report(
    sections: list[ElfSection], source: bytes
) -> list[dict[str, str | int]]:
    """Summarize each overlaid section against its source window.

    Args:
        sections: Allocated sections to report, in ascending address order.
        source: The source flat firmware image the sections overlay.

    Returns:
        One record per section with its address, flat offset, size, digests,
        and changed-byte count.

    """
    report: list[dict[str, str | int]] = []
    for section in sorted(sections, key=lambda item: item.address):
        offset = section.address - _CPU_IMAGE_BASE
        before = source[offset : offset + len(section.data)]
        report.append(
            {
                "name": section.name,
                "address": f"0x{section.address:08X}",
                "flat_offset": f"0x{offset:06X}",
                "size": len(section.data),
                "sha256": _sha256(section.data),
                "source_window_sha256": _sha256(before),
                "changed_bytes": sum(
                    left != right
                    for left, right in zip(before, section.data, strict=True)
                ),
            }
        )
    return report


def _read_validated_source(path: Path) -> bytes:
    """Read the source image and confirm its exact size and SHA-256.

    Args:
        path: The normal-gm-nor-read flat firmware image.

    Returns:
        The image bytes.

    Raises:
        ValueError: If the image is the wrong size or has an unexpected hash.

    """
    source = path.read_bytes()
    if len(source) != _SOURCE_SIZE:
        msg = f"source image is 0x{len(source):X} bytes, expected 0x{_SOURCE_SIZE:X}"
        raise ValueError(msg)
    source_hash = _sha256(source)
    if source_hash != _SOURCE_SHA256:
        msg = f"source SHA-256 is {source_hash}, expected {_SOURCE_SHA256}"
        raise ValueError(msg)
    return source


def _validate_dual_build(
    object_a: Path,
    object_b: Path,
    elf_a: Path,
    elf_b: Path,
) -> tuple[bytes, bytes, list[ElfSection]]:
    """Confirm two independent builds are identical and parse their sections.

    Args:
        object_a: First build's assembled object file.
        object_b: Second build's assembled object file.
        elf_a: First build's linked ELF.
        elf_b: Second build's linked ELF.

    Returns:
        The first object's bytes, the first ELF's bytes, and the allocated
        sections parsed from the first ELF.

    Raises:
        ValueError: If the objects or ELFs differ, a relocation section
            survives, the parsed section sets differ, or layout validation
            fails.

    """
    object_a_data = object_a.read_bytes()
    object_b_data = object_b.read_bytes()
    elf_a_data = elf_a.read_bytes()
    elf_b_data = elf_b.read_bytes()
    if object_a_data != object_b_data:
        msg = "independent assembly objects are not byte-identical"
        raise ValueError(msg)
    if elf_a_data != elf_b_data:
        msg = "independent linked ELFs are not byte-identical"
        raise ValueError(msg)
    sections_a, relocations_a = elf_sections(elf_a_data)
    sections_b, relocations_b = elf_sections(elf_b_data)
    if relocations_a or relocations_b:
        msg = (
            f"linked ELF retains relocation sections: {relocations_a or relocations_b}"
        )
        raise ValueError(msg)
    if sections_a != sections_b:
        msg = "independent ELFs have different allocated sections"
        raise ValueError(msg)
    _validate_sections(sections_a)
    return object_a_data, elf_a_data, sections_a


def _write_optional_disassembly(
    objdump_arg: str | None, elf: Path, output: Path
) -> None:
    """Write ``elf``'s disassembly to ``output`` when llvm-objdump is available.

    Args:
        objdump_arg: An explicit llvm-objdump path, or ``None`` to search.
        elf: The linked ELF to disassemble.
        output: The directory that receives ``disassembly.txt``.

    """
    try:
        objdump = resolve_executable(
            objdump_arg,
            (
                "/opt/homebrew/opt/llvm/bin/llvm-objdump",
                "/opt/homebrew/bin/llvm-objdump",
                "llvm-objdump",
            ),
        )
    except ValueError:
        return
    # ``objdump`` is a resolved, validated tool run with a fixed flag list and
    # no shell; the only variable is the ELF path this tool just produced.
    disassembly = subprocess.run(  # noqa: S603
        [objdump, "-d", "--no-show-raw-insn", str(elf)],
        check=True,
        capture_output=True,
        text=True,
    )
    _ = (output / "disassembly.txt").write_text(disassembly.stdout, encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    """Parse the command-line arguments for the overlay builder."""
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "source",
        type=Path,
        help="exact normal-gm-nor-read 0x280000-byte flat firmware image",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="new empty directory for build products and audit logs",
    )
    _ = parser.add_argument("--clang", help="ARM-capable clang executable")
    _ = parser.add_argument("--linker", help="ld.lld executable")
    _ = parser.add_argument("--objdump", help="optional llvm-objdump executable")
    return parser.parse_args()


def main() -> int:
    """Build the USB-storage recovery overlay and write its audit artifacts.

    Returns:
        ``0`` on success.

    Raises:
        ValueError: If the source image or the linked ELF fails validation.
        RuntimeError: If clang or the linker exits non-zero.

    """
    args = _parse_args()
    if not args.source.is_file():
        msg = f"source image not found: {args.source}"
        raise ValueError(msg)
    if args.output.exists():
        msg = f"output path already exists: {args.output}"
        raise ValueError(msg)
    args.output.mkdir(parents=True)

    source = _read_validated_source(args.source)
    source_hash = _sha256(source)

    clang = resolve_executable(args.clang, ("/usr/bin/clang", "clang"))
    linker = resolve_executable(
        args.linker,
        ("/opt/homebrew/bin/ld.lld", "/opt/homebrew/opt/llvm/bin/ld.lld", "ld.lld"),
    )
    log: list[str] = []
    object_a, elf_a = _build_once(
        args.output / "build-a", clang=clang, linker=linker, log=log
    )
    object_b, elf_b = _build_once(
        args.output / "build-b", clang=clang, linker=linker, log=log
    )
    object_a_data, elf_a_data, sections = _validate_dual_build(
        object_a, object_b, elf_a, elf_b
    )

    result = _overlay(source, sections)
    result_path = args.output / "usb_storage_recovery.bin"
    result_path.write_bytes(result)
    changed_offsets = [
        offset
        for offset, (before, after) in enumerate(zip(source, result, strict=True))
        if before != after
    ]
    if not changed_offsets:
        msg = "linked overlay did not change the source firmware"
        raise ValueError(msg)

    report = {
        "source": str(args.source.resolve()),
        "assembly": str(_ASSEMBLY),
        "linker_script": str(_LINKER_SCRIPT),
        "source_sha256": source_hash,
        "assembly_sha256": _sha256(_ASSEMBLY.read_bytes()),
        "linker_script_sha256": _sha256(_LINKER_SCRIPT.read_bytes()),
        "object_sha256": _sha256(object_a_data),
        "elf_sha256": _sha256(elf_a_data),
        "result_sha256": _sha256(result),
        "result_firmware_checksum": f"0x{firmware_checksum(result):04X}",
        "change_count": len(changed_offsets),
        "first_changed_offset": f"0x{changed_offsets[0]:06X}",
        "last_changed_offset": f"0x{changed_offsets[-1]:06X}",
        "sections": _section_report(sections, source),
    }
    (args.output / "audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (args.output / "build.log").write_text("\n".join(log) + "\n", encoding="utf-8")

    _write_optional_disassembly(args.objdump, elf_a, args.output)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
