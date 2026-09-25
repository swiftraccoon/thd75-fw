#!/usr/bin/env python3
"""Reproducibly build and audit the TH-D75 closed-loop automation overlay.

The source must be the exact, hash-pinned V1.03 USB-storage recovery flat
firmware image.  The assembly is linked at final CPU addresses, built twice,
and accepted only when both objects and ELFs are byte-identical.  Linked ABI
symbols, Thumb entry points, hook branch destinations, framebuffer geometry,
and both virtual apertures are checked independently.  Only the three
explicitly allowlisted allocated sections and the exact 16-byte firmware
identity field are overlaid; ELF gaps are never interpreted as firmware bytes.

In addition to the rebuilt flat image and JSON audit, the output directory
contains a complete fail-closed patch-manifest draft.  Artifact hashes that
exist only after KEX/updater repacking are intentionally absent from that draft
until the normal deterministic repack loop supplies them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import zlib
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypedDict

from build_usb_storage_recovery import (
    ElfSection,
    elf_sections,
    firmware_checksum,
    resolve_executable,
    run_logged,
)

if TYPE_CHECKING:
    from unicorn import Uc

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ASSEMBLY = _REPO_ROOT / "scripts" / "radio_automation.s"
_LINKER_SCRIPT = _REPO_ROOT / "scripts" / "radio_automation.ld"
_CPU_IMAGE_BASE = 0xC000_0000
_SOURCE_SIZE = 0x28_0000
_SOURCE_SHA256 = "239128bca8f608398dc23865c336bd48a00484ea598202a000fd9f5647aa92a6"
_SOURCE_UPDATER_SHA256 = (
    "28e9ae17ab85e7831d04bb7a520e9e735081ea78c22e64e57daafa50f7bce23d"
)
_FIRMWARE_IDENTITY_OFFSET = 0xA0
_SOURCE_FIRMWARE_IDENTITY = b"V1.03.000      \0"
_RESULT_FIRMWARE_IDENTITY = b"V1.03.AZM      \0"

# ELF32 little-endian layout values (System V ABI, ELF chapter).
_ELF32_HEADER_SIZE: Final = 52
_ELF32_SECTION_HEADER_SIZE: Final = 40
_ELF_SHT_SYMTAB: Final = 2
_ELF32_SYMBOL_ENTRY_SIZE: Final = 16

# ARMv5 Thumb BL (branch-with-link) instruction encoding.  The high and low
# halfwords each carry a five-bit opcode in their top bits.
_THUMB_BL_BYTE_LENGTH: Final = 4
_THUMB_BL_OPCODE_MASK: Final = 0xF800
_THUMB_BL_HIGH_OPCODE: Final = 0xF000
_THUMB_BL_LOW_OPCODE: Final = 0xF800

# The reviewed snapshot cave ends here; the raw and RLE buffers must fit inside.
_SNAPSHOT_CAVE_END: Final = 0xC01C_A480

# Byte value the reserved runtime caves are padded with in the source image.
_FF_FILL_BYTE: Final = 0xFF

# Changed bytes no more than this far apart join one manifest context cluster.
_CLUSTER_GAP_BYTES: Final = 64

# RLE3 run-length encoding audit expectations for the emulated self-test.
_RLE_MAX_RUN_LENGTH: Final = 255
_SOLID_FRAME_RLE_LENGTH: Final = 510
_BOUNDARY_FRAME_RLE_LENGTH: Final = 513
_UNSTABLE_FRAME_COPIES: Final = 6

_SECTION_BOUNDS: dict[str, tuple[int, int]] = {
    ".gm_adapter_call": (0xC002_EC04, 0xC002_EC08),
    ".gm_read_call": (0xC006_F8AC, 0xC006_F8B0),
    ".automation_runtime": (0xC019_D280, 0xC019_E000),
}

_EXACT_SOURCE_WINDOWS: tuple[tuple[int, bytes], ...] = (
    (0x02_EC04, bytes.fromhex("40 F0 0F FE")),
    (0x06_F8AC, bytes.fromhex("A1 F7 8D FD")),
)

# Loaded-image storage reserved by the runtime.  The second copy is private;
# metadata plus the first copy are exposed through the raw virtual GM aperture.
# After a stable comparison, the second copy is reused as bounded RLE output
# and exposed through a second, non-overlapping virtual aperture.
_RUNTIME_FF_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x19_D280, 0x19_E000, "automation code cave"),
    (0x1A_0000, 0x1A_0100, "automation metadata"),
    (0x1A_0100, 0x1B_5280, "published stable framebuffer"),
    (0x1B_5300, 0x1C_A480, "comparison/RLE framebuffer"),
)

# The linked ELF retains absolute symbols for every reviewed ABI constant.
# Checking them here makes layout drift fail closed even when the assembly and
# linker script still happen to produce syntactically valid machine code.
_EXPECTED_SYMBOLS: dict[str, int] = {
    "AUTOMATION_MAGIC": 0x4135_3744,
    "AUTOMATION_ABI_VERSION": 3,
    "AUTOMATION_FEATURES": 0x7F,
    "AUTOMATION_MAX_KEY": 0x18,
    "AUTOMATION_MAX_PHASE": 2,
    "AUTOMATION_META": 0xC01A_0000,
    "AUTOMATION_SNAPSHOT_A": 0xC01A_0100,
    "AUTOMATION_SNAPSHOT_B": 0xC01B_5300,
    "AUTOMATION_VIRTUAL_RAW_BASE": 0xC0F0_0000,
    "AUTOMATION_VIRTUAL_RAW_END": 0xC0F1_5280,
    "AUTOMATION_VIRTUAL_RLE_BASE": 0xC0F1_5300,
    "AUTOMATION_VIRTUAL_RLE_END": 0xC0F2_A480,
    "AUTOMATION_RLE_OFFSET": 0x0001_5300,
    "AUTOMATION_RLE_MAGIC": 0x3345_4C52,
    "FRAMEBUFFER": 0xC234_9A40,
    "FRAME_WIDTH": 240,
    "FRAME_HEIGHT": 180,
    "FRAME_STRIDE": 480,
    "FRAME_BYTES": 0x15180,
    "FRAME_WORDS": 0x5460,
    "PIXEL_FORMAT_RGB565LE": 0x3536_3552,
    "MAX_CAPTURE_ATTEMPTS": 3,
    "META_MAGIC": 0x00,
    "META_ABI_VERSION": 0x04,
    "META_SEQUENCE": 0x08,
    "META_FEATURES": 0x0C,
    "META_WIDTH": 0x10,
    "META_HEIGHT": 0x14,
    "META_STRIDE": 0x18,
    "META_PIXEL_FORMAT": 0x1C,
    "META_PIXEL_LENGTH": 0x20,
    "META_PIXEL_OFFSET": 0x24,
    "META_GENERATION": 0x28,
    "META_CAPTURE_RESULT": 0x2C,
    "META_CRC32": 0x30,
    "META_CAPTURE_ATTEMPTS": 0x34,
    "META_COMMAND_COUNT": 0x38,
    "META_LAST_COMMAND": 0x3C,
    "META_LAST_HOST_SEQUENCE": 0x40,
    "META_LAST_KEY": 0x44,
    "META_LAST_PHASE": 0x48,
    "META_LAST_KEY_RESULT": 0x4C,
    "META_FRAMEBUFFER_ADDRESS": 0x50,
    "META_SNAPSHOT_ADDRESS": 0x54,
    "META_LIMITS": 0x58,
    "META_RLE_MAGIC": 0x5C,
    "META_RLE_OFFSET": 0x60,
    "META_RLE_LENGTH": 0x64,
    "META_ROUTE_DIGITS": 0x68,
    "META_ROUTE_GUARD_ATTEMPTS": 0x6C,
    "META_ROUTE_COMPLETED_TAPS": 0x70,
    "META_ROUTE_EVENT_MASK": 0x74,
    "META_TRAILING_MAGIC": 0xFC,
    "COMMAND_QUERY": 0,
    "COMMAND_SNAPSHOT": 1,
    "COMMAND_KEY": 2,
    "COMMAND_GUARDED_KEY": 3,
    "COMMAND_GUARDED_ROUTE": 4,
    "RESULT_OK": 0,
    "RESULT_UNSTABLE": 1,
    "RESULT_CONTEXT_CHANGED": 2,
    "RESULT_BUSY": 0xFFFF_FFFF,
    "svc_9r_read_handler": 0xC006_F827,
    "cat_parse_hex_param": 0xC006_DF39,
    "cat_reply_hex_echo": 0xC006_EE67,
    "cat_error_reply": 0xC002_FA05,
    "memcpy_n": 0xC001_13CB,
    "input_dispatch": 0xC005_6319,
}
_RUNTIME_FUNCTIONS = (
    "automation_dispatch",
    "automation_metadata_prepare",
    "automation_metadata_begin",
    "automation_metadata_end",
    "automation_query_invalidate",
    "automation_key_event",
    "automation_guarded_key_event",
    "automation_guard_snapshot",
    "automation_guarded_route",
    "automation_capture",
    "automation_crc32",
    "automation_rle_encode",
    "automation_memory_copy",
)

# External functions the runtime calls; the emulator stubs each with ``bx lr``.
_EXTERNAL_FUNCTIONS = (
    "svc_9r_read_handler",
    "cat_parse_hex_param",
    "cat_reply_hex_echo",
    "cat_error_reply",
    "memcpy_n",
    "input_dispatch",
)


class _ReplyRecord(TypedDict):
    """One captured ``cat_reply_hex_echo`` reply."""

    echo: bytes
    data: bytes


class _MemcpyRecord(TypedDict):
    """One captured ``memcpy_n`` call."""

    destination: int
    source: int
    length: int


class _EventLog(TypedDict):
    """Side effects one emulated command produced, captured by the code hook."""

    replies: list[_ReplyRecord]
    errors: int
    inputs: list[tuple[int, int]]
    service: list[tuple[bytes, int]]
    memcpy: list[_MemcpyRecord]
    copy_data: bool
    unstable_frame: bool
    frame_copy_count: int
    change_frame_after_inputs: int | None
    stopped: bool
    stack_mod_8: list[int]


def _sha256(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _read_u32(data: bytes, offset: int) -> int:
    """Return the little-endian unsigned 32-bit word at ``offset`` in ``data``."""
    fields: tuple[int, ...] = struct.unpack_from("<I", data, offset)
    return fields[0]


def _new_event_log() -> _EventLog:
    """Return a fresh, empty event log for one emulated machine."""
    return {
        "replies": [],
        "errors": 0,
        "inputs": [],
        "service": [],
        "memcpy": [],
        "copy_data": True,
        "unstable_frame": False,
        "frame_copy_count": 0,
        "change_frame_after_inputs": None,
        "stopped": False,
        "stack_mod_8": [],
    }


def _build_once(
    directory: Path,
    *,
    clang: str,
    linker: str,
    log: list[str],
) -> tuple[Path, Path]:
    """Assemble and link the automation overlay once into ``directory``.

    Args:
        directory: A new directory to hold this build's object and ELF.
        clang: The ARM-capable clang executable.
        linker: The ld.lld executable.
        log: A running build log for the compile and link commands.

    Returns:
        The assembled object path and the linked ELF path.

    """
    directory.mkdir()
    object_path = directory / "radio_automation.o"
    elf_path = directory / "radio_automation.elf"
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


def _validate_source(source: bytes) -> None:
    """Confirm the source image's identity, patch hooks, and reserved caves.

    Args:
        source: The exact hash-pinned USB-storage recovery flat image.

    Raises:
        ValueError: If the firmware identity, a hook window, or a reserved
            ``0xFF`` cave does not match expectations.

    """
    identity_end = _FIRMWARE_IDENTITY_OFFSET + len(_SOURCE_FIRMWARE_IDENTITY)
    identity = source[_FIRMWARE_IDENTITY_OFFSET:identity_end]
    if identity != _SOURCE_FIRMWARE_IDENTITY:
        msg = (
            "source firmware identity mismatch at "
            f"0x{_FIRMWARE_IDENTITY_OFFSET:06X}: "
            f"{identity!r} != {_SOURCE_FIRMWARE_IDENTITY!r}"
        )
        raise ValueError(msg)
    for offset, expected in _EXACT_SOURCE_WINDOWS:
        actual = source[offset : offset + len(expected)]
        if actual != expected:
            msg = (
                f"source hook mismatch at 0x{offset:06X}: "
                f"{actual.hex(' ').upper()} != {expected.hex(' ').upper()}"
            )
            raise ValueError(msg)
    for start, end, label in _RUNTIME_FF_RANGES:
        window = source[start:end]
        if len(window) != end - start or any(byte != _FF_FILL_BYTE for byte in window):
            first = next(
                (
                    start + index
                    for index, byte in enumerate(window)
                    if byte != _FF_FILL_BYTE
                ),
                start + len(window),
            )
            msg = f"{label} is not an exact FF cave at 0x{first:06X}"
            raise ValueError(msg)


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
            f"missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
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


def _parse_elf_symbol_header(elf: bytes) -> tuple[int, int]:
    """Validate an ELF32 little-endian header and locate its section table.

    Args:
        elf: The full linked ELF image.

    Returns:
        The section-header table's byte offset and the number of section
        headers.

    Raises:
        ValueError: If the image is not little-endian ELF32 or its section
            table lies outside the image.

    """
    if (
        len(elf) < _ELF32_HEADER_SIZE
        or elf[:4] != b"\x7fELF"
        or elf[4:6] != b"\x01\x01"
    ):
        msg = "linked output is not ELF32 little-endian"
        raise ValueError(msg)
    header: tuple[int, ...] = struct.unpack_from("<HHIIIIIHHHHHH", elf, 16)
    section_offset = header[5]
    section_entry_size = header[10]
    section_count = header[11]
    if section_entry_size != _ELF32_SECTION_HEADER_SIZE:
        msg = f"ELF section entry size is {section_entry_size}, expected 40"
        raise ValueError(msg)
    table_end = section_offset + section_entry_size * section_count
    if table_end > len(elf):
        msg = "ELF section table is out of bounds"
        raise ValueError(msg)
    return section_offset, section_count


def _collect_symbols(
    symbols: bytes,
    strings: bytes,
    wanted: set[str],
    found: dict[str, int],
) -> None:
    """Record the value of each wanted symbol found in one symbol table.

    Args:
        symbols: The raw symbol-table bytes.
        strings: The associated string table.
        wanted: Symbol names of interest.
        found: Accumulator mapping each located name to its value.

    Raises:
        ValueError: If a symbol name is out of bounds, unterminated, or a
            wanted name is defined more than once.

    """
    for symbol_offset in range(0, len(symbols), _ELF32_SYMBOL_ENTRY_SIZE):
        pair: tuple[int, int] = struct.unpack_from("<II", symbols, symbol_offset)
        name_offset, value = pair
        if name_offset >= len(strings):
            msg = "ELF symbol name is out of bounds"
            raise ValueError(msg)
        name_end = strings.find(b"\0", name_offset)
        if name_end < 0:
            msg = "ELF symbol name is unterminated"
            raise ValueError(msg)
        name = strings[name_offset:name_end].decode("ascii")
        if name not in wanted:
            continue
        if name in found:
            msg = f"linked ELF contains duplicate symbol {name}"
            raise ValueError(msg)
        found[name] = value


def _read_symbol_table(
    elf: bytes,
    section: tuple[int, ...],
    sections: list[tuple[int, ...]],
    wanted: set[str],
    found: dict[str, int],
) -> None:
    """Read one SHT_SYMTAB section's wanted symbols into ``found``.

    Args:
        elf: The full linked ELF image.
        section: The symbol-table section header.
        sections: All section headers, used to locate the string table.
        wanted: Symbol names of interest.
        found: Accumulator mapping each located name to its value.

    Raises:
        ValueError: If the symbol-table metadata or its ranges are invalid.

    """
    offset, size, strings_index, entry_size = (
        section[4],
        section[5],
        section[6],
        section[9],
    )
    if entry_size != _ELF32_SYMBOL_ENTRY_SIZE or strings_index >= len(sections):
        msg = "ELF symbol table has invalid metadata"
        raise ValueError(msg)
    strings_header = sections[strings_index]
    strings_offset, strings_size = strings_header[4], strings_header[5]
    strings = elf[strings_offset : strings_offset + strings_size]
    symbols = elf[offset : offset + size]
    if (
        len(strings) != strings_size
        or len(symbols) != size
        or size % _ELF32_SYMBOL_ENTRY_SIZE
    ):
        msg = "ELF symbol or string table is out of bounds"
        raise ValueError(msg)
    _collect_symbols(symbols, strings, wanted, found)


def _elf_named_symbols(elf: bytes, wanted: set[str]) -> dict[str, int]:
    """Read selected ELF32 symbol values without trusting an external tool.

    Args:
        elf: The full linked ELF image.
        wanted: Symbol names to resolve.

    Returns:
        A mapping from each wanted symbol name to its value.

    Raises:
        ValueError: If the ELF is malformed or a wanted symbol is missing.

    """
    section_offset, section_count = _parse_elf_symbol_header(elf)
    sections: list[tuple[int, ...]] = [
        struct.unpack_from(
            "<IIIIIIIIII",
            elf,
            section_offset + index * _ELF32_SECTION_HEADER_SIZE,
        )
        for index in range(section_count)
    ]

    found: dict[str, int] = {}
    for section in sections:
        if section[1] != _ELF_SHT_SYMTAB:
            continue
        _read_symbol_table(elf, section, sections, wanted, found)

    missing = wanted - set(found)
    if missing:
        msg = f"linked ELF is missing symbols: {sorted(missing)}"
        raise ValueError(msg)
    return found


def _thumb1_bl_target(address: int, instruction: bytes) -> int:
    """Decode one ARMv5 Thumb BL and return its even destination address.

    Args:
        address: The instruction's own address.
        instruction: The four raw BL bytes.

    Returns:
        The branch target address with its low bit cleared.

    Raises:
        ValueError: If ``instruction`` is not a four-byte ARMv5 Thumb BL, or
            its displacement is out of range.

    """
    if len(instruction) != _THUMB_BL_BYTE_LENGTH:
        msg = "Thumb BL must be exactly four bytes"
        raise ValueError(msg)
    halves: tuple[int, int] = struct.unpack("<HH", instruction)
    high, low = halves
    if (
        high & _THUMB_BL_OPCODE_MASK != _THUMB_BL_HIGH_OPCODE
        or low & _THUMB_BL_OPCODE_MASK != _THUMB_BL_LOW_OPCODE
    ):
        msg = (
            f"0x{address:08X} is not an ARMv5 Thumb BL: {instruction.hex(' ').upper()}"
        )
        raise ValueError(msg)
    displacement = ((high & 0x7FF) << 12) | ((low & 0x7FF) << 1)
    if displacement & (1 << 22):
        displacement -= 1 << 23
    if not -(1 << 22) <= displacement < (1 << 22):
        msg = "Thumb BL displacement is out of range"
        raise ValueError(msg)
    return (address + 4 + displacement) & 0xFFFF_FFFF


def _validate_abi_symbols(symbols: dict[str, int]) -> None:
    """Confirm every reviewed ABI constant has its expected value.

    Args:
        symbols: The resolved symbol table.

    Raises:
        ValueError: If any expected ABI symbol has an unexpected value.

    """
    for name, expected in _EXPECTED_SYMBOLS.items():
        actual = symbols[name]
        if actual != expected:
            msg = f"ABI symbol {name} is 0x{actual:08X}, expected 0x{expected:08X}"
            raise ValueError(msg)


def _validate_runtime_functions(
    sections: list[ElfSection],
    symbols: dict[str, int],
) -> None:
    """Confirm every runtime function is Thumb-marked and inside the cave.

    Args:
        sections: Allocated sections, providing the runtime section bounds.
        symbols: The resolved symbol table.

    Raises:
        ValueError: If a runtime function is not Thumb, lies outside the
            runtime section, or ``automation_dispatch`` is not its entry point.

    """
    by_name = {section.name: section for section in sections}
    runtime = by_name[".automation_runtime"]
    runtime_end = runtime.address + len(runtime.data)
    for name in _RUNTIME_FUNCTIONS:
        value = symbols[name]
        if not value & 1:
            msg = f"runtime function {name} is not marked Thumb"
            raise ValueError(msg)
        address = value & ~1
        if not runtime.address <= address < runtime_end:
            msg = f"runtime function {name} at 0x{address:08X} is outside runtime"
            raise ValueError(msg)
    if symbols["automation_dispatch"] != runtime.address | 1:
        msg = "automation_dispatch is not the runtime entry point"
        raise ValueError(msg)


def _validate_layout(symbols: dict[str, int]) -> None:
    """Confirm the metadata, buffer, geometry, and aperture layout is coherent.

    Args:
        symbols: The resolved symbol table.

    Raises:
        ValueError: If the physical layout, framebuffer geometry, or virtual
            apertures are inconsistent or overlap.

    """
    meta = symbols["AUTOMATION_META"]
    frame_bytes = symbols["FRAME_BYTES"]
    raw = symbols["AUTOMATION_SNAPSHOT_A"]
    rle = symbols["AUTOMATION_SNAPSHOT_B"]
    if raw != meta + 0x100 or rle != meta + symbols["AUTOMATION_RLE_OFFSET"]:
        msg = "metadata/raw/RLE physical layout is inconsistent"
        raise ValueError(msg)
    if raw + frame_bytes > rle or rle + frame_bytes != _SNAPSHOT_CAVE_END:
        msg = "raw and RLE buffers overlap or exceed the reviewed cave"
        raise ValueError(msg)
    if (
        symbols["FRAME_WIDTH"] * 2 != symbols["FRAME_STRIDE"]
        or symbols["FRAME_STRIDE"] * symbols["FRAME_HEIGHT"] != frame_bytes
        or symbols["FRAME_WORDS"] * 4 != frame_bytes
    ):
        msg = "framebuffer geometry is internally inconsistent"
        raise ValueError(msg)
    if (
        symbols["AUTOMATION_VIRTUAL_RAW_END"] - symbols["AUTOMATION_VIRTUAL_RAW_BASE"]
        != 0x100 + frame_bytes
        or symbols["AUTOMATION_VIRTUAL_RLE_END"]
        - symbols["AUTOMATION_VIRTUAL_RLE_BASE"]
        != frame_bytes
    ):
        msg = "virtual aperture sizes are inconsistent"
        raise ValueError(msg)
    if not (
        symbols["AUTOMATION_VIRTUAL_RAW_END"] <= symbols["AUTOMATION_VIRTUAL_RLE_BASE"]
    ):
        msg = "raw and RLE virtual apertures overlap"
        raise ValueError(msg)


def _validate_hooks(
    sections: list[ElfSection],
    symbols: dict[str, int],
) -> None:
    """Confirm each patched hook's BL branches to its expected runtime target.

    Args:
        sections: Allocated sections, keyed by name to find each hook.
        symbols: The resolved symbol table.

    Raises:
        ValueError: If a hook's BL does not target its expected function.

    """
    by_name = {section.name: section for section in sections}
    hooks = (
        (
            ".gm_adapter_call",
            "automation_dispatch",
        ),
        (
            ".gm_read_call",
            "automation_memory_copy",
        ),
    )
    for section_name, target_name in hooks:
        section = by_name[section_name]
        target = _thumb1_bl_target(section.address, section.data)
        expected = symbols[target_name] & ~1
        if target != expected:
            msg = (
                f"{section_name} BL targets 0x{target:08X}, "
                f"expected {target_name} at 0x{expected:08X}"
            )
            raise ValueError(msg)


def _validate_contract(
    sections: list[ElfSection],
    symbols: dict[str, int],
) -> None:
    """Check the linked overlay against the full reviewed ABI contract.

    Args:
        sections: Allocated sections parsed from the linked ELF.
        symbols: The resolved symbol table.

    Raises:
        ValueError: If any ABI symbol, runtime function, layout invariant, or
            hook branch target is wrong.

    """
    _validate_abi_symbols(symbols)
    _validate_runtime_functions(sections, symbols)
    _validate_layout(symbols)
    _validate_hooks(sections, symbols)


class _AzimuthEmulator:
    """Emulate the linked Thumb overlay and verify its external-call ABI.

    Unicorn is intentionally an opt-in audit dependency rather than a package
    runtime dependency.  Constructing this emulator makes its absence fatal;
    ``run`` exercises every vector and records the evidence for ``audit.json``.
    """

    def __init__(self, result: bytes, symbols: dict[str, int]) -> None:
        """Load Unicorn, map the linked image, and derive the emulation layout.

        Args:
            result: The linked flat firmware image.
            symbols: The resolved ABI symbol table.

        Raises:
            ValueError: If the optional ``unicorn`` package is unavailable.

        """
        super().__init__()
        try:
            import unicorn  # noqa: PLC0415 - optional audit dependency, imported on demand
            from unicorn import arm_const  # noqa: PLC0415 - optional audit dependency
        except ImportError as error:
            msg = "--emulate requires the optional 'unicorn' package"
            raise ValueError(msg) from error
        self._unicorn = unicorn
        self._arm = arm_const
        self._result = result
        self._symbols = symbols

        self._page_size = 0x1000
        self._runtime_page = 0xC019_D000
        self._data_page = symbols["AUTOMATION_META"]
        self._raw_address = symbols["AUTOMATION_SNAPSHOT_A"]
        self._rle_address = symbols["AUTOMATION_SNAPSHOT_B"]
        self._framebuffer = symbols["FRAMEBUFFER"]
        self._frame_bytes = symbols["FRAME_BYTES"]
        self._stack_page = 0x2000_0000
        self._io_page = 0x3000_0000
        self._sentinel = 0x0010_0000
        self._request_address = self._io_page

        self._external = {name: symbols[name] & ~1 for name in _EXTERNAL_FUNCTIONS}
        self._register_patterns = {
            arm_const.UC_ARM_REG_R4: 0x4444_4444,
            arm_const.UC_ARM_REG_R5: 0x5555_5555,
            arm_const.UC_ARM_REG_R6: 0x6666_6666,
            arm_const.UC_ARM_REG_R7: 0x7777_7777,
        }
        self._expected_info = b"D75A" + bytes(
            [
                symbols["AUTOMATION_ABI_VERSION"],
                symbols["AUTOMATION_FEATURES"],
                symbols["AUTOMATION_MAX_KEY"],
                symbols["AUTOMATION_MAX_PHASE"],
            ]
        )
        self._query_request = b"GM A000000\r"
        self._route_request = b"GM R980,A1\r"
        self._packed_route = 0x0030_3839
        self._route_inputs = [
            (0x13, 0),
            (0x13, 1),
            (0x12, 0),
            (0x12, 1),
            (0x0A, 0),
            (0x0A, 1),
        ]
        self._solid = b"\x34\x12" * (self._frame_bytes // 2)
        self._alternating = struct.pack(
            f"<{self._frame_bytes // 2}H",
            *(index & 1 for index in range(self._frame_bytes // 2)),
        )
        self._active_events: _EventLog = _new_event_log()

    def _map_size(self, start: int, end: int) -> tuple[int, int]:
        """Return the page-aligned start and byte size covering ``start..end``."""
        aligned_start = start & ~(self._page_size - 1)
        aligned_end = (end + self._page_size - 1) & ~(self._page_size - 1)
        return aligned_start, aligned_end - aligned_start

    def _read_register(self, machine: Uc, register: int) -> int:
        """Return ``register`` from ``machine`` masked to 32 bits."""
        return int(machine.reg_read(register)) & 0xFFFF_FFFF

    def _flip_framebuffer_byte(self, current: Uc) -> None:
        """Toggle the low bit of the framebuffer's first byte to force a change."""
        first = bytes(current.mem_read(self._framebuffer, 1))[0] ^ 1
        current.mem_write(self._framebuffer, bytes((first,)))

    def _handle_memcpy(
        self, current: Uc, events: _EventLog, r0: int, r1: int, r2: int
    ) -> None:
        """Emulate a ``memcpy_n`` call, optionally perturbing an unstable frame.

        Args:
            current: The executing emulator.
            events: The active event log.
            r0: Destination address.
            r1: Source address.
            r2: Byte length.

        """
        events["memcpy"].append({"destination": r0, "source": r1, "length": r2})
        if events["copy_data"]:
            current.mem_write(r0, bytes(current.mem_read(r1, r2)))
            if (
                events["unstable_frame"]
                and r1 == self._framebuffer
                and r2 == self._frame_bytes
            ):
                self._flip_framebuffer_byte(current)
                events["frame_copy_count"] += 1
        current.reg_write(self._arm.UC_ARM_REG_R0, r0)

    def _handle_parse_hex(self, current: Uc, r0: int, r1: int, r2: int) -> None:
        """Emulate ``cat_parse_hex_param`` over the request bytes at ``r1``.

        Args:
            current: The executing emulator.
            r0: Output pointer for the parsed value.
            r1: Encoded-digit source pointer.
            r2: Encoded-digit length.

        """
        encoded = bytes(current.mem_read(r1, r2))
        valid = bool(encoded) and all(
            byte in b"0123456789abcdefABCDEF" for byte in encoded
        )
        value = int(encoded, 16) if valid else 0xFFFF_FFFF
        current.mem_write(r0, struct.pack("<I", value))
        current.reg_write(self._arm.UC_ARM_REG_R0, 1 if valid else 0)

    def _dispatch_external(
        self,
        current: Uc,
        events: _EventLog,
        address: int,
        registers: tuple[int, int, int],
    ) -> None:
        """Route one stubbed external call to its emulated behavior.

        Args:
            current: The executing emulator.
            events: The active event log.
            address: The stub address that was reached.
            registers: The R0, R1, and R2 argument values.

        """
        r0, r1, r2 = registers
        external = self._external
        if address == external["memcpy_n"]:
            self._handle_memcpy(current, events, r0, r1, r2)
        elif address == external["cat_parse_hex_param"]:
            self._handle_parse_hex(current, r0, r1, r2)
        elif address == external["cat_reply_hex_echo"]:
            events["replies"].append(
                {
                    "echo": bytes(current.mem_read(r0, 10)),
                    "data": bytes(current.mem_read(r1, r2)),
                }
            )
        elif address == external["cat_error_reply"]:
            events["errors"] += 1
        elif address == external["input_dispatch"]:
            events["inputs"].append((r0, r1))
            if events["change_frame_after_inputs"] == len(events["inputs"]):
                self._flip_framebuffer_byte(current)
        elif address == external["svc_9r_read_handler"]:
            events["service"].append((bytes(current.mem_read(r0, r1)), r1))

    def _hook_code(
        self,
        current: Uc,
        address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        """Unicorn code hook: stop at the sentinel or emulate external calls.

        Args:
            current: The executing emulator.
            address: The address about to execute.
            _size: The instruction size (unused).
            _user_data: The hook's user data (unused).

        """
        events = self._active_events
        if address == self._sentinel:
            events["stopped"] = True
            current.emu_stop()
            return
        if address not in self._external.values():
            return
        events["stack_mod_8"].append(
            self._read_register(current, self._arm.UC_ARM_REG_SP) & 7
        )
        r0 = self._read_register(current, self._arm.UC_ARM_REG_R0)
        r1 = self._read_register(current, self._arm.UC_ARM_REG_R1)
        r2 = self._read_register(current, self._arm.UC_ARM_REG_R2)
        self._dispatch_external(current, events, address, (r0, r1, r2))

    def _new_machine(self) -> tuple[Uc, _EventLog]:
        """Create a fresh emulator with the linked image, memory, and hook.

        Returns:
            The configured emulator and its event log.

        """
        machine = self._unicorn.Uc(
            self._unicorn.UC_ARCH_ARM, self._unicorn.UC_MODE_THUMB
        )
        events = _new_event_log()

        machine.mem_map(self._runtime_page, self._page_size)
        runtime_offset = self._runtime_page - _CPU_IMAGE_BASE
        machine.mem_write(
            self._runtime_page,
            self._result[runtime_offset : runtime_offset + self._page_size],
        )
        start, size = self._map_size(
            self._data_page,
            self._rle_address + self._frame_bytes + 16,
        )
        machine.mem_map(start, size)
        start, size = self._map_size(
            self._framebuffer, self._framebuffer + self._frame_bytes
        )
        machine.mem_map(start, size)
        raw_virtual = self._symbols["AUTOMATION_VIRTUAL_RAW_BASE"]
        virtual_end = self._symbols["AUTOMATION_VIRTUAL_RLE_END"]
        start, size = self._map_size(raw_virtual, virtual_end)
        machine.mem_map(start, size)
        machine.mem_map(0xC000_0000, 0x1_0000)
        machine.mem_map(self._stack_page, 0x1_0000)
        machine.mem_map(self._io_page, 0x1_0000)
        machine.mem_map(self._sentinel, self._page_size)
        machine.mem_write(self._sentinel, b"\x00\xbe")  # BKPT if the hook fails.

        mapped_stub_pages: set[int] = set()
        for address in self._external.values():
            page = address & ~(self._page_size - 1)
            if page not in mapped_stub_pages:
                machine.mem_map(page, self._page_size)
                mapped_stub_pages.add(page)
            machine.mem_write(address, b"\x70\x47")  # bx lr

        _ = machine.hook_add(self._unicorn.UC_HOOK_CODE, self._hook_code)
        self._active_events = events
        return machine, events

    def _execute(
        self,
        machine: Uc,
        events: _EventLog,
        function: str,
        arguments: tuple[int, int, int] = (0, 0, 0),
        *,
        instruction_limit: int = 50_000_000,
    ) -> int:
        """Run one linked function to the sentinel and verify the calling ABI.

        Args:
            machine: The emulator to run.
            events: The event log the code hook writes to.
            function: The linked symbol to start at.
            arguments: The R0, R1, and R2 argument values.
            instruction_limit: The maximum instructions before giving up.

        Returns:
            The 32-bit R0 return value.

        Raises:
            ValueError: If the function fails to return, corrupts SP or a
                callee-saved register, or makes an unaligned external call.

        """
        self._active_events = events
        initial_sp = self._stack_page + 0x8000
        machine.reg_write(self._arm.UC_ARM_REG_SP, initial_sp)
        machine.reg_write(self._arm.UC_ARM_REG_LR, self._sentinel | 1)
        machine.reg_write(self._arm.UC_ARM_REG_R0, arguments[0])
        machine.reg_write(self._arm.UC_ARM_REG_R1, arguments[1])
        machine.reg_write(self._arm.UC_ARM_REG_R2, arguments[2])
        for register, value in self._register_patterns.items():
            machine.reg_write(register, value)
        machine.emu_start(
            self._symbols[function],
            self._sentinel + 2,
            count=instruction_limit,
        )
        if not events["stopped"]:
            pc = int(machine.reg_read(self._arm.UC_ARM_REG_PC))
            msg = f"emulation of {function} did not return; PC=0x{pc:08X}"
            raise ValueError(msg)
        if int(machine.reg_read(self._arm.UC_ARM_REG_SP)) != initial_sp:
            msg = f"{function} did not restore SP"
            raise ValueError(msg)
        for register, value in self._register_patterns.items():
            if int(machine.reg_read(register)) != value:
                msg = f"{function} corrupted a callee-saved register"
                raise ValueError(msg)
        if any(events["stack_mod_8"]):
            msg = f"{function} made an external call with unaligned SP"
            raise ValueError(msg)
        return int(machine.reg_read(self._arm.UC_ARM_REG_R0)) & 0xFFFF_FFFF

    def _reference_rle(self, raw: bytes) -> bytes:
        """Return the reference RLE3 encoding of ``raw``, or empty on overflow.

        Args:
            raw: One full frame of RGB565 little-endian pixels.

        Returns:
            The RLE3 byte stream, or ``b""`` if it would exceed the frame size.

        Raises:
            ValueError: If ``raw`` is not a full even-length frame.

        """
        if len(raw) != self._frame_bytes or len(raw) % 2:
            msg = "RLE reference input has the wrong length"
            raise ValueError(msg)
        output = bytearray()
        offset = 0
        while offset < len(raw):
            pixel = raw[offset : offset + 2]
            count = 1
            offset += 2
            while (
                count < _RLE_MAX_RUN_LENGTH
                and offset < len(raw)
                and raw[offset : offset + 2] == pixel
            ):
                count += 1
                offset += 2
            if len(output) + 3 > self._frame_bytes:
                return b""
            output.extend((count, pixel[0], pixel[1]))
        return bytes(output)

    def _run_rle(self, raw: bytes) -> tuple[int, bytes]:
        """Encode ``raw`` in the emulator and check it against the reference.

        Args:
            raw: One full frame of RGB565 little-endian pixels.

        Returns:
            The encoded length and its bytes (empty on overflow fallback).

        Raises:
            ValueError: If the encoder writes outside snapshot B or diverges
                from the reference encoder.

        """
        machine, events = self._new_machine()
        machine.mem_write(self._raw_address, raw)
        machine.mem_write(self._rle_address - 16, b"\xa5" * 16)
        machine.mem_write(self._rle_address + self._frame_bytes, b"\x5a" * 16)
        length = self._execute(machine, events, "automation_rle_encode")
        if bytes(machine.mem_read(self._rle_address - 16, 16)) != b"\xa5" * 16:
            msg = "RLE encoder wrote before snapshot B"
            raise ValueError(msg)
        if (
            bytes(machine.mem_read(self._rle_address + self._frame_bytes, 16))
            != b"\x5a" * 16
        ):
            msg = "RLE encoder wrote past snapshot B"
            raise ValueError(msg)
        encoded = bytes(machine.mem_read(self._rle_address, length)) if length else b""
        expected = self._reference_rle(raw)
        if length != len(expected) or encoded != expected:
            msg = "Thumb RLE output differs from the reference encoder"
            raise ValueError(msg)
        return length, encoded

    def _dispatch(
        self,
        request: bytes,
        *,
        frame: bytes | None = None,
        unstable_frame: bool = False,
    ) -> tuple[Uc, _EventLog]:
        """Run ``automation_dispatch`` over one request in a fresh machine.

        Args:
            request: The CAT request bytes.
            frame: Optional framebuffer contents to preload.
            unstable_frame: Whether the code hook should perturb the frame.

        Returns:
            The machine and its event log after dispatch.

        """
        machine, events = self._new_machine()
        machine.mem_write(self._request_address, request)
        if frame is not None:
            machine.mem_write(self._framebuffer, frame)
        events["unstable_frame"] = unstable_frame
        _ = self._execute(
            machine,
            events,
            "automation_dispatch",
            (self._request_address, len(request), 0),
        )
        return machine, events

    def _check_rle_vectors(self) -> tuple[int, bytes, int, int]:
        """Verify RLE run-splitting, the 255/256 boundary, and overflow fallback.

        Returns:
            The solid-frame length and bytes, the boundary length, and the
            overflow length.

        Raises:
            ValueError: If any RLE vector produces an unexpected length or
                structure.

        """
        boundary_pixels = (
            [0x1111] * 255 + [0x2222] * 256 + [0x3333] * (self._frame_bytes // 2 - 511)
        )
        boundary = struct.pack(f"<{len(boundary_pixels)}H", *boundary_pixels)
        solid_length, solid_rle = self._run_rle(self._solid)
        boundary_length, _ = self._run_rle(boundary)
        overflow_length, _ = self._run_rle(self._alternating)
        if solid_length != _SOLID_FRAME_RLE_LENGTH:
            msg = f"solid-frame RLE length is {solid_length}, expected 510"
            raise ValueError(msg)
        if list(solid_rle[::3]) != [_RLE_MAX_RUN_LENGTH] * 169 + [105]:
            msg = "RLE 255-count splitting is incorrect"
            raise ValueError(msg)
        if boundary_length != _BOUNDARY_FRAME_RLE_LENGTH:
            msg = f"RLE 255/256 boundary length is {boundary_length}, expected 513"
            raise ValueError(msg)
        if overflow_length != 0:
            msg = "incompressible RLE input did not fail closed to raw"
            raise ValueError(msg)
        return solid_length, solid_rle, boundary_length, overflow_length

    def _check_crc32(self) -> dict[str, str]:
        """Verify the Thumb CRC-32 against zlib on two vectors.

        Returns:
            A mapping from each vector label to its hexadecimal CRC-32.

        Raises:
            ValueError: If an emulated CRC-32 differs from zlib's.

        """
        crc_vectors: list[tuple[str, bytes]] = [
            ("123456789", b"123456789"),
            (
                "full_frame",
                bytes((index * 37) & 0xFF for index in range(self._frame_bytes)),
            ),
        ]
        crc_report: dict[str, str] = {}
        for label, data in crc_vectors:
            machine, events = self._new_machine()
            machine.mem_write(self._raw_address, data)
            actual = self._execute(
                machine,
                events,
                "automation_crc32",
                (self._raw_address, len(data), 0),
                instruction_limit=20_000_000,
            )
            expected = zlib.crc32(data)
            if actual != expected:
                msg = (
                    f"Thumb CRC-32 {label} is 0x{actual:08X}, expected 0x{expected:08X}"
                )
                raise ValueError(msg)
            crc_report[label] = f"0x{actual:08X}"
        return crc_report

    def _check_virtual_mappings(self) -> list[str]:
        """Verify each GM virtual-aperture read maps to the expected source.

        Returns:
            The list of exercised mapping-case labels.

        Raises:
            ValueError: If any case reads from an unexpected source address.

        """
        raw_virtual_base = self._symbols["AUTOMATION_VIRTUAL_RAW_BASE"]
        raw_virtual_end = self._symbols["AUTOMATION_VIRTUAL_RAW_END"]
        rle_virtual_base = self._symbols["AUTOMATION_VIRTUAL_RLE_BASE"]
        rle_virtual_end = self._symbols["AUTOMATION_VIRTUAL_RLE_END"]
        mapping_cases = (
            ("raw_start", raw_virtual_base, 1, self._data_page),
            (
                "raw_last_full_chunk",
                raw_virtual_end - 256,
                256,
                self._raw_address + self._frame_bytes - 256,
            ),
            ("raw_cross_end", raw_virtual_end - 255, 256, raw_virtual_end - 255),
            ("raw_exact_end", raw_virtual_end, 1, raw_virtual_end),
            ("rle_start", rle_virtual_base, 1, self._rle_address),
            (
                "rle_last_full_chunk",
                rle_virtual_end - 256,
                256,
                self._rle_address + self._frame_bytes - 256,
            ),
            ("rle_cross_end", rle_virtual_end - 255, 256, rle_virtual_end - 255),
            ("rle_exact_end", rle_virtual_end, 1, rle_virtual_end),
            ("normal_ddr", 0xC000_1234, 32, 0xC000_1234),
            ("wrapped_end", 0xFFFF_FFF0, 0x40, 0xFFFF_FFF0),
        )
        for label, source, length, expected_source in mapping_cases:
            machine, events = self._new_machine()
            events["copy_data"] = False
            _ = self._execute(
                machine,
                events,
                "automation_memory_copy",
                (self._io_page + 0x1000, source, length),
            )
            calls = events["memcpy"]
            if len(calls) != 1 or calls[0]["source"] != expected_source:
                msg = (
                    f"virtual mapping {label} used "
                    f"{calls[0]['source'] if calls else None!r}, "
                    f"expected 0x{expected_source:08X}"
                )
                raise ValueError(msg)
        return [case[0] for case in mapping_cases]

    def _check_query(self) -> None:
        """Verify the ABI query reply and its fresh-runtime invalid lease.

        Raises:
            ValueError: If the query reply or its published metadata is wrong.

        """
        query = self._query_request
        query_machine, query_events = self._dispatch(query)
        if query_events["replies"] != [
            {"echo": query[:10], "data": self._expected_info}
        ]:
            msg = "automation query reply has the wrong echo or ABI bytes"
            raise ValueError(msg)
        query_meta = bytes(query_machine.mem_read(self._data_page, 0x100))
        query_fresh_fields = {
            0x00: self._symbols["AUTOMATION_MAGIC"],
            0x04: self._symbols["AUTOMATION_ABI_VERSION"],
            0x08: 2,
            0x0C: self._symbols["AUTOMATION_FEATURES"],
            0x28: 0,
            0x2C: 1,
            0x30: 0,
            0x34: 0,
            0x38: 1,
            0x3C: 0,
            0x40: 0,
            0x44: 0,
            0x48: 0,
            0x4C: 0,
            0x64: 0,
            0xFC: self._symbols["AUTOMATION_MAGIC"],
        }
        if (
            query_events["inputs"]
            or query_events["memcpy"]
            or query_events["service"]
            or query_events["errors"]
            or any(
                _read_u32(query_meta, offset) != expected
                for offset, expected in query_fresh_fields.items()
            )
            or any(query_meta[0x68:0xFC])
        ):
            msg = "fresh-runtime query did not publish an invalid lease"
            raise ValueError(msg)

    def _check_requery_invalidation(self) -> None:
        """Verify a re-query seqlocks/invalidates a prior capture and its lease.

        A query is also a repeatable qualification/session boundary.  Prove that
        it seqlocks and invalidates a previously successful capture without
        touching the raw bytes, framebuffer, or input dispatcher, then prove a
        guarded key cannot inherit that old lease.

        Raises:
            ValueError: If the re-query setup capture fails, the query does not
                invalidate the prior capture, or the guarded key inherits it.

        """
        query = self._query_request
        requery_machine, requery_events = self._new_machine()
        requery_machine.mem_write(self._framebuffer, self._solid)
        if (
            self._execute(
                requery_machine,
                requery_events,
                "automation_capture",
                (0xA1B2C3, 0, 0),
            )
            != 0
        ):
            msg = "re-query setup capture failed"
            raise ValueError(msg)
        requery_events["inputs"].clear()
        requery_events["replies"].clear()
        requery_events["service"].clear()
        requery_events["memcpy"].clear()
        requery_events["errors"] = 0
        requery_machine.mem_write(self._request_address, query)
        _ = self._execute(
            requery_machine,
            requery_events,
            "automation_dispatch",
            (self._request_address, len(query), 0),
        )
        requery_meta = bytes(requery_machine.mem_read(self._data_page, 0x100))
        requery_fields = {
            0x08: 4,
            0x28: 1,
            0x2C: 1,
            0x30: 0,
            0x34: 0,
            0x38: 2,
            0x3C: 0,
            0x40: 0,
            0x44: 0,
            0x48: 0,
            0x4C: 0,
            0x64: 0,
        }
        if (
            requery_events["replies"]
            != [{"echo": query[:10], "data": self._expected_info}]
            or requery_events["inputs"]
            or requery_events["memcpy"]
            or requery_events["service"]
            or requery_events["errors"]
            or any(
                _read_u32(requery_meta, offset) != expected
                for offset, expected in requery_fields.items()
            )
            or any(requery_meta[0x68:0xFC])
            or bytes(requery_machine.mem_read(self._raw_address, self._frame_bytes))
            != self._solid
        ):
            msg = "query did not seqlock and invalidate the prior capture"
            raise ValueError(msg)

        guarded_after_requery = b"GM G13,0C1\r"
        requery_events["replies"].clear()
        requery_events["memcpy"].clear()
        requery_machine.mem_write(self._request_address, guarded_after_requery)
        _ = self._execute(
            requery_machine,
            requery_events,
            "automation_dispatch",
            (self._request_address, len(guarded_after_requery), 0),
        )
        after_requery_meta = bytes(requery_machine.mem_read(self._data_page, 0x100))
        after_requery_fields = {
            0x08: 6,
            0x28: 1,
            0x2C: 1,
            0x30: 0,
            0x38: 3,
            0x3C: 3,
            0x4C: 2,
            0x64: 0,
        }
        if (
            requery_events["inputs"]
            or requery_events["memcpy"]
            or requery_events["replies"]
            != [{"echo": guarded_after_requery[:10], "data": b"\x02"}]
            or any(
                _read_u32(after_requery_meta, offset) != expected
                for offset, expected in after_requery_fields.items()
            )
            or any(after_requery_meta[0x68:0x78])
        ):
            msg = "guarded key inherited a capture invalidated by re-query"
            raise ValueError(msg)

    def _check_memory_forward(self) -> None:
        """Verify an ordinary GM memory read is forwarded to the stock handler.

        Raises:
            ValueError: If the thirteen-byte read is not forwarded exactly.

        """
        memory_request = b"GM 000000,01\r"
        _, memory_events = self._dispatch(memory_request)
        if memory_events["service"] != [(memory_request, 13)]:
            msg = "thirteen-byte GM memory read was not forwarded exactly"
            raise ValueError(msg)

    def _check_snapshot(self, solid_length: int, solid_rle: bytes) -> None:
        """Verify a stable snapshot publishes correct metadata, raw, and RLE.

        Args:
            solid_length: The expected solid-frame RLE length.
            solid_rle: The expected solid-frame RLE bytes.

        Raises:
            ValueError: If the reply, metadata, raw copy, or RLE copy is wrong.

        """
        snapshot = b"GM S123456\r"
        snapshot_machine, snapshot_events = self._dispatch(snapshot, frame=self._solid)
        if snapshot_events["replies"] != [{"echo": snapshot[:10], "data": b"\x00"}]:
            msg = "snapshot reply has the wrong echo or status"
            raise ValueError(msg)
        metadata = bytes(snapshot_machine.mem_read(self._data_page, 0x100))
        expected_metadata = {
            0x00: self._symbols["AUTOMATION_MAGIC"],
            0x04: self._symbols["AUTOMATION_ABI_VERSION"],
            0x0C: self._symbols["AUTOMATION_FEATURES"],
            0x10: self._symbols["FRAME_WIDTH"],
            0x14: self._symbols["FRAME_HEIGHT"],
            0x18: self._symbols["FRAME_STRIDE"],
            0x1C: self._symbols["PIXEL_FORMAT_RGB565LE"],
            0x20: self._frame_bytes,
            0x24: 0x100,
            0x28: 1,
            0x2C: 0,
            0x30: zlib.crc32(self._solid),
            0x34: 1,
            0x38: 1,
            0x3C: 1,
            0x40: 0x123456,
            0x50: self._framebuffer,
            0x54: self._raw_address,
            0x58: 0x218,
            0x5C: self._symbols["AUTOMATION_RLE_MAGIC"],
            0x60: self._symbols["AUTOMATION_RLE_OFFSET"],
            0x64: solid_length,
            0xFC: self._symbols["AUTOMATION_MAGIC"],
        }
        for offset, expected in expected_metadata.items():
            actual = _read_u32(metadata, offset)
            if actual != expected:
                msg = (
                    f"snapshot metadata +0x{offset:02X} is 0x{actual:08X}, "
                    f"expected 0x{expected:08X}"
                )
                raise ValueError(msg)
        if _read_u32(metadata, 0x08) & 1:
            msg = "successful snapshot left the metadata seqlock odd"
            raise ValueError(msg)
        if any(metadata[0x68:0xFC]):
            msg = "snapshot metadata reserved bytes are not zero"
            raise ValueError(msg)
        if bytes(snapshot_machine.mem_read(self._raw_address, self._frame_bytes)) != (
            self._solid
        ):
            msg = "successful snapshot raw publication differs from LCD"
            raise ValueError(msg)
        if bytes(snapshot_machine.mem_read(self._rle_address, solid_length)) != (
            solid_rle
        ):
            msg = "successful snapshot RLE publication is inconsistent"
            raise ValueError(msg)

    def _check_snapshot_raw_fallback(self) -> None:
        """Verify an incompressible frame publishes a valid raw-only snapshot.

        Raises:
            ValueError: If the RLE-overflow snapshot loses the raw success path.

        """
        raw_fallback = b"GM SABCDEF\r"
        fallback_machine, fallback_events = self._dispatch(
            raw_fallback, frame=self._alternating
        )
        if fallback_events["replies"] != [{"echo": raw_fallback[:10], "data": b"\x00"}]:
            msg = "RLE-overflow snapshot did not retain the raw success path"
            raise ValueError(msg)
        fallback_meta = bytes(fallback_machine.mem_read(self._data_page, 0x100))
        if (
            _read_u32(fallback_meta, 0x2C) != 0
            or _read_u32(fallback_meta, 0x30) != zlib.crc32(self._alternating)
            or _read_u32(fallback_meta, 0x64) != 0
            or _read_u32(fallback_meta, 0x08) & 1
            or bytes(fallback_machine.mem_read(self._raw_address, self._frame_bytes))
            != self._alternating
        ):
            msg = "RLE overflow did not publish a valid raw-only snapshot"
            raise ValueError(msg)

    def _check_snapshot_unstable(self) -> None:
        """Verify an unstable frame fails closed after three capture attempts.

        Raises:
            ValueError: If the reply or fail-closed metadata is wrong.

        """
        unstable = b"GM S654321\r"
        unstable_machine, unstable_events = self._dispatch(
            unstable,
            frame=self._solid,
            unstable_frame=True,
        )
        if unstable_events["replies"] != [{"echo": unstable[:10], "data": b"\x01"}]:
            msg = "unstable snapshot did not return RESULT_UNSTABLE"
            raise ValueError(msg)
        unstable_meta = bytes(unstable_machine.mem_read(self._data_page, 0x100))
        unstable_fields = {
            0x28: 0,
            0x2C: 1,
            0x30: 0,
            0x34: 3,
            0x40: 0x654321,
            0x64: 0,
        }
        if (
            unstable_events["frame_copy_count"] != _UNSTABLE_FRAME_COPIES
            or any(
                _read_u32(unstable_meta, offset) != expected
                for offset, expected in unstable_fields.items()
            )
            or _read_u32(unstable_meta, 0x08) & 1
        ):
            msg = "unstable snapshot metadata did not fail closed"
            raise ValueError(msg)

    def _check_key(self) -> None:
        """Verify an unconditional key command dispatches once and records it.

        Raises:
            ValueError: If input dispatch, the reply, or metadata is wrong.

        """
        key = b"GM K18,2AB\r"
        key_machine, key_events = self._dispatch(key)
        if key_events["inputs"] != [(0x18, 2)]:
            msg = "key command did not call input_dispatch exactly once"
            raise ValueError(msg)
        if key_events["replies"] != [{"echo": key[:10], "data": b"\x00"}]:
            msg = "key reply has the wrong echo or status"
            raise ValueError(msg)
        key_meta = bytes(key_machine.mem_read(self._data_page, 0x100))
        key_fields = {0x3C: 2, 0x40: 0xAB, 0x44: 0x18, 0x48: 2, 0x4C: 0}
        if (
            any(
                _read_u32(key_meta, offset) != expected
                for offset, expected in key_fields.items()
            )
            or _read_u32(key_meta, 0x08) & 1
            or any(key_meta[0x68:0x78])
        ):
            msg = "key metadata or seqlock is incorrect"
            raise ValueError(msg)

    def _check_guarded_key_without_snapshot(self) -> None:
        """Verify a guarded key with no snapshot fails closed without dispatch.

        Raises:
            ValueError: If it dispatches input or its receipt is wrong.

        """
        guarded_without_snapshot = b"GM G13,0C1\r"
        missing_machine, missing_events = self._dispatch(
            guarded_without_snapshot, frame=self._solid
        )
        if missing_events["inputs"] or missing_events["replies"] != [
            {"echo": guarded_without_snapshot[:10], "data": b"\x02"}
        ]:
            msg = "guarded key without a snapshot did not fail closed"
            raise ValueError(msg)
        missing_meta = bytes(missing_machine.mem_read(self._data_page, 0x100))
        missing_fields = {0x3C: 3, 0x4C: 2}
        if (
            any(
                _read_u32(missing_meta, offset) != expected
                for offset, expected in missing_fields.items()
            )
            or _read_u32(missing_meta, 0x08) & 1
            or any(missing_meta[0x68:0x78])
        ):
            msg = "missing-snapshot guarded-key metadata is incorrect"
            raise ValueError(msg)

    def _check_guarded_key_match(self) -> None:
        """Verify a guarded key with a matching snapshot dispatches once.

        A guarded key requires an existing stable snapshot and compares the
        current live framebuffer with that exact raw snapshot before dispatch.
        The sample/compare/dispatch sequence is deliberately not labeled atomic
        against a preemptive framebuffer writer.

        Raises:
            ValueError: If dispatch, the reply, or the receipt is wrong.

        """
        guarded = b"GM G13,0C2\r"
        guarded_machine, guarded_events = self._new_machine()
        guarded_machine.mem_write(self._framebuffer, self._solid)
        _ = self._execute(
            guarded_machine, guarded_events, "automation_capture", (0x123456, 0, 0)
        )
        guarded_events["inputs"].clear()
        guarded_events["replies"].clear()
        guarded_machine.mem_write(self._request_address, guarded)
        _ = self._execute(
            guarded_machine,
            guarded_events,
            "automation_dispatch",
            (self._request_address, len(guarded), 0),
        )
        if guarded_events["inputs"] != [(0x13, 0)]:
            msg = "matching guarded key did not dispatch exactly once"
            raise ValueError(msg)
        if guarded_events["replies"] != [{"echo": guarded[:10], "data": b"\x00"}]:
            msg = "matching guarded key returned the wrong status"
            raise ValueError(msg)
        guarded_meta = bytes(guarded_machine.mem_read(self._data_page, 0x100))
        guarded_fields = {
            0x38: 2,
            0x3C: 3,
            0x40: 0xC2,
            0x44: 0x13,
            0x48: 0,
            0x4C: 0,
            0x64: 0,
        }
        if (
            any(
                _read_u32(guarded_meta, offset) != expected
                for offset, expected in guarded_fields.items()
            )
            or _read_u32(guarded_meta, 0x08) & 1
            or any(guarded_meta[0x68:0x78])
        ):
            msg = "matching guarded-key metadata is incorrect"
            raise ValueError(msg)

    def _check_guarded_key_changed(self) -> None:
        """Verify a guarded key refuses when the framebuffer changed.

        Raises:
            ValueError: If it dispatches input or its refusal receipt is wrong.

        """
        changed = b"GM G13,0C3\r"
        changed_machine, changed_events = self._new_machine()
        changed_machine.mem_write(self._framebuffer, self._solid)
        _ = self._execute(
            changed_machine, changed_events, "automation_capture", (0x654321, 0, 0)
        )
        changed_machine.mem_write(self._framebuffer, self._alternating)
        changed_events["inputs"].clear()
        changed_events["replies"].clear()
        changed_machine.mem_write(self._request_address, changed)
        _ = self._execute(
            changed_machine,
            changed_events,
            "automation_dispatch",
            (self._request_address, len(changed), 0),
        )
        if changed_events["inputs"]:
            msg = "changed-screen guarded key dispatched an input event"
            raise ValueError(msg)
        if changed_events["replies"] != [{"echo": changed[:10], "data": b"\x02"}]:
            msg = "changed-screen guarded key returned the wrong refusal status"
            raise ValueError(msg)
        changed_meta = bytes(changed_machine.mem_read(self._data_page, 0x100))
        changed_fields = {0x3C: 3, 0x4C: 2}
        if (
            any(
                _read_u32(changed_meta, offset) != expected
                for offset, expected in changed_fields.items()
            )
            or _read_u32(changed_meta, 0x08) & 1
            or any(changed_meta[0x68:0x78])
        ):
            msg = "changed-screen guarded-key metadata is incorrect"
            raise ValueError(msg)

    def _check_guarded_route_success(self) -> None:
        """Verify a matching guarded route dispatches all three digit taps.

        The Azimuth ABI-3 batch route accepts exactly three decimal digits,
        guards the top-level Menu once, and dispatches all three synchronous
        press/release pairs with no host turn. The radio legitimately redraws
        its numeric-entry state after digit one, so re-comparing the original
        frame between digits would reject the intended route.

        Raises:
            ValueError: If the taps, reply, or receipt is wrong.

        """
        route = self._route_request
        route_machine, route_events = self._new_machine()
        route_machine.mem_write(self._framebuffer, self._solid)
        _ = self._execute(
            route_machine, route_events, "automation_capture", (0x112233, 0, 0)
        )
        route_events["inputs"].clear()
        route_events["replies"].clear()
        route_machine.mem_write(self._request_address, route)
        _ = self._execute(
            route_machine,
            route_events,
            "automation_dispatch",
            (self._request_address, len(route), 0),
        )
        if route_events["inputs"] != self._route_inputs:
            msg = "guarded route did not dispatch three exact key taps"
            raise ValueError(msg)
        if route_events["replies"] != [{"echo": route[:10], "data": b"\x00"}]:
            msg = "successful guarded route returned the wrong status"
            raise ValueError(msg)
        route_meta = bytes(route_machine.mem_read(self._data_page, 0x100))
        route_success_fields = {
            0x38: 2,
            0x3C: 4,
            0x40: 0xA1,
            0x44: 0x0A,
            0x48: 1,
            0x4C: 0,
            0x64: 0,
            0x68: self._packed_route,
            0x6C: 1,
            0x70: 3,
            0x74: 0x3F,
        }
        if (
            any(
                _read_u32(route_meta, offset) != expected
                for offset, expected in route_success_fields.items()
            )
            or _read_u32(route_meta, 0x08) & 1
        ):
            msg = "successful guarded-route receipt is incorrect"
            raise ValueError(msg)

    def _check_guarded_route_without_snapshot(self) -> None:
        """Verify a guarded route with no snapshot fails closed before input.

        Raises:
            ValueError: If it dispatches input or its receipt is wrong.

        """
        route = self._route_request
        route_missing_machine, route_missing_events = self._dispatch(
            route, frame=self._solid
        )
        if route_missing_events["inputs"] or route_missing_events["replies"] != [
            {"echo": route[:10], "data": b"\x02"}
        ]:
            msg = "guarded route without a snapshot did not fail closed"
            raise ValueError(msg)
        route_missing_meta = bytes(
            route_missing_machine.mem_read(self._data_page, 0x100)
        )
        route_missing_fields = {
            0x38: 1,
            0x3C: 4,
            0x40: 0xA1,
            0x44: 0x13,
            0x48: 0,
            0x4C: 2,
            0x68: self._packed_route,
            0x6C: 1,
            0x70: 0,
            0x74: 0,
        }
        if (
            any(
                _read_u32(route_missing_meta, offset) != expected
                for offset, expected in route_missing_fields.items()
            )
            or _read_u32(route_missing_meta, 0x08) & 1
        ):
            msg = "missing-snapshot guarded-route receipt is incorrect"
            raise ValueError(msg)

    def _check_guarded_route_changed(self) -> None:
        """Verify a guarded route refuses when the frame changed before input.

        Raises:
            ValueError: If it dispatches input or its receipt is wrong.

        """
        route = self._route_request
        route_changed_machine, route_changed_events = self._new_machine()
        route_changed_machine.mem_write(self._framebuffer, self._solid)
        _ = self._execute(
            route_changed_machine,
            route_changed_events,
            "automation_capture",
            (0x223344, 0, 0),
        )
        route_changed_machine.mem_write(self._framebuffer, self._alternating)
        route_changed_events["inputs"].clear()
        route_changed_events["replies"].clear()
        route_changed_machine.mem_write(self._request_address, route)
        _ = self._execute(
            route_changed_machine,
            route_changed_events,
            "automation_dispatch",
            (self._request_address, len(route), 0),
        )
        if route_changed_events["inputs"] or route_changed_events["replies"] != [
            {"echo": route[:10], "data": b"\x02"}
        ]:
            msg = "changed-screen guarded route did not refuse before input"
            raise ValueError(msg)
        route_changed_meta = bytes(
            route_changed_machine.mem_read(self._data_page, 0x100)
        )
        route_changed_fields = {
            0x38: 2,
            0x3C: 4,
            0x40: 0xA1,
            0x44: 0x13,
            0x48: 0,
            0x4C: 2,
            0x68: self._packed_route,
            0x6C: 1,
            0x70: 0,
            0x74: 0,
        }
        if (
            any(
                _read_u32(route_changed_meta, offset) != expected
                for offset, expected in route_changed_fields.items()
            )
            or _read_u32(route_changed_meta, 0x08) & 1
        ):
            msg = "changed-before-first guarded-route receipt is incorrect"
            raise ValueError(msg)

    def _check_guarded_route_redraw(self) -> None:
        """Verify a guarded route completes after its intended first-digit redraw.

        Raises:
            ValueError: If the taps, reply, or receipt is wrong.

        """
        route = self._route_request
        route_transition_machine, route_transition_events = self._new_machine()
        route_transition_machine.mem_write(self._framebuffer, self._solid)
        _ = self._execute(
            route_transition_machine,
            route_transition_events,
            "automation_capture",
            (0x334455, 0, 0),
        )
        route_transition_events["inputs"].clear()
        route_transition_events["replies"].clear()
        route_transition_events["change_frame_after_inputs"] = 2
        route_transition_machine.mem_write(self._request_address, route)
        _ = self._execute(
            route_transition_machine,
            route_transition_events,
            "automation_dispatch",
            (self._request_address, len(route), 0),
        )
        if route_transition_events["inputs"] != self._route_inputs:
            msg = "guarded route did not complete after its intended first-digit redraw"
            raise ValueError(msg)
        if route_transition_events["replies"] != [
            {"echo": route[:10], "data": b"\x00"}
        ]:
            msg = "guarded route returned the wrong status after its intended redraw"
            raise ValueError(msg)
        route_transition_meta = bytes(
            route_transition_machine.mem_read(self._data_page, 0x100)
        )
        route_transition_fields = {
            0x38: 2,
            0x3C: 4,
            0x40: 0xA1,
            0x44: 0x0A,
            0x48: 1,
            0x4C: 0,
            0x64: 0,
            0x68: self._packed_route,
            0x6C: 1,
            0x70: 3,
            0x74: 0x3F,
        }
        if (
            any(
                _read_u32(route_transition_meta, offset) != expected
                for offset, expected in route_transition_fields.items()
            )
            or _read_u32(route_transition_meta, 0x08) & 1
        ):
            msg = "post-redraw guarded-route receipt is incorrect"
            raise ValueError(msg)

    def _check_invalid_requests(self) -> int:
        """Verify every malformed request fails closed with an error reply.

        Returns:
            The number of invalid requests exercised.

        Raises:
            ValueError: If any invalid request is not rejected exactly once.

        """
        invalid_requests = (
            b"GM A00000\r",
            b"GM A000001\r",
            b"GM K19,0AA\r",
            b"GM K18,3AA\r",
            b"GM G19,0AA\r",
            b"GM G18,3AA\r",
            b"GM S12X456\r",
            b"GM R98A,AA\r",
            b"GM R980-AA\r",
            b"GM R980,AX\r",
            b"GM R980,A\r",
            b"GM R980,AAA\r",
        )
        for request in invalid_requests:
            _, events = self._dispatch(request)
            if events["errors"] != 1 or events["replies"] or events["inputs"]:
                msg = f"invalid request did not fail closed: {request!r}"
                raise ValueError(msg)
        return len(invalid_requests)

    def run(self) -> dict[str, object]:
        """Run every emulation vector and return the audit evidence.

        Returns:
            A JSON-serializable record of the machine-code self-test results.

        Raises:
            ValueError: If any emulation vector fails.

        """
        solid_length, solid_rle, boundary_length, overflow_length = (
            self._check_rle_vectors()
        )
        crc_report = self._check_crc32()
        mapping_case_names = self._check_virtual_mappings()
        self._check_query()
        self._check_requery_invalidation()
        self._check_memory_forward()
        self._check_snapshot(solid_length, solid_rle)
        self._check_snapshot_raw_fallback()
        self._check_snapshot_unstable()
        self._check_key()
        self._check_guarded_key_without_snapshot()
        self._check_guarded_key_match()
        self._check_guarded_key_changed()
        self._check_guarded_route_success()
        self._check_guarded_route_without_snapshot()
        self._check_guarded_route_changed()
        self._check_guarded_route_redraw()
        invalid_count = self._check_invalid_requests()

        return {
            "status": "passed",
            "engine": f"unicorn {self._unicorn.__version__}",
            "thumb_abi": {
                "callee_saved_registers": "preserved",
                "external_stack_alignment": 8,
            },
            "rle": {
                "solid_length": solid_length,
                "run_255_256_length": boundary_length,
                "incompressible_length": overflow_length,
                "canaries": "preserved",
            },
            "crc32": crc_report,
            "virtual_mapping_cases": mapping_case_names,
            "commands": {
                "query_fresh_runtime": "invalidated_without_dispatch",
                "query_after_capture": "seqlocked_lease_invalidation",
                "guarded_key_after_requery": "refused_without_dispatch",
                "memory_forward": "passed",
                "snapshot_stable_rle": "passed",
                "snapshot_raw_fallback": "passed",
                "snapshot_unstable_three_attempts": "passed",
                "key": "passed",
                "guarded_key_without_snapshot": "refused_without_dispatch",
                "guarded_key_matching_snapshot": "dispatched_once",
                "guarded_key_changed_framebuffer": "refused_without_dispatch",
                "guarded_route_success": "three_press_release_taps",
                "guarded_route_without_snapshot": "refused_before_dispatch",
                "guarded_route_changed_before_first": "refused_before_dispatch",
                "guarded_route_intended_redraw": "completed_without_rechecking_original_frame",
                "invalid_fail_closed": invalid_count,
            },
        }


def _emulate_contract(result: bytes, symbols: dict[str, int]) -> dict[str, object]:
    """Exercise the linked Thumb code and its exact external-call ABI.

    Unicorn is intentionally an opt-in audit dependency rather than a package
    runtime dependency.  ``--emulate`` makes its absence or any failed vector
    fatal and records the evidence in ``audit.json``.

    Args:
        result: The linked flat firmware image.
        symbols: The resolved ABI symbol table.

    Returns:
        A JSON-serializable record of the machine-code self-test results.

    Raises:
        ValueError: If Unicorn is unavailable or any emulation vector fails.

    """
    return _AzimuthEmulator(result, symbols).run()


def _overlay(source: bytes, sections: list[ElfSection]) -> bytes:
    """Overlay the identity field and allocated sections onto ``source``.

    Args:
        source: The exact source flat firmware image.
        sections: Allocated sections to write, keyed by CPU address.

    Returns:
        A new flat image with the result identity and each section written.

    Raises:
        ValueError: If a section maps outside the flat image.

    """
    result = bytearray(source)
    identity_end = _FIRMWARE_IDENTITY_OFFSET + len(_RESULT_FIRMWARE_IDENTITY)
    result[_FIRMWARE_IDENTITY_OFFSET:identity_end] = _RESULT_FIRMWARE_IDENTITY
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
    sections: list[ElfSection],
    source: bytes,
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


def _hex_block(data: bytes, width: int = 16) -> str:
    """Return ``data`` as space-separated uppercase hex, ``width`` bytes per line."""
    return "\n".join(
        data[offset : offset + width].hex(" ").upper()
        for offset in range(0, len(data), width)
    )


def _change_clusters(changed_offsets: list[int]) -> list[tuple[int, int]]:
    """Group changed offsets into half-open clusters split on large gaps.

    Args:
        changed_offsets: Ascending flat offsets that differ from the source.

    Returns:
        Half-open ``(start, end)`` ranges; a gap wider than the cluster gap
        starts a new range.

    """
    clusters: list[tuple[int, int]] = []
    start = changed_offsets[0]
    previous = start
    for offset in changed_offsets[1:]:
        if offset - previous > _CLUSTER_GAP_BYTES:
            clusters.append((start, previous + 1))
            start = offset
        previous = offset
    clusters.append((start, previous + 1))
    return clusters


def _manifest_text(source: bytes, result: bytes) -> str:
    """Render the fail-closed patch-manifest draft for the Azimuth overlay.

    Args:
        source: The source flat firmware image.
        result: The overlaid result flat firmware image.

    Returns:
        The TOML manifest text pinning the source/result hashes, per-cluster
        source contexts, and every changed byte.

    """
    changed = [
        offset
        for offset, (before, after) in enumerate(zip(source, result, strict=True))
        if before != after
    ]
    lines = [
        'name = "normal-gm-nor-read-usb-recover-azimuth"',
        'description = """',
        "Closed-loop TH-D75 V1.03.AZM Azimuth automation overlay for the exact",
        "hash-pinned V1.03 USB-storage recovery firmware. It preserves",
        "ordinary GM DDR reads and GW 2 USB-storage recovery, adds bounded",
        "stock key-dispatch commands, including ABI-3 guarded-key and guarded",
        "three-decimal-digit route operations. A route samples the complete live",
        "LCD once, compares it with the authenticated stable top-level Menu",
        "snapshot, then synchronously dispatches all three digits with no host",
        "turn. The sole guard precedes every route input because the stock radio",
        "legitimately redraws numeric-entry state after digit one. A preemptive",
        "display writer remains a documented TOCTOU boundary. It publishes only double-copied,",
        "byte-identical 240x180 RGB565 LCD snapshots through attested raw and",
        "bounded RLE virtual GM apertures. Metadata is seqlocked and carries a",
        "generation number plus raw CRC-32. Invalid commands, unstable captures,",
        "RLE overflow, missing snapshots, and changed guard context fail closed.",
        "The exact ABI query seqlocks and invalidates any prior guarded-input",
        "snapshot lease before replying, without dispatching input.",
        "Its exact 16-byte payload identity is V1.03.AZM plus six spaces and NUL;",
        "the updater's stock V1.03 compatibility metadata remains unchanged.",
        "A route refusal therefore authenticates an empty prefix; success",
        "authenticates all six press/release events. RLE overflow retains an",
        "explicit raw path.",
        '"""',
        'target_firmware = "TH-D75 V1.03 pinned USB-storage recovery FIRMWARE"',
        "",
        f'source_sha256 = "{_sha256(source)}"',
        f'result_sha256 = "{_sha256(result)}"',
        f'source_updater_sha256 = "{_SOURCE_UPDATER_SHA256}"',
        f"change_count = {len(changed)}",
        "",
    ]

    for cluster_start, cluster_end in _change_clusters(changed):
        context_start = max(0, (cluster_start - 32) & ~0xF)
        context_end = min(
            len(source),
            (cluster_end + 32 + 0xF) & ~0xF,
        )
        lines.extend(
            [
                "[[contexts]]",
                f"offset = 0x{context_start:X}",
                'expect = """',
                _hex_block(source[context_start:context_end]),
                '"""',
                "",
            ]
        )

    for offset in changed:
        lines.extend(
            [
                "[[changes]]",
                f"offset = 0x{offset:X}",
                f"expect = 0x{source[offset]:02X}",
                f"value = 0x{result[offset]:02X}",
                "",
            ]
        )
    return "\n".join(lines)


def _parse_args() -> argparse.Namespace:
    """Parse the command-line arguments for the automation overlay builder."""
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "source",
        type=Path,
        help="exact hash-pinned V1.03 0x280000-byte flat firmware image",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="new empty directory for build products and audit logs",
    )
    _ = parser.add_argument("--clang", help="ARM-capable clang executable")
    _ = parser.add_argument("--linker", help="ld.lld executable")
    _ = parser.add_argument("--objdump", help="optional llvm-objdump executable")
    _ = parser.add_argument(
        "--emulate",
        action="store_true",
        help=(
            "require Unicorn and emulate the linked Thumb ABI, commands, "
            "CRC-32, bounded RLE, and virtual mappings"
        ),
    )
    return parser.parse_args()


def _read_validated_source(path: Path) -> bytes:
    """Read the source image and confirm its size, SHA-256, and layout.

    Args:
        path: The hash-pinned USB-storage recovery flat firmware image.

    Returns:
        The image bytes.

    Raises:
        ValueError: If the image is the wrong size, has an unexpected hash, or
            fails source-layout validation.

    """
    source = path.read_bytes()
    if len(source) != _SOURCE_SIZE:
        msg = f"source image is 0x{len(source):X} bytes, expected 0x{_SOURCE_SIZE:X}"
        raise ValueError(msg)
    source_hash = _sha256(source)
    if source_hash != _SOURCE_SHA256:
        msg = f"source SHA-256 is {source_hash}, expected {_SOURCE_SHA256}"
        raise ValueError(msg)
    _validate_source(source)
    return source


def _validate_dual_build(
    object_a: Path,
    object_b: Path,
    elf_a: Path,
    elf_b: Path,
) -> tuple[bytes, bytes, list[ElfSection], dict[str, int]]:
    """Confirm two builds are identical and parse their sections and symbols.

    Args:
        object_a: First build's assembled object file.
        object_b: Second build's assembled object file.
        elf_a: First build's linked ELF.
        elf_b: Second build's linked ELF.

    Returns:
        The first object's bytes, the first ELF's bytes, the allocated
        sections, and the resolved ABI symbols.

    Raises:
        ValueError: If the objects, ELFs, sections, or symbols differ, a
            relocation section survives, or contract validation fails.

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
    wanted_symbols = set(_EXPECTED_SYMBOLS) | set(_RUNTIME_FUNCTIONS)
    symbols_a = _elf_named_symbols(elf_a_data, wanted_symbols)
    symbols_b = _elf_named_symbols(elf_b_data, wanted_symbols)
    if symbols_a != symbols_b:
        msg = "independent ELFs have different ABI symbols"
        raise ValueError(msg)
    _validate_contract(sections_a, symbols_a)
    return object_a_data, elf_a_data, sections_a, symbols_a


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


def main() -> int:
    """Build the automation overlay and write its audit and manifest artifacts.

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
    object_a_data, elf_a_data, sections, symbols = _validate_dual_build(
        object_a, object_b, elf_a, elf_b
    )

    result = _overlay(source, sections)
    emulation: dict[str, object] = (
        _emulate_contract(result, symbols)
        if args.emulate
        else {
            "status": "not_requested",
            "rerun": "pass --emulate to require linked Thumb self-tests",
        }
    )
    result_path = args.output / "radio_automation.bin"
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
        "firmware_identity": {
            "offset": f"0x{_FIRMWARE_IDENTITY_OFFSET:06X}",
            "source_hex": _SOURCE_FIRMWARE_IDENTITY.hex(" ").upper(),
            "result_hex": _RESULT_FIRMWARE_IDENTITY.hex(" ").upper(),
            "result_ascii": _RESULT_FIRMWARE_IDENTITY[:-1].decode("ascii"),
        },
        "first_changed_offset": f"0x{changed_offsets[0]:06X}",
        "last_changed_offset": f"0x{changed_offsets[-1]:06X}",
        "machine_code_self_test": emulation,
        "automation_abi": {
            "version": symbols["AUTOMATION_ABI_VERSION"],
            "features": f"0x{symbols['AUTOMATION_FEATURES']:08X}",
            "metadata_address": f"0x{symbols['AUTOMATION_META']:08X}",
            "raw_virtual_range": [
                f"0x{symbols['AUTOMATION_VIRTUAL_RAW_BASE']:08X}",
                f"0x{symbols['AUTOMATION_VIRTUAL_RAW_END']:08X}",
            ],
            "rle_virtual_range": [
                f"0x{symbols['AUTOMATION_VIRTUAL_RLE_BASE']:08X}",
                f"0x{symbols['AUTOMATION_VIRTUAL_RLE_END']:08X}",
            ],
            "rle_magic": f"0x{symbols['AUTOMATION_RLE_MAGIC']:08X}",
            "rle_offset": f"0x{symbols['AUTOMATION_RLE_OFFSET']:08X}",
            "raw_length": symbols["FRAME_BYTES"],
            "dispatch": f"0x{symbols['automation_dispatch'] & ~1:08X}",
            "memory_copy": f"0x{symbols['automation_memory_copy'] & ~1:08X}",
        },
        "sections": _section_report(sections, source),
    }
    _ = (args.output / "audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    _ = (args.output / "build.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    _ = (args.output / "radio_automation_patch.toml").write_text(
        _manifest_text(source, result),
        encoding="utf-8",
    )

    _write_optional_disassembly(args.objdump, elf_a, args.output)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
