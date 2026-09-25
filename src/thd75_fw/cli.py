"""Command-line entry points for TH-D75 firmware tools."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

import serial
from serial.tools import list_ports as _serial_list_ports

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

from . import (
    __version__,
    file_cipher,
    flash,
    flash_ui,
    images,
    intel_hex,
    kex,
    patch,
    resource,
    serial_cipher,
    theme,
    voice,
)
from .sections import (
    FLASH_BASE,
    SECTIONS,
    FlashAddress,
    lookup_by_address,
    lookup_by_name,
)

__all__: list[str] = [
    "main_extract",
    "main_extract_images",
    "main_extract_voice",
    "main_flash",
    "main_list_patches",
    "main_patch",
    "main_repack",
    "main_serial_cipher",
    "main_theme",
]


_OFFICIAL_V103_PLAINTEXT_KEX_SHA256 = (
    "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
)
_SERVICE_9R_PLAINTEXT_KEX_SHA256 = (
    "fa95a673156c2d47b06a85fd6038682bbe1adfcbd1b7bdfdb7529ecfc1ca9541"
)
_NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256 = (
    "38d435f655d1d999802efba6d116a7aedc41bc2ffdaa662eac7473a37fe7b077"
)
_NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256 = (
    "f619fbb6b6fd91ad5bcdaf85bcc3bcd31483564fc5a5643aad73ce5915f5f30e"
)
_NORMAL_GM_NOR_USB_RECOVER_PLAINTEXT_KEX_SHA256 = (
    "257a93cbefb843c61676e5ca61e03ce4bc72b071658c936757f89477f1fa792a"
)
_AZIMUTH_PLAINTEXT_KEX_SHA256 = (
    "6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d"
)
_AZIMUTH_ORANGE_ON_BLACK_PLAINTEXT_KEX_SHA256 = (
    "c9a42fabbb5accd6da0a459e0238b4e79ce13ce1126127d738e9c317f4487ce2"
)
"""normal-gm-nor-read, usb-recover, Azimuth automation, then orange-on-black."""
# Every admitted Azimuth image: each runs the same ABI-3 automation runtime and
# takes the same post-flash qualifier, whatever display theme it carries.
_RADIO_AUTOMATION_PLAINTEXT_KEX_SHA256_FAMILY: frozenset[str] = frozenset(
    {
        _AZIMUTH_PLAINTEXT_KEX_SHA256,
        _AZIMUTH_ORANGE_ON_BLACK_PLAINTEXT_KEX_SHA256,
    }
)
_NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY: frozenset[str] = frozenset(
    {
        _NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256,
        _NORMAL_GM_NOR_USB_RECOVER_PLAINTEXT_KEX_SHA256,
        *_RADIO_AUTOMATION_PLAINTEXT_KEX_SHA256_FAMILY,
    }
)
_NORMAL_GM_FAST_PLAINTEXT_KEX_SHA256: frozenset[str] = frozenset(
    {
        _NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256,
        *_NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY,
    }
)

# Exact canonical plaintext artifacts admitted to a real KEX-mode write. The
# stock value is render(parse_encrypted_resource(official V1.03 resource)); the
# five single-patch values are also pinned by their manifests'
# result_kex_sha256, and the Azimuth + orange-on-black stack is pinned by the
# slow real-firmware theme test. Dry-run remains available for inspecting
# other well-formed artifacts without opening a device.
_AUDITED_PLAINTEXT_KEX_SHA256: dict[str, str] = {
    _OFFICIAL_V103_PLAINTEXT_KEX_SHA256: "official TH-D75 V1.03 stock",
    _SERVICE_9R_PLAINTEXT_KEX_SHA256: "TH-D75 V1.03 service-9r-nor-read",
    _NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256: "TH-D75 V1.03 normal-gm-ddr-read",
    _NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256: "TH-D75 V1.03 normal-gm-nor-read",
    _NORMAL_GM_NOR_USB_RECOVER_PLAINTEXT_KEX_SHA256: (
        "TH-D75 V1.03 normal-gm-nor-read-usb-recover V18"
    ),
    _AZIMUTH_PLAINTEXT_KEX_SHA256: ("TH-D75 V1.03.AZM Azimuth automation"),
    _AZIMUTH_ORANGE_ON_BLACK_PLAINTEXT_KEX_SHA256: (
        "TH-D75 V1.03.AZM Azimuth automation + orange-on-black"
    ),
}

_STOCK_IMAGE_DATA_QUALIFICATION_FLAG = "--qualification-rewrite-stock-image-data"
_STOCK_IMAGE_DATA_QUALIFICATION_NAME = "stock-selective-image-data"
_STOCK_IMAGE_DATA_QUALIFICATION_INDEX = 1
_STOCK_IMAGE_DATA_QUALIFICATION_INDICES: frozenset[int] = frozenset(
    {_STOCK_IMAGE_DATA_QUALIFICATION_INDEX}
)
_STOCK_IMAGE_DATA_QUALIFICATION_DESCRIPTOR = (
    "IMAGE_DATA",
    0x6060_0000,
    360_448,
    393_216,
    393_216,
)
_STOCK_IMAGE_DATA_QUALIFICATION_PAYLOAD_SHA256 = (
    "cd86abd837cd8cdf2b781148eec52d9cb39ce11f8b6b7d13e2f380669d652fb2"
)

# The exact normal-GM artifacts change only main FIRMWARE. DATA_0160 is
# byte-identical to stock, but its stock descriptor has $VL=0 / $VA="" and the
# loader reports SETUP mismatch for it on every retained run. In the retained
# 207-second trace, its erase, 40,960 acknowledged packets, and verification
# consumed about 165 seconds without changing the artifact. The normal-GM fast
# plan omits only this fully pinned source segment before any loader command.
# Stock recovery retains all seven segments so it can still repair DATA_0160.
_NORMAL_GM_FAST_OMIT_INDEX = 3
_NORMAL_GM_FAST_DATA_0160_DESCRIPTOR = bytes.fromhex(
    "00 00 60 61 00 00 A0 00 00 00 A0 00 00 00 00 00 "
    "0F 00 00 00 00 00 00 00 16 00 00 00 AE 04 AE 04 "
    "00 00 00 00 00 00 A0 00 0A 00 00 00 00 00 00 00 "
    "00 00 00 00"
)
_NORMAL_GM_FAST_DATA_0160_PAYLOAD_SHA256 = (
    "861082d1cfd24ac048b1c576d7421da06c8c6df55feaa48959d7fa7bc05928a9"
)
_NORMAL_GM_FAST_OMISSION = (
    "source segment 3 DATA_0160 omitted before SETUP: exact stock-identical "
    "10 MiB payload pinned; its $VL=0 descriptor is non-skippable by SETUP; "
    "retained source segments 0,1,2,4,5,6"
)

#: Default packet size for the CLI: the hardware-proven recovery value.
#:
#: Full stock V1.03 restores completed on this D75 with 256-byte packets on
#: 2026-07-05 and 2026-07-25. Attempts using 1024 in the acknowledged profile
#: stopped at the first packet and produced ``Data Error``. The stock KEX's
#: ``$DU/$DC=1024`` values are host metadata, not fields in the SETUP payload,
#: so they do not make 1024 a loader requirement.
#:
#: Kept as a module-level literal rather than read from ``FlashSession`` so
#: that tests replacing that class with a mock do not turn the argparse
#: default into a mock object.
_DEFAULT_CHUNK_SIZE: int = 256

#: Packet sizes admitted to a real hardware write.
#:
#: Only the exact successful 256-byte profile may reach real hardware.
#: ``--dry-run`` still accepts 1..2048 for offline protocol experiments.
_WRITABLE_CHUNK_SIZES: frozenset[int] = frozenset({_DEFAULT_CHUNK_SIZE})

#: The successful hardware control skipped segments that SETUP reported current.
#: Preserve vendor-force modeling offline without admitting it to a real write.
_FORCE_ALL_SEGMENTS_DRY_RUN_ERROR = (
    "--force-all-segments is valid only with --dry-run; real hardware writes "
    "must use the proven skip-current policy"
)

#: Chunks between data-phase throughput lines.
#:
#: At the default packet size a full stock image is tens of thousands of
#: chunks, so a per-chunk line is unreadable and no line at all is what made
#: a slow run indistinguishable from a hung one until it was abandoned. 256
#: puts a line roughly every second at the rates observed on hardware.
_DEFAULT_PROGRESS_EVERY_CHUNKS: int = 256

_TH_D75_USB_VID = 0x2166
_TH_D75_USB_PID = 0x9023

#: Inclusive upper bound of a single unsigned byte, for the ``--key`` range.
_MAX_BYTE_VALUE: int = 0xFF

#: Bytes of a cipher result shown as a hex dump when no ``-o`` file is given.
_HEXDUMP_PREVIEW_BYTES: int = 64

#: Printable 7-bit ASCII range ``[start, end)`` for a hex dump's ASCII column.
_PRINTABLE_ASCII_START: int = 32
_PRINTABLE_ASCII_END: int = 127

#: Number of components in an ``R,G,B`` colour, each in ``0..255``.
_RGB_COMPONENT_COUNT: int = 3
_RGB_COMPONENT_MAX: int = 255

#: Segment count of the audited D75 V1.03 KEX (FIRMWARE, IMAGE_DATA,
#: DATA_00E0, DATA_0160, FONT_DATA, CHECKBYTES, FINAL_ZZZ).
_D75_V103_SEGMENT_COUNT: int = 7

#: The only cleartext FLDM line rate proven on local D75 V1.03 hardware.
_PROVEN_CLEARTEXT_BAUD: int = 576_000

#: COMPLETE_UPDATE payload width in bytes: ``#FC`` as LE u32, the width of the
#: successful OpenWood-compatible D75 run (both the KEX and raw profiles use it).
_HARDWARE_COMPLETE_UPDATE_WIDTH: int = 4


# ── shared helpers ─────────────────────────────────────────────────


def _log(msg: str) -> None:
    """Write a progress message to stderr, leaving stdout for real output."""
    print(msg, file=sys.stderr)


_CHANGE_LOG_LIMIT: int = 32


def _verify_first_stage_updater(
    selected: Sequence[patch.Patch], exe_data: bytes
) -> None:
    """Authenticate the official updater against the first stage's pin only.

    Later stages of a stack pin the updater of the exe chain that built them
    (each repacked on the previous stage's output); the KEX path never
    materialises those intermediates, so their updater pins cannot be checked
    here and are reported instead of silently skipped.
    """
    selected[0].verify_updater_source(exe_data)
    for entry in selected[1:]:
        if entry.source_updater_sha256 is not None:
            _log(
                f"  {entry.name}: updater source pin describes the exe chain's "
                "intermediate; not checked for a stack"
            )


def _log_changes(entry: patch.Patch) -> None:
    """Log a patch's byte changes: one line each, or per-section totals when large."""
    if len(entry.changes) <= _CHANGE_LOG_LIMIT:
        for change in entry.changes:
            _log(
                f"  {change.section} offset 0x{change.offset:05X}: "
                f"0x{change.expect:02X} -> 0x{change.value:02X}"
            )
        return
    by_section: dict[str, list[int]] = {}
    for change in entry.changes:
        by_section.setdefault(change.section, []).append(change.offset)
    for section, offsets in sorted(by_section.items()):
        noun = "byte change" if len(offsets) == 1 else "byte changes"
        _log(
            f"  {section}: {len(offsets):,} {noun} between "
            f"0x{min(offsets):05X} and 0x{max(offsets):05X}"
        )


def _require_fldm_usb_port(port: str) -> str:
    """Attest that an explicit FLDM path is the enumerated TH-D75 USB node.

    VID:PID 2166:9023 identifies a TH-D75 USB endpoint, but owned-hardware
    traces show the same identity in normal CAT and Firmware Programming Mode.
    This gate therefore excludes Bluetooth/persistent/unrelated serial nodes;
    it does not replace the operator's PTT+1 FLDM-state attestation.
    """
    matches = sorted(
        device
        for device, vid, pid in _enumerate_fldm_serial_ports()
        if vid == _TH_D75_USB_VID and pid == _TH_D75_USB_PID
    )
    if port not in matches:
        _die(
            f"--port {port!r} is not a currently enumerated TH-D75 USB "
            "endpoint with VID:PID 2166:9023. Bluetooth/persistent nodes such "
            "as /dev/cu.TH-D75 and unrelated serial devices are forbidden for "
            "FLDM. VID/PID alone does not prove Firmware Programming Mode; "
            "after selecting the USB node, the operator must still attest the "
            "PTT+1 power-on state."
        )
    return port


def _enumerate_fldm_serial_ports() -> list[tuple[str, int | None, int | None]]:
    """Return immutable port identity fields for the pre-I/O FLDM gate."""
    try:
        ports = _serial_list_ports.comports()
    except (OSError, serial.SerialException) as exc:
        _die(f"cannot enumerate USB serial devices for FLDM identity gate: {exc}")
    return [(entry.device, entry.vid, entry.pid) for entry in ports]


def _atomic_write_bytes(output_path: Path, data: bytes) -> None:
    """Replace ``output_path`` atomically after fsyncing a staged artifact.

    The temporary file is created beside the destination so ``os.replace``
    remains an atomic same-filesystem operation. An existing regular file's
    permission bits are retained. Every failure path closes and removes the
    temporary file; the prior destination remains untouched unless replace
    itself has completed successfully.
    """
    try:
        existing_mode: int | None = output_path.stat().st_mode & 0o7777
    except FileNotFoundError:
        existing_mode = None

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            _ = temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        if existing_mode is not None:
            temp_path.chmod(existing_mode)
        _ = temp_path.replace(output_path)
        temp_path = None
    finally:
        if temp_path is not None:
            with contextlib.suppress(OSError):
                temp_path.unlink()


def _die(msg: str, code: int = 2) -> NoReturn:
    """Print a clean error message to stderr and exit non-zero.

    Exit-code convention used throughout the CLI:
        2 — file/IO problem (missing input, output path is a file, etc.).
            This is also argparse's exit code for argument errors.
        1 — data/format problem (parse error, malformed firmware, etc.).
        0 — success.
    """
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _die_on_os_error(exc: OSError) -> NoReturn:
    """Map an ``OSError`` to a clean stderr message and exit code.

    Routes ``FileNotFoundError`` / ``PermissionError`` /
    ``IsADirectoryError`` to specific user-facing messages; treats a
    ``BrokenPipeError`` (e.g. ``thd75-list-patches | head``) as a
    successful exit because the consumer has indicated it has read
    enough; falls back to a generic message for other OS errors so the
    user never sees a Python traceback.
    """
    if isinstance(exc, BrokenPipeError):
        # Downstream pipe closed (typical of ``thd75-list-patches | head``).
        # Redirect stdout to /dev/null so the interpreter's final flush
        # at shutdown does not raise on the already-closed pipe. The
        # contextlib.suppress is explicit: if /dev/null itself is
        # unopenable (sandboxed environment, OOM, etc.) we accept the
        # noisy flush rather than hide a deeper system error.
        with contextlib.suppress(OSError):
            # Point the stdout fd at /dev/null (no Python file object to leave
            # unclosed) so the interpreter's shutdown flush cannot re-raise on
            # the already-closed pipe. os.dup2 replaces the descriptor in place.
            devnull_fd = os.open(os.devnull, os.O_WRONLY)
            _ = os.dup2(devnull_fd, sys.stdout.fileno())
            os.close(devnull_fd)
        sys.exit(0)
    if isinstance(exc, FileNotFoundError):
        _die(f"file not found: {exc.filename}")
    if isinstance(exc, PermissionError):
        _die(f"permission denied: {exc.filename}")
    if isinstance(exc, IsADirectoryError):
        _die(f"path is a directory: {exc.filename}")
    target = exc.filename or "file"
    reason = exc.strerror or str(exc)
    _die(f"cannot access {target}: {reason}")


def _validate_output_dir(path: Path) -> None:
    """Ensure ``path`` is a directory we can write into (or doesn't exist yet)."""
    if path.exists() and not path.is_dir():
        _die(f"output path exists and is not a directory: {path}")


def _add_version(parser: argparse.ArgumentParser) -> None:
    _ = parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )


def _parse_serial_key(raw: str) -> int:
    """Parse a ``--key`` string and validate the 0..255 single-byte range.

    Accepts decimal, ``0xHEX``, or ``0oOCT`` via ``int(raw, 0)``.
    Out-of-range keys are caught here rather than later as opaque
    ``IndexError`` (decrypt) or silent-wrong roundtrip (negative keys).
    Raised ``ValueError`` is consumed by argparse and printed as a
    clean ``argument --key: invalid value`` line.
    """
    try:
        value = int(raw, 0)
    except ValueError as exc:
        msg = f"key must be an integer (decimal, 0xHEX, or 0oOCT): {raw!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    if not 0 <= value <= _MAX_BYTE_VALUE:
        msg = f"key must be 0..255, got {value}"
        raise argparse.ArgumentTypeError(msg)
    return value


# ── thd75-extract ──────────────────────────────────────────────────


def main_extract() -> None:
    """Extract firmware sections from a TH-D75 updater .exe."""
    parser = argparse.ArgumentParser(
        prog="thd75-extract",
        description="Extract firmware sections from the TH-D75 updater .exe.",
        epilog=(
            "Example:\n"
            "  thd75-extract TH-D75_V103_e.exe ./extracted/\n"
            "  thd75-extract TH-D75_V103_e.exe ./firmware-only/ "
            "--section FIRMWARE\n\n"
            "Other tools in this package: thd75-extract-voice, "
            "thd75-extract-images, thd75-list-patches, thd75-patch, "
            "thd75-repack, thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "input",
        type=Path,
        help="Path to the TH-D75 updater .exe to extract from",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="Output directory for extracted .bin files",
    )
    _ = parser.add_argument(
        "--verify",
        type=Path,
        metavar="DIR",
        help=(
            "Verify extracted files byte-for-byte against a reference directory; "
            "with --section, verify only that section's standard filename"
        ),
    )
    _ = parser.add_argument(
        "--resource",
        type=Path,
        metavar="FILE",
        help="Use a pre-extracted resource file (e.g., from ilspycmd)",
    )
    _ = parser.add_argument(
        "--section",
        choices=tuple(section.name for section in SECTIONS),
        metavar="NAME",
        help=(
            "Extract and validate only one named section. Unselected blocks "
            "still require valid $SA metadata, but their Intel HEX streams "
            "are not parsed; this does not waive any integrity error in the "
            "selected section."
        ),
    )
    args = parser.parse_args()

    try:
        _run_extract(
            args.input,
            args.output,
            args.verify,
            args.resource,
            args.section,
        )
    except OSError as exc:
        _die_on_os_error(exc)
    except (ValueError, UnicodeDecodeError) as exc:
        _die(str(exc), code=1)


def _load_extract_resource(exe_path: Path, resource_path: Path | None) -> str:
    """Load the encrypted resource text from an explicit file or the .exe."""
    _log("\n[1/3] Loading firmware resource...")
    if resource_path is not None:
        resource_text: str = resource_path.read_text(encoding="utf-8")
    else:
        resource_text = resource.load(exe_path)
    _log(f"  {len(resource_text):,} chars")
    return resource_text


def _resolve_selected_section(
    section_name: str | None,
) -> tuple[FlashAddress | None, str | None]:
    """Resolve ``--section`` to its flash address and standard filename.

    Returns ``(None, None)`` when no section filter was given.

    Raises:
        ValueError: If the name is unknown (argparse prevents this for CLI
            callers).

    """
    if section_name is None:
        return None, None
    selected_info = lookup_by_name(section_name)
    if selected_info is None:  # argparse prevents this for CLI callers.
        msg = f"unknown section name: {section_name}"
        raise ValueError(msg)
    _log(
        f"  Selected section: {selected_info.name} "
        f"(0x{selected_info.flash_address:08X})"
    )
    return selected_info.flash_address, selected_info.filename


@dataclass(slots=True)
class _ExtractedBlocks:
    """Outcome of parsing every resource block's Intel HEX stream.

    Attributes:
        sections: Flat section bytes keyed by flash-relative address.
        total_records: Intel HEX records parsed across every block.
        parse_errors: One message per checksum/format error, block-prefixed.
        skipped_blocks: Blocks skipped because ``--section`` filtered them out.
        selected_block_count: Blocks that matched the ``--section`` filter.

    """

    sections: dict[FlashAddress, bytes]
    total_records: int
    parse_errors: list[str]
    skipped_blocks: int
    selected_block_count: int


def _parse_extract_blocks(
    decrypted: file_cipher.DecryptedResource,
    *,
    selected_address: FlashAddress | None,
    section_name: str | None,
) -> _ExtractedBlocks:
    """Parse each block's Intel HEX independently and route by ``$SA=`` metadata.

    Raises:
        ValueError: If two unfiltered blocks repeat a ``$SA`` address, or the
            requested section appears in more than one block.

    """
    sections: dict[FlashAddress, bytes] = {}
    total_records: int = 0
    all_parse_errors: list[str] = []
    skipped_blocks: int = 0
    selected_block_count: int = 0
    unfiltered_addresses: set[FlashAddress] = set()

    for block_index, block in enumerate(decrypted.blocks):
        if not block.data:
            continue
        section_addr = _extract_flash_address(block, block_index)
        if selected_address is None:
            if section_addr in unfiltered_addresses:
                msg = (
                    f"block {block_index} repeats $SA flash address "
                    f"0x{section_addr:08X}"
                )
                raise ValueError(msg)
            unfiltered_addresses.add(section_addr)
        if selected_address is not None and section_addr != selected_address:
            skipped_blocks += 1
            continue
        if selected_address is not None:
            selected_block_count += 1
            if selected_block_count > 1:
                msg = f"requested section {section_name} appears in more than one block"
                raise ValueError(msg)

        parsed: intel_hex.ParseResult = intel_hex.parse(block.data)
        total_records += parsed.record_count
        approved_nonstandard_stream = kex.is_d75_v103_nonstandard_overlay_stream(
            block_index=block_index,
            physical_address=int(FLASH_BASE) + int(section_addr),
            records=block.data,
        )
        if parsed.errors and approved_nonstandard_stream:
            _log(
                f"  Block {block_index}: recognized exact stock V1.03 "
                f"nonstandard overlay ({len(parsed.errors)} checksum "
                "anomaly/anomalies)"
            )
        else:
            all_parse_errors.extend(
                f"block {block_index}: {err}" for err in parsed.errors
            )

        if parsed.data:
            sections[section_addr] = parsed.data

    return _ExtractedBlocks(
        sections=sections,
        total_records=total_records,
        parse_errors=all_parse_errors,
        skipped_blocks=skipped_blocks,
        selected_block_count=selected_block_count,
    )


def _write_extracted_sections(
    sections: dict[FlashAddress, bytes], output_dir: Path
) -> None:
    """Write each section to its standard filename in definition order."""
    _log(f"\n[3/3] Saving {len(sections)} sections to {output_dir}/")
    output_dir.mkdir(parents=True, exist_ok=True)

    for addr in _sort_sections_by_definition_order(sections.keys()):
        data: bytes = sections[addr]
        info = lookup_by_address(addr)
        filename: str = info.filename if info else f"UNKNOWN_0x{addr:08X}.bin"
        _ = (output_dir / filename).write_bytes(data)
        preview: str = " ".join(f"{b:02X}" for b in data[:8])
        _log(f"  {filename}: {len(data):>10,} bytes  [{preview}...]")


def _run_extract(
    exe_path: Path,
    output_dir: Path,
    verify_dir: Path | None,
    resource_path: Path | None,
    section_name: str | None = None,
) -> None:
    """Execute the full extraction pipeline."""
    _validate_output_dir(output_dir)

    _log(f"TH-D75 Firmware Extractor\n  Input: {exe_path}")

    resource_text = _load_extract_resource(exe_path, resource_path)

    _log("\n[2/3] Decrypting...")
    decrypted: file_cipher.DecryptedResource = file_cipher.decrypt_resource(
        resource_text
    )
    _log(f"  Blocks: {len(decrypted.blocks)}")
    _log(f"  Metadata: {len(decrypted.metadata)} entries")

    selected_address, selected_filename = _resolve_selected_section(section_name)

    parsed_blocks = _parse_extract_blocks(
        decrypted,
        selected_address=selected_address,
        section_name=section_name,
    )
    sections = parsed_blocks.sections

    _log(f"  Total records: {parsed_blocks.total_records:,}")
    _log(f"  Sections: {len(sections)}")
    if selected_address is not None:
        _log(f"  Unselected blocks skipped: {parsed_blocks.skipped_blocks}")

    if parsed_blocks.parse_errors:
        _log(
            f"\n  WARNING: {len(parsed_blocks.parse_errors)} Intel HEX parse error(s):"
        )
        for err in parsed_blocks.parse_errors:
            _log(f"    {err}")
        _die(
            "output may be incomplete or corrupt; "
            "re-run with a known-good updater .exe",
            code=1,
        )

    if selected_address is not None and parsed_blocks.selected_block_count == 0:
        msg = f"requested section {section_name} is not present"
        raise ValueError(msg)

    _write_extracted_sections(sections, output_dir)

    if verify_dir is not None:
        verify_passed: bool = _verify(
            output_dir,
            verify_dir,
            selected_filename=selected_filename,
        )
        _log(f"\nVerification: {'PASS' if verify_passed else 'FAIL'}")
        if not verify_passed:
            sys.exit(1)

    _log("\nDone.")


def _sort_sections_by_definition_order(
    addresses: Iterable[FlashAddress],
) -> list[FlashAddress]:
    """Sort flash addresses to match the order in ``SECTIONS``.

    Sorting by raw flash address would put CHECKBYTES (0x00200062) and
    FINAL_ZZZ (0x00200040) before FIRMWARE/IMAGE_DATA, which is confusing
    in the output listing because those two sections are tiny patches into
    the FIRMWARE region. The SECTIONS tuple defines a presentation order
    (FIRMWARE first, patches last) — preserve that. Unknown addresses
    sort to the end.
    """
    section_order = [section.flash_address for section in SECTIONS]
    return sorted(
        addresses,
        key=lambda addr: section_order.index(addr) if addr in section_order else 999,
    )


def _extract_flash_address(
    block: file_cipher.DecryptedBlock,
    block_index: int,
) -> FlashAddress:
    """Extract a section's flash-relative address from block metadata.

    Each block in the encrypted resource is preceded by a ``$SA=`` line
    holding the section's *physical* address — that includes the OMAP-L138's
    NOR flash base (``0x60000000``). Subtracting the base gives the
    flash-relative offset used everywhere else (filenames, ``SectionInfo.
    flash_address``, the README's section table). See ``docs/FORMAT.md``
    "Block / section metadata format" for the broader resource format.

    Raises:
        ValueError: If the block has no parseable ``$SA=`` line.
            Falling back to a positional ``SECTIONS[block_index]``
            lookup would silently misroute a block whenever ``$SA=``
            is corrupted or the ``SECTIONS`` tuple is reordered,
            so we refuse instead.

    """
    for meta_line in block.metadata:
        stripped = meta_line.strip()
        if stripped.startswith("$SA="):
            val: str = stripped[4:]
            try:
                physical_addr = int(val, 16) if val.startswith("0x") else int(val)
            except ValueError as exc:
                msg = f"Block {block_index} has unparseable $SA= value: {val!r}"
                raise ValueError(msg) from exc
            return FlashAddress(physical_addr - FLASH_BASE)
    msg = (
        f"Block {block_index} has no $SA= metadata line; cannot determine "
        f"flash address. Block metadata: {block.metadata!r}"
    )
    raise ValueError(msg)


def _verify(
    output_dir: Path,
    reference_dir: Path,
    *,
    selected_filename: str | None = None,
) -> bool:
    """Compare extracted files byte-for-byte against a reference.

    Verification fails when there is nothing to compare: a missing reference
    directory, or a full extraction whose reference directory holds no
    ``*.bin`` files.
    """
    _log(f"\nVerifying against: {reference_dir}")
    if not reference_dir.is_dir():
        _log("  REFERENCE DIRECTORY MISSING")
        return False
    all_match: bool = True

    reference_files = (
        [reference_dir / selected_filename]
        if selected_filename is not None
        else sorted(reference_dir.glob("*.bin"))
    )
    if not reference_files:
        _log("  NO REFERENCE FILES: no *.bin files to compare")
        return False
    for ref_file in reference_files:
        if not ref_file.is_file():
            _log(f"  {ref_file.name}: REFERENCE MISSING")
            all_match = False
            continue
        out_file: Path = output_dir / ref_file.name
        if not out_file.exists():
            _log(f"  {ref_file.name}: MISSING")
            all_match = False
            continue

        ref_data: bytes = ref_file.read_bytes()
        out_data: bytes = out_file.read_bytes()

        if ref_data == out_data:
            _log(f"  {ref_file.name}: MATCH ({len(ref_data):,} bytes)")
        else:
            all_match = False
            _report_mismatch(ref_file.name, ref_data, out_data)

    return all_match


def _report_mismatch(
    filename: str,
    reference_data: bytes,
    output_data: bytes,
) -> None:
    """Print a human-readable mismatch report."""
    for byte_index in range(min(len(reference_data), len(output_data))):
        if reference_data[byte_index] != output_data[byte_index]:
            _log(
                f"  {filename}: MISMATCH at byte {byte_index} "
                f"(got 0x{output_data[byte_index]:02X}, "
                f"expected 0x{reference_data[byte_index]:02X})"
            )
            return
    _log(
        f"  {filename}: SIZE MISMATCH "
        f"(got {len(output_data):,}, expected {len(reference_data):,})"
    )


# ── thd75-serial-cipher ───────────────────────────────────────────


def main_serial_cipher() -> None:
    """Encrypt or decrypt TH-D75 serial transfer packets."""
    parser = argparse.ArgumentParser(
        prog="thd75-serial-cipher",
        description="Encrypt/decrypt TH-D75 serial transfer packets.",
        epilog=(
            "Examples:\n"
            "  thd75-serial-cipher decrypt packet.bin -o plain.bin\n"
            "  thd75-serial-cipher encrypt plain.bin -o packet.bin\n"
            "  thd75-serial-cipher selftest\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-voice, "
            "thd75-extract-images, thd75-list-patches, thd75-patch, thd75-repack."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    for action_name, action_help in [
        ("decrypt", "Decrypt a captured serial packet"),
        ("encrypt", "Encrypt a plaintext payload"),
    ]:
        action_parser = sub.add_parser(action_name, help=action_help)
        _ = action_parser.add_argument(
            "input",
            type=Path,
            help="Path to the input file",
        )
        _ = action_parser.add_argument(
            "-o",
            "--output",
            type=Path,
            help="Path to the output file (if omitted, prints a hex dump of "
            "the first 64 bytes to stdout)",
        )
        _ = action_parser.add_argument(
            "--key",
            type=_parse_serial_key,
            default=serial_cipher.DEFAULT_KEY,
            help=(
                "Cipher key as decimal, 0xHEX, or 0oOCT, in 0..255 "
                f"(default: 0x{serial_cipher.DEFAULT_KEY:02X}; 0 = passthrough)"
            ),
        )

    _ = sub.add_parser(
        "selftest",
        help="Run the encrypt/decrypt round-trip self-test for all 256 byte values",
    )

    args = parser.parse_args()

    if args.command == "selftest":
        try:
            serial_cipher.verify_round_trip()
        except AssertionError as exc:
            _die(f"FAIL: {exc}", code=1)
        # The PASS line is the only meaningful output for this subcommand,
        # so it goes to stdout (not _log/stderr) to support shell scripting:
        #   thd75-serial-cipher selftest && echo "all good"
        print("PASS: round-trip verified for all 256 byte values")
        return

    try:
        data: bytes = args.input.read_bytes()
    except OSError as exc:
        _die_on_os_error(exc)

    # Guard against ``-o some/dir/`` where some/dir/ exists as a directory:
    # write_bytes() would raise IsADirectoryError mid-pipeline. Reject up front.
    if args.output is not None and args.output.is_dir():
        _die(f"output path is a directory, expected a file: {args.output}")

    cipher_func = (
        serial_cipher.decrypt if args.command == "decrypt" else serial_cipher.encrypt
    )
    result: bytes = cipher_func(data, args.key)

    try:
        if args.output:
            args.output.write_bytes(result)
            _log(f"Wrote {len(result):,} bytes to {args.output}")
        else:
            _hexdump(result[:_HEXDUMP_PREVIEW_BYTES])
            if len(result) > _HEXDUMP_PREVIEW_BYTES:
                _log(
                    f"  ... ({len(result) - _HEXDUMP_PREVIEW_BYTES:,} more bytes, "
                    "use -o to write)"
                )
    except OSError as exc:
        _die_on_os_error(exc)


def _hexdump(data: bytes, width: int = 16) -> None:
    """Print a compact hex dump."""
    for offset in range(0, len(data), width):
        chunk: bytes = data[offset : offset + width]
        hex_part: str = " ".join(f"{b:02X}" for b in chunk)
        ascii_part: str = "".join(
            chr(b) if _PRINTABLE_ASCII_START <= b < _PRINTABLE_ASCII_END else "."
            for b in chunk
        )
        print(f"  {offset:04X}: {hex_part:<{width * 3}}  {ascii_part}")


# ── thd75-extract-voice ──────────────────────────────────────────


def main_extract_voice() -> None:
    """Extract voice prompts from a TH-D75 DATA_0160 binary."""
    parser = argparse.ArgumentParser(
        prog="thd75-extract-voice",
        description="Extract voice prompts as WAV files from a DATA_0160 section.",
        epilog=(
            "Examples:\n"
            "  thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/\n"
            "  thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/ "
            "--lang en\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-images, "
            "thd75-list-patches, thd75-patch, thd75-repack, thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "input",
        type=Path,
        help="Path to a DATA_0160 .bin file from thd75-extract",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="Output directory for the extracted WAV files",
    )
    _ = parser.add_argument(
        "--lang",
        choices=["en", "ja", "zh", "all"],
        default="all",
        help="Language code to filter by (default: all three languages)",
    )
    args = parser.parse_args()

    try:
        data: bytes = args.input.read_bytes()
    except OSError as exc:
        _die_on_os_error(exc)

    _validate_output_dir(args.output)

    try:
        database: voice.PromptDatabase = voice.load(data)
    except ValueError as exc:
        _die(str(exc), code=1)

    _log(f"Voice Prompt Database: {database.model_id} / {database.engine_version}")
    _log(
        f"  {len(database.prompts)} prompts, "
        f"{database.total_duration_ms / 1000:.1f}s total"
    )

    for language in ("en", "ja", "zh"):
        prompts = database.by_language(language)
        total_ms = sum(prompt.duration_ms for prompt in prompts)
        _log(f"  {language}: {len(prompts)} prompts, {total_ms / 1000:.1f}s")

    args.output.mkdir(parents=True, exist_ok=True)

    prompts_to_export = (
        database.prompts if args.lang == "all" else database.by_language(args.lang)
    )

    for prompt in prompts_to_export:
        wav_path = (
            args.output
            / f"{prompt.index:03d}_{prompt.language}_{prompt.duration_ms}ms.wav"
        )
        prompt.to_wav(wav_path)

    _log(f"\nExported {len(prompts_to_export)} WAV files to {args.output}/")


# ── thd75-extract-images ─────────────────────────────────────────


def main_extract_images() -> None:
    """Extract PNG images from a TH-D75 IMAGE_DATA binary."""
    parser = argparse.ArgumentParser(
        prog="thd75-extract-images",
        description="Extract PNG images from an IMAGE_DATA section.",
        epilog=(
            "Example:\n"
            "  thd75-extract-images ./extracted/IMAGE_DATA_0x00600000.bin "
            "./images/\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-voice, "
            "thd75-list-patches, thd75-patch, thd75-repack, thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "input",
        type=Path,
        help="Path to an IMAGE_DATA .bin file from thd75-extract",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="Output directory for the extracted PNG files",
    )
    args = parser.parse_args()

    try:
        data: bytes = args.input.read_bytes()
    except OSError as exc:
        _die_on_os_error(exc)

    _validate_output_dir(args.output)

    try:
        database: images.ImageDatabase = images.load(data)
    except ValueError as exc:
        _die(str(exc), code=1)

    _log(f"Image Database: {database.version}")
    _log(f"  {len(database.images)} images, {database.valid_count} valid PNGs")

    args.output.mkdir(parents=True, exist_ok=True)

    exported_count: int = 0
    for image in database.images:
        if not image.is_valid_png:
            continue
        png_path = args.output / f"{image.index:03d}.png"
        image.save(png_path)
        exported_count += 1

    _log(f"\nExported {exported_count} PNG files to {args.output}/")


# ── thd75-patch ──────────────────────────────────────────────────


def main_patch() -> None:
    """Build a patched .KEX firmware file from a TH-D75 updater .exe."""
    parser = argparse.ArgumentParser(
        prog="thd75-patch",
        description=(
            "Apply a named patch to a TH-D75 updater .exe and write the "
            "resulting .KEX firmware image. Patches are loaded from the "
            "built-in catalog or a user-supplied .toml file."
        ),
        epilog=(
            "Example:\n"
            "  thd75-patch TH-D75_V103_e.exe out.KEX --patch pf-screen-capture\n\n"
            "List available built-in patches: thd75-list-patches.\n"
            "The .KEX is the patched firmware as a plaintext image, for "
            "inspection. To produce a flashable updater, use thd75-repack.\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-voice, "
            "thd75-extract-images, thd75-list-patches, thd75-repack, "
            "thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "input",
        type=Path,
        help="Path to the TH-D75 updater .exe",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="Path to write the patched .KEX file",
    )
    _ = parser.add_argument(
        "--patch",
        action="append",
        required=True,
        metavar="NAME",
        help=(
            "Patch to apply: a catalog name (see thd75-list-patches) or a path "
            "to a .toml patch file. Repeat to stack patches; they apply in the "
            "order given and each is verified against the output of the "
            "previous one."
        ),
    )
    _ = parser.add_argument(
        "--resource",
        type=Path,
        metavar="FILE",
        help="Use a pre-extracted resource file instead of scanning the .exe",
    )
    args = parser.parse_args()

    # Reject `thd75-patch foo.exe somedir/` before doing any work.
    if args.output.is_dir():
        _die(f"output path is a directory, expected a file: {args.output}")

    # Validate the file that will actually be read, before any
    # ``[N/4]`` progress prints — ``--resource`` shadows the ``.exe``
    # input, so check the resource path when present.
    required_input: Path = args.resource if args.resource is not None else args.input
    if not required_input.is_file():
        _die(f"file not found: {required_input}")

    try:
        _run_patch(args.input, args.output, args.resource, args.patch)
    except OSError as exc:
        _die_on_os_error(exc)
    except (ValueError, UnicodeDecodeError) as exc:
        _die(str(exc), code=1)


def _run_patch(
    exe_path: Path,
    output_path: Path,
    resource_path: Path | None,
    patch_ids: Sequence[str],
) -> None:
    """Load a resource, apply the named patches in order, write the .KEX."""
    if isinstance(patch_ids, str):
        msg = "patch_ids must be a sequence of names, not one string"
        raise TypeError(msg)
    _log(
        f"TH-D75 Firmware Patcher\n  Input: {exe_path}\n"
        f"  Patches: {', '.join(patch_ids)}"
    )

    _log("\n[1/4] Resolving patches...")
    selected = [patch.load_patch(patch_id) for patch_id in patch_ids]
    for entry in selected:
        _log(f"  {entry.name}: {entry.description.splitlines()[0]}")

    _log("\n[2/4] Loading firmware resource...")
    if resource_path is not None:
        # An explicit resource is the input artifact, so the unused updater
        # path has no source bytes to authenticate.  The patch engine still
        # verifies the decrypted firmware and rendered KEX pins below.
        resource_text: str = resource_path.read_text(encoding="utf-8")
    else:
        exe_data: bytes = exe_path.read_bytes()
        _verify_first_stage_updater(selected, exe_data)
        resource_text = resource.extract(exe_data)
    _log(f"  {len(resource_text):,} chars")

    _log("\n[3/4] Applying patches...")
    patched: bytes = kex.patch_kex_stack(resource_text, selected)
    for entry in selected:
        _log(f"  {entry.name}:")
        _log_changes(entry)

    _log(f"\n[4/4] Writing patched .KEX ({len(patched):,} bytes) to {output_path}")
    _atomic_write_bytes(output_path, patched)
    _log(f"  SHA-256 of rendered .KEX: {hashlib.sha256(patched).hexdigest()}")
    _log(
        "\nDone. The .KEX is the patched firmware image; "
        "run thd75-repack to build a flashable updater."
    )


# ── thd75-repack ─────────────────────────────────────────────────


def main_repack() -> None:
    """Build a patched copy of the TH-D75 updater .exe."""
    parser = argparse.ArgumentParser(
        prog="thd75-repack",
        description=(
            "Build a patched copy of the TH-D75 updater .exe by applying a "
            "named patch to its embedded firmware. The patched updater "
            "flashes exactly like the official one."
        ),
        epilog=(
            "Example:\n"
            "  thd75-repack TH-D75_V103_e.exe out.exe --patch pf-screen-capture\n\n"
            "List available built-in patches: thd75-list-patches.\n"
            "Run the patched .exe like the official updater (Windows). "
            "Reflashing firmware always carries some risk; use a fully "
            "charged radio.\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-voice, "
            "thd75-extract-images, thd75-list-patches, thd75-patch, "
            "thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "input",
        type=Path,
        help="Path to the official TH-D75 updater .exe",
    )
    _ = parser.add_argument(
        "output",
        type=Path,
        help="Path to write the patched updater .exe",
    )
    _ = parser.add_argument(
        "--patch",
        action="append",
        required=True,
        metavar="NAME",
        help=(
            "Patch to apply: a catalog name (see thd75-list-patches) or a path "
            "to a .toml patch file. Repeat to stack patches; they apply in the "
            "order given and each is verified against the output of the "
            "previous one."
        ),
    )
    args = parser.parse_args()

    if args.output.is_dir():
        _die(f"output path is a directory, expected a file: {args.output}")

    # Validate input before the ``[N/5]`` progress prints fire.
    if not args.input.is_file():
        _die(f"file not found: {args.input}")

    try:
        _run_repack(args.input, args.output, args.patch)
    except OSError as exc:
        _die_on_os_error(exc)
    except (ValueError, UnicodeDecodeError) as exc:
        _die(str(exc), code=1)


def _run_repack(exe_path: Path, output_path: Path, patch_ids: Sequence[str]) -> None:
    """Patch the updater's embedded firmware in order and write a new .exe."""
    if isinstance(patch_ids, str):
        msg = "patch_ids must be a sequence of names, not one string"
        raise TypeError(msg)
    _log(
        f"TH-D75 Updater Repacker\n  Input: {exe_path}\n"
        f"  Patches: {', '.join(patch_ids)}"
    )

    _log("\n[1/5] Resolving patches...")
    selected = [patch.load_patch(patch_id) for patch_id in patch_ids]
    for entry in selected:
        _log(f"  {entry.name}: {entry.description.splitlines()[0]}")

    _log("\n[2/5] Reading updater .exe...")
    exe_data: bytes = exe_path.read_bytes()
    _log(f"  {len(exe_data):,} bytes")
    _verify_first_stage_updater(selected, exe_data)

    _log("\n[3/5] Extracting embedded firmware resource...")
    resource_text: str = resource.extract(exe_data)
    _log(f"  {len(resource_text):,} chars")

    _log("\n[4/5] Applying patches...")
    # Each stage's encrypted-resource result pin is checked inside the stack.
    patched_resource: str = kex.patch_resource_stack(resource_text, selected)
    for entry in selected:
        _log(f"  {entry.name}:")
        _log_changes(entry)

    _log("\n[5/5] Building and verifying patched updater...")
    patched_exe: bytes = resource.replace(exe_data, patched_resource)
    if len(selected) == 1:
        selected[0].verify_updater_result(patched_exe)
    else:
        _log(
            "  updater result pins describe single-patch outputs; "
            "not checked for a stack"
        )
    _log(f"  SHA-256 of patched updater: {hashlib.sha256(patched_exe).hexdigest()}")
    _log(f"  Writing patched updater to {output_path}")
    _atomic_write_bytes(output_path, patched_exe)
    _log(f"  {len(patched_exe):,} bytes")
    _log("\nDone. Run the patched updater like the official one.")


# ── thd75-theme ──────────────────────────────────────────────────


def _parse_rgb(text: str) -> theme.RGB:
    """Parse ``R,G,B`` with each component 0..255."""
    parts = [part.strip() for part in text.split(",")]
    if len(parts) != _RGB_COMPONENT_COUNT or not all(part.isdigit() for part in parts):
        msg = f"colour must be R,G,B with decimal components, got {text!r}"
        raise ValueError(msg)
    red, green, blue = (int(part) for part in parts)
    if not all(
        0 <= component <= _RGB_COMPONENT_MAX for component in (red, green, blue)
    ):
        msg = f"colour must be R,G,B with components 0..255, got {text!r}"
        raise ValueError(msg)
    return (red, green, blue)


def main_theme() -> None:
    """Generate a display-theme patch from stock firmware sections."""
    parser = argparse.ArgumentParser(
        prog="thd75-theme",
        description=(
            "Derive a display theme patch for menu 906 from the stock TH-D75 "
            "FIRMWARE and IMAGE_DATA sections. The White option's palettes, "
            "text palette and icon twins are recoloured to one theme colour on "
            "black; the result is a section-aware patch TOML for thd75-patch."
        ),
        epilog=(
            "Examples:\n"
            "  thd75-theme orange-on-black.toml --exe TH-D75_V103_e.exe\n"
            "  thd75-theme amber.toml --exe TH-D75_V103_e.exe --rgb 255,191,0 "
            "--name amber-on-black\n"
            "  thd75-theme out.toml --firmware FIRMWARE_0x00200000.bin "
            "--image-data IMAGE_DATA_0x00600000.bin\n\n"
            "Apply the result: thd75-patch TH-D75_V103_e.exe out.KEX --patch out.toml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "output", type=Path, help="Path to write the generated patch .toml"
    )
    _ = parser.add_argument(
        "--exe",
        type=Path,
        metavar="UPDATER",
        help="Official TH-D75 updater .exe to read both sections from",
    )
    _ = parser.add_argument(
        "--firmware",
        type=Path,
        metavar="FILE",
        help="Extracted FIRMWARE section (with --image-data)",
    )
    _ = parser.add_argument(
        "--image-data",
        type=Path,
        metavar="FILE",
        help="Extracted IMAGE_DATA section (with --firmware)",
    )
    _ = parser.add_argument(
        "--rgb",
        default="255,140,0",
        metavar="R,G,B",
        help="Theme colour (default: deep orange 255,140,0)",
    )
    _ = parser.add_argument(
        "--name",
        default=theme.DEFAULT_NAME,
        help=f"Patch name (default: {theme.DEFAULT_NAME})",
    )
    args = parser.parse_args()

    from_exe = args.exe is not None
    from_sections = args.firmware is not None or args.image_data is not None
    incomplete_sections = from_sections and (
        args.firmware is None or args.image_data is None
    )
    if from_exe == from_sections or incomplete_sections:
        _die("give either --exe UPDATER or both --firmware FILE and --image-data FILE")
    if args.output.is_dir():
        _die(f"output path is a directory, expected a file: {args.output}")
    for required in (args.exe, args.firmware, args.image_data):
        if required is not None and not required.is_file():
            _die(f"file not found: {required}")
    try:
        rgb = _parse_rgb(args.rgb)
    except ValueError as exc:
        _die(str(exc))

    try:
        _run_theme(
            args.output,
            _ThemeSources(
                exe=args.exe, firmware=args.firmware, image_data=args.image_data
            ),
            rgb,
            args.name,
        )
    except OSError as exc:
        _die_on_os_error(exc)
    except ValueError as exc:
        _die(str(exc), code=1)


@dataclass(frozen=True, slots=True, kw_only=True)
class _ThemeSources:
    """The two FIRMWARE/IMAGE_DATA sources a theme is derived from.

    Exactly one supply is used: ``exe`` (both sections read from an updater
    .exe) or ``firmware`` plus ``image_data`` (pre-extracted sections). The
    ``main_theme`` argument gates guarantee that before ``_run_theme`` runs.

    Attributes:
        exe: Official updater .exe both sections are read from, or ``None``.
        firmware: Extracted FIRMWARE section, or ``None``.
        image_data: Extracted IMAGE_DATA section, or ``None``.

    """

    exe: Path | None
    firmware: Path | None
    image_data: Path | None


def _run_theme(
    output_path: Path,
    sources: _ThemeSources,
    rgb: theme.RGB,
    name: str,
) -> None:
    """Read the two sections, build the theme, write the TOML, log the report."""
    _log(
        f"TH-D75 Theme Generator\n  Colour: {rgb[0]},{rgb[1]},{rgb[2]}\n"
        f"  Patch name: {name}"
    )
    _log("\n[1/3] Loading sections...")
    if sources.exe is not None:
        model = kex.parse_resource(resource.extract(sources.exe.read_bytes()))
        firmware = kex.section_image(model, "FIRMWARE")
        image_data = kex.section_image(model, "IMAGE_DATA")
    else:
        if sources.firmware is None or sources.image_data is None:
            msg = "both --firmware and --image-data are required"
            raise ValueError(msg)
        firmware = sources.firmware.read_bytes()
        image_data = sources.image_data.read_bytes()
    _log(f"  FIRMWARE {len(firmware):,} bytes, IMAGE_DATA {len(image_data):,} bytes")

    _log("\n[2/3] Deriving the theme...")
    build = theme.build_theme(firmware, image_data, rgb, theme.ThemeOptions(name=name))
    report = build.report
    _log(f"  text palette entries recoloured: {report.text_palette_entries}")
    _log(f"  menu label changed: {'yes' if report.label_changed else 'no'}")
    _log(
        "  IMAGE_DATA header version bumped: "
        f"{'yes' if report.image_version_bumped else 'no'}"
    )
    palettes = ", ".join(str(index) for index in report.palettes_changed) or "none"
    _log(f"  palettes changed: {palettes}")
    _log(f"  twin groups: {report.twin_groups}, recoloured: {report.twins_recoloured}")
    if report.twins_from_overrides:
        overrides = ", ".join(str(index) for index in report.twins_from_overrides)
        _log(f"  twins resolved by override: {overrides}")
    _log(f"  FIRMWARE byte changes: {report.firmware_bytes:,}")
    _log(f"  IMAGE_DATA byte changes: {report.image_data_bytes:,}")

    _log(f"\n[3/3] Writing {output_path}")
    _atomic_write_bytes(output_path, build.toml.encode("utf-8"))
    _log(f"  {len(build.toml):,} bytes, {build.patch.change_count} single-byte changes")


# ── thd75-list-patches ───────────────────────────────────────────


def main_list_patches() -> None:
    """List every built-in patch in the catalog."""
    parser = argparse.ArgumentParser(
        prog="thd75-list-patches",
        description=(
            "List every patch shipped in the built-in catalog. Each entry "
            "shows the patch name (the value to pass as --patch to "
            "thd75-patch / thd75-repack), its target firmware, the byte "
            "changes it makes, and its full description."
        ),
        epilog=(
            "Example:\n"
            "  thd75-list-patches\n\n"
            "Apply a catalog patch:\n"
            "  thd75-repack TH-D75_V103_e.exe out.exe --patch <name>\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-voice, "
            "thd75-extract-images, thd75-patch, thd75-repack, "
            "thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.parse_args()

    try:
        patches: list[patch.Patch] = list(patch.iter_catalog())
    except OSError as exc:
        _die_on_os_error(exc)
    except ValueError as exc:
        _die(f"failed to read catalog: {exc}", code=1)

    # This is the real output (operators may pipe it through grep), so
    # use stdout via print() instead of _log() which writes to stderr.
    # ``_die_on_os_error`` handles BrokenPipeError if the consumer
    # (e.g. ``thd75-list-patches | head``) closes the pipe mid-print.
    try:
        if not patches:
            print("(no built-in patches)")
            return

        for index, entry in enumerate(patches):
            if index > 0:
                print()
            print(entry.name)
            target: str = entry.target_firmware or "unspecified"
            print(f"  target firmware: {target}")
            print(f"  changes ({len(entry.changes)}):")
            for change in entry.changes:
                print(
                    f"    offset 0x{change.offset:05X}: "
                    f"0x{change.expect:02X} -> 0x{change.value:02X}"
                )
            print("  description:")
            for line in entry.description.splitlines():
                print(f"    {line}")
    except OSError as exc:
        _die_on_os_error(exc)


# ── thd75-flash ────────────────────────────────────────────────────


def _build_flash_parser() -> argparse.ArgumentParser:
    """Construct the ``thd75-flash`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="thd75-flash",
        description=(
            "Flash only an exact audited TH-D75 V1.03 plaintext .KEX image "
            "to a connected radio; arbitrary artifacts are dry-run-only."
        ),
        epilog=(
            "The radio must be in Firmware Programming Mode (power on while "
            "holding [PTT] + [1]). Fully charged battery recommended.\n\n"
            "Other tools in this package: thd75-extract, thd75-extract-voice, "
            "thd75-extract-images, thd75-list-patches, thd75-patch, "
            "thd75-repack, thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    _ = parser.add_argument(
        "input",
        type=Path,
        nargs="?",
        help="Path to .KEX firmware (omit for probe/SETUP calibration modes)",
    )
    _ = parser.add_argument(
        "--port",
        help=(
            "Currently enumerated TH-D75 USB serial port (for example, "
            "/dev/cu.usbmodemXXXX); exact VID:PID 2166:9023 is required for "
            "probes, SETUP calibration, and real flashes. Omit for offline "
            "--dry-run. The same VID/PID appears in normal CAT and FLDM, so "
            "the operator must still establish PTT+1 Firmware Programming "
            "Mode. Bluetooth SPP is forbidden for FLDM."
        ),
    )
    _ = parser.add_argument(
        "--probe-only",
        action="store_true",
        help=(
            "Handshake only — sends the 11-byte unlock probe and "
            "waits for the 2-byte unlock reply. No framed commands, "
            "no known NOR-write verb. Radio state advances to 'unlocked' "
            "(flashing PROGRAM on D75); power-cycle to reset."
        ),
    )
    _ = parser.add_argument(
        "--probe-target",
        action="store_true",
        help=(
            "Deep probe — handshake + ENTER_PROGRAM + TIMED_SESSION + "
            "QUERY_TARGET; "
            "reports the 17-byte target identification payload. "
            "Validates the framed-protocol round-trip (XOR encoding, "
            "framing, decoding) without a known NOR-write verb. Radio state "
            "advances past the unlock-waiting state; power-cycle to reset."
        ),
    )
    _ = parser.add_argument(
        "--setup-controls-only",
        action="store_true",
        help=(
            "USB-C FLDM calibration: cleartext 576000, official post-unlock "
            "ordering, then exactly three allowlisted stock-main SETUP "
            "positive controls. Sends no known erase/program/finalization verb; "
            "target-side SETUP nonmutation is unproven. Power-cycle afterward."
        ),
    )
    _ = parser.add_argument(
        "--setup-mismatch-repeat-only",
        action="store_true",
        help=(
            "Experimental USB-C FLDM calibration: exactly one known mismatch "
            "SETUP followed by its known match. Requires "
            "--allow-unproven-setup-repeat and prior positive controls in a "
            "separate power-cycled session."
        ),
    )
    _ = parser.add_argument(
        "--allow-unproven-setup-repeat",
        action="store_true",
        help=(
            "Required acknowledgement for --setup-mismatch-repeat-only; the "
            "official D75 host never repeats SETUP after result 1."
        ),
    )
    _ = parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate the image and print the resolved flash plan offline; "
            "do not open the serial device or send any bytes"
        ),
    )
    _ = parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip pre-flash operator-confirmation prompt",
    )
    _ = parser.add_argument(
        "--acknowledge-service-9r-write",
        action="store_true",
        help=(
            "Required in addition to any --yes for a real write of the exact "
            "service-9r-nor-read KEX. Confirms this completed order: an "
            "untouched-stock USB-C 9R baseline; positive SETUP controls pass; "
            "a full radio power cycle; the exact mismatch/repeat result (1,0) "
            "passes; another full radio power cycle; and a verified stock "
            "restore artifact retained. The patched read/bounds check follows "
            "this write."
        ),
    )
    _ = parser.add_argument(
        "--acknowledge-gm-ddr-read-write",
        action="store_true",
        help=(
            "Required in addition to any --yes for a real write of the exact "
            "normal-gm-ddr-read KEX. Confirms this completed order: Firmware "
            "Programming Mode entry proven on the stock radio; a verified "
            "stock restore artifact generated and retained; and the radio "
            "fully charged. This patch destroys the GM GPS-mode command and is "
            "reverted only by a stock reflash. The first post-flash operation "
            "must be the escalating read probe followed by an out-of-bounds "
            "request that is rejected."
        ),
    )
    _ = parser.add_argument(
        "--acknowledge-gm-nor-read-write",
        action="store_true",
        help=(
            "Required with --yes for a real write of an exact "
            "normal-gm-nor-read family KEX. Confirms the verified stock "
            "restore is retained and the one-byte NOR-base delta was audited "
            "against the hardware-qualified DDR reader. The base image first "
            "requires the bounded gm-nor-check; the V18 recovery image first "
            "requires usb_apply_trigger attest-trigger followed by its "
            "one-shot qualify action; Azimuth first requires "
            "its ABI-3 byte-exact qualifier, missing-snapshot refusal, "
            "changed-context refusal, command-4 zero-prefix refusal, and "
            "atomic-991 route canary. Outside those exact "
            "qualifiers, never request a GM offset "
            "above 1FFFFF. The base patch replaces the GM GPS-mode command; "
            "family variants may also replace the GW GPS-mode command."
        ),
    )
    _ = parser.add_argument(
        "--no-post-hint",
        action="store_true",
        help="Suppress post-flash Full Reset reminder",
    )
    _ = parser.add_argument(
        "--baud-ladder",
        default=None,
        help="Comma-separated baud rates (default: 19200,4800,38400,57600,9600)",
    )
    _ = parser.add_argument(
        "--force-all-segments",
        action="store_true",
        help=(
            "Dry-run only: model writing every segment even when the loader "
            "reports it already matches, honouring the KEX #AF=1 force flag. "
            "Real hardware writes reject this option and always skip matching "
            "segments. For each exact normal-GM family artifact, the default fast "
            "plan also omits its separately pinned, stock-identical DATA_0160 "
            "source segment before SETUP because that segment's $VL=0 "
            "descriptor cannot report current. Stock recovery still retains "
            "every segment"
        ),
    )
    _ = parser.add_argument(
        _STOCK_IMAGE_DATA_QUALIFICATION_FLAG,
        action="store_true",
        help=(
            "HARDWARE QUALIFICATION ONLY: selectively rewrite segment index 1 "
            "IMAGE_DATA even when SETUP reports it current, while every other "
            "current segment remains skipped. Admitted only for the exact "
            "audited stock V1.03 KEX and retained IMAGE_DATA payload. Requires "
            "a new --wire-trace path and conflicts with --force-all-segments. "
            "This flag authorizes the selective qualification rewrite but does "
            "not imply --yes; the normal operator prompt remains unless --yes "
            "is also supplied"
        ),
    )
    _ = parser.add_argument(
        "--chunk-size",
        type=_parse_chunk_size,
        default=_DEFAULT_CHUNK_SIZE,
        help=(
            "SEND_CHUNK payload size, 1..2048 for dry-run inspection. Real KEX "
            f"writes are locked to {_DEFAULT_CHUNK_SIZE} (default), the value "
            "proven by two complete D75 stock restores"
        ),
    )
    _ = parser.add_argument(
        "--raw",
        action="store_true",
        help=(
            "Inspect INPUT as a flat .bin (e.g. a custom payload built "
            "by firmware/) rather than a .KEX. Raw mode is currently "
            "dry-run-only because no raw payload has an audited USB/Bluetooth "
            "return path. Requires --flash-addr."
        ),
    )
    _ = parser.add_argument(
        "--flash-addr",
        type=lambda s: int(s, 0),
        default=None,
        help=(
            "NOR flash address to model in the --raw dry-run plan (e.g. "
            "0x00200000 for the main-firmware slot). Required with --raw; "
            "raw hardware writes are disabled."
        ),
    )
    _ = parser.add_argument(
        "--complete-code",
        type=lambda s: int(s, 0),
        default=None,
        help=(
            "Required with --raw. For the audited D75 V1.03 candidate "
            "dry-run profile this must be 0x1DB0 and is modeled as LE u32. "
            "KEX recovery uses its required #FC value in the hardware-proven "
            "LE-u32 form."
        ),
    )
    _ = parser.add_argument(
        "--cleartext",
        action="store_true",
        help=(
            "Use the cleartext FPROMOD unlock path (locally proven on "
            "D75 V1.03 at 576000; OpenWood separately proves D74) instead of "
            "the encrypted Thd75tw unlock + D75 4-step cipher. "
            "Pairs with --cleartext-baud; opens the serial port "
            "directly at that baud (no probe ladder). This is the path "
            "exercised locally on real D75 V1.03 over macOS USB-CDC."
        ),
    )
    _ = parser.add_argument(
        "--cleartext-baud",
        type=int,
        default=576_000,
        help=(
            "Baud rate to open the serial port at when --cleartext "
            "is used (default 576000, the only cleartext rate proven on "
            "local D75 hardware). Stock metadata also lists 57600, 115200, "
            "and 1152000, but those rates are not locally validated."
        ),
    )
    _ = parser.add_argument(
        "--single-segment",
        action="store_true",
        help=(
            "Resolve --raw as one segment for offline diagnostics. "
            "Hardware writes are gated to the default vendor-shaped "
            "body/CHECKBYTES/FINAL_ZZZ plan."
        ),
    )
    _ = parser.add_argument(
        "--wire-trace",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Record every frame sent and received to PATH: monotonic "
            "timestamp, direction, verb, payload length and a "
            f"{flash.diagnostics.TRACE_HEX_PREFIX_BYTES}-byte hex prefix. Off "
            "by default. Records are written in batches, not per frame, so "
            "the data phase keeps its timing; the file also carries the "
            "configuration banner as a header. Valid only for a real flash"
        ),
    )
    _ = parser.add_argument(
        "--progress-every",
        type=_parse_progress_every,
        default=_DEFAULT_PROGRESS_EVERY_CHUNKS,
        metavar="N",
        help=(
            "Log elapsed time, bytes sent and bytes/sec every N data chunks "
            f"(default {_DEFAULT_PROGRESS_EVERY_CHUNKS}, 0 to disable). Makes "
            "a slow run diagnosable while it is running rather than after it "
            "has been abandoned"
        ),
    )
    _ = parser.add_argument(
        "--reference-transport",
        action="store_true",
        help=(
            "Drive calibration modes with the stabilized direct-open serial "
            "profile (timeout fixed to 0.25 at open, write_timeout 1, no "
            "exclusive lock, no explicit DTR, input+output buffers reset at "
            "open, and literal flush/tcdrain after every write). It opens at "
            "the operating baud and never reapplies the macOS custom-baud "
            "ioctl during the session. Real KEX writes always use this "
            "profile, so the flag is optional for them. It is rejected with "
            "--probe-only/--probe-target because those walk the keyed baud "
            "ladder."
        ),
    )
    return parser


def _flash_device_probe_mode(args: argparse.Namespace) -> bool:
    """Return whether a probe or SETUP calibration mode was selected."""
    return any(
        (
            args.probe_only,
            args.probe_target,
            args.setup_controls_only,
            args.setup_mismatch_repeat_only,
        )
    )


def _names_same_file(first: Path, second: Path) -> bool:
    """Return whether two paths reach the same existing file.

    Compares device and inode, so a symlink or hard link counts as the same
    file. A path that cannot be examined, such as a trace that does not exist
    yet, aliases nothing.
    """
    try:
        same = first.samefile(second)
    except OSError:
        return False
    return same


def _wire_trace_alias_error(wire_trace: Path) -> str:
    """Return the refusal for a ``--wire-trace`` path that is the input image."""
    return (
        "--wire-trace refuses to overwrite the input image, directly or "
        f"through a link: {wire_trace}"
    )


def _validate_flash_mode_exclusivity_and_qualification(
    args: argparse.Namespace, *, device_probe_mode: bool
) -> None:
    """Reject mutually exclusive modes and misused qualification flags."""
    if (
        sum(
            (
                args.probe_only,
                args.probe_target,
                args.setup_controls_only,
                args.setup_mismatch_repeat_only,
                args.dry_run,
            )
        )
        > 1
    ):
        _die(
            "--probe-only, --probe-target, --setup-controls-only, "
            "--setup-mismatch-repeat-only, and --dry-run are mutually exclusive",
        )
    if args.qualification_rewrite_stock_image_data and args.force_all_segments:
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} conflicts with "
            "--force-all-segments",
        )
    if args.qualification_rewrite_stock_image_data and (
        device_probe_mode or args.dry_run or args.raw
    ):
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} is valid only for a real "
            "write of the exact audited stock V1.03 KEX",
        )
    if args.qualification_rewrite_stock_image_data and args.wire_trace is None:
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} requires --wire-trace "
            "with a new evidence path",
        )
    if (
        args.qualification_rewrite_stock_image_data
        and args.wire_trace is not None
        and args.wire_trace.exists()
    ):
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} refuses to replace "
            f"existing --wire-trace evidence: {args.wire_trace}",
        )
    if (
        args.wire_trace is not None
        and args.input is not None
        and _names_same_file(args.wire_trace, args.input)
    ):
        # The trace opens with truncation after the prompt; aliasing the
        # input would destroy the artifact being flashed.
        _die(_wire_trace_alias_error(args.wire_trace))
    if args.force_all_segments and not args.dry_run:
        # Keep the hardware profile identical to the successful control. This
        # gate precedes USB-port resolution; _run_flash repeats it for direct
        # callers before reading the image or constructing a transport.
        _die(_FORCE_ALL_SEGMENTS_DRY_RUN_ERROR)


def _validate_flash_setup_and_ack_flags(
    args: argparse.Namespace, *, device_probe_mode: bool
) -> None:
    """Reject SETUP-repeat and write-acknowledgement flags out of context."""
    if args.allow_unproven_setup_repeat and not args.setup_mismatch_repeat_only:
        _die(
            "--allow-unproven-setup-repeat is valid only with "
            "--setup-mismatch-repeat-only",
        )
    if args.setup_mismatch_repeat_only and not args.allow_unproven_setup_repeat:
        _die(
            "--setup-mismatch-repeat-only requires --allow-unproven-setup-repeat",
        )
    if args.acknowledge_service_9r_write and (
        device_probe_mode or args.dry_run or args.raw
    ):
        _die(
            "--acknowledge-service-9r-write is valid only for a real write of "
            "the exact service-9r-nor-read plaintext KEX",
        )
    if args.acknowledge_gm_ddr_read_write and (
        device_probe_mode or args.dry_run or args.raw
    ):
        _die(
            "--acknowledge-gm-ddr-read-write is valid only for a real write of "
            "the exact normal-gm-ddr-read plaintext KEX",
        )
    if args.acknowledge_gm_nor_read_write and (
        device_probe_mode or args.dry_run or args.raw
    ):
        _die(
            "--acknowledge-gm-nor-read-write is valid only for a real write of "
            "the exact normal-gm-nor-read family plaintext KEX",
        )


def _validate_flash_trace_input_and_transport_flags(
    args: argparse.Namespace, *, device_probe_mode: bool
) -> None:
    """Reject trace, input, port and transport flags out of context."""
    if args.wire_trace is not None and (device_probe_mode or args.dry_run):
        # A dry run sends nothing, and the probe paths build their own
        # sessions. Refusing beats writing a file with a two-line header and
        # no frames, which reads like a flash that never got started.
        _die(
            "--wire-trace records a real flash; it is not valid with --dry-run "
            "or the probe/SETUP calibration modes",
        )
    if device_probe_mode and args.input is not None:
        _die("probe/SETUP calibration modes do not accept an input image")
    if not device_probe_mode and args.input is None:
        _die(
            "input KEX path required (or select a probe/SETUP calibration mode)",
        )
    if (device_probe_mode or not args.dry_run) and args.port is None:
        _die("--port is required for probes, SETUP calibration, and real flashes")
    if (
        not device_probe_mode
        and not args.dry_run
        and args.chunk_size not in _WRITABLE_CHUNK_SIZES
    ):
        _die(
            f"hardware writes require --chunk-size {_DEFAULT_CHUNK_SIZE}, the "
            "profile proven by two complete D75 stock restores; "
            f"got {args.chunk_size}. Use --dry-run to inspect other sizes"
        )
    if args.reference_transport and (args.probe_only or args.probe_target):
        _die(
            "--reference-transport cannot be combined with --probe-only or "
            "--probe-target: those modes walk the keyed baud ladder, and the "
            "direct-open transport opens the port once at its operating baud "
            "and refuses to reconfigure a live port",
        )
    if (
        args.reference_transport
        and not device_probe_mode
        and not args.dry_run
        and not args.cleartext
    ):
        _die(
            "--reference-transport requires --cleartext: the encrypted unlock "
            "path walks the baud ladder, which the direct-open transport refuses",
        )


def _validate_flash_raw_flags(args: argparse.Namespace) -> None:
    """Reject raw-profile flags that are absent, out of range, or misused."""
    if args.raw and args.flash_addr is None:
        _die("--raw requires --flash-addr (e.g. --flash-addr 0x00200000)")
    if args.raw and args.flash_addr != flash.segments.MAIN_FIRMWARE_REGION_START:
        _die(
            "the audited D75 raw profile requires --flash-addr 0x00200000; "
            "writes to the bootloader or any other NOR region are not supported"
        )
    if args.raw and args.complete_code is None:
        _die("--raw requires explicit --complete-code 0x1DB0")
    if (
        args.raw
        and args.complete_code != flash.session.FlashSession.D75_V103_COMPLETE_CODE
    ):
        _die("the audited D75 V1.03 raw profile only permits --complete-code 0x1DB0")
    if not args.raw and args.complete_code is not None:
        _die("--complete-code is only valid with --raw; KEX mode uses required #FC")


def _resolve_enumerated_port(port: str | None) -> str:
    """Return the enumerated FLDM port, requiring ``--port`` to be set.

    The mode gates guarantee a port for every device mode, so a missing
    value here is an internal invariant rather than operator error.
    """
    if port is None:
        msg = "device modes require --port"
        raise AssertionError(msg)
    return _require_fldm_usb_port(port)


def _dispatch_flash(args: argparse.Namespace) -> None:
    """Run the selected probe, SETUP calibration, or flash operation."""
    try:
        if args.probe_only:
            fldm_port = _resolve_enumerated_port(args.port)
            _run_flash_probe(fldm_port, args.baud_ladder)
            return
        if args.probe_target:
            fldm_port = _resolve_enumerated_port(args.port)
            _run_flash_probe_target(fldm_port, args.baud_ladder)
            return
        if args.setup_controls_only:
            fldm_port = _resolve_enumerated_port(args.port)
            _run_setup_calibration(
                fldm_port,
                mismatch_repeat=False,
                reference_transport=args.reference_transport,
            )
            return
        if args.setup_mismatch_repeat_only:
            fldm_port = _resolve_enumerated_port(args.port)
            _run_setup_calibration(
                fldm_port,
                mismatch_repeat=True,
                reference_transport=args.reference_transport,
            )
            return
        if args.input is None:
            msg = "input KEX path required"
            raise AssertionError(msg)
        flash_port = None if args.dry_run else _require_fldm_usb_port(args.port or "")
        _run_flash(
            _FlashRequest(
                input_path=args.input,
                port=flash_port,
                baud_ladder_text=args.baud_ladder,
                skip_prompt=args.yes,
                dry_run=args.dry_run,
                show_post_hint=not args.no_post_hint,
                chunk_size=args.chunk_size,
                raw=args.raw,
                flash_addr=args.flash_addr,
                raw_complete_code=args.complete_code,
                single_segment=args.single_segment,
                cleartext_unlock=args.cleartext,
                cleartext_baud=args.cleartext_baud,
                acknowledge_service_9r_write=args.acknowledge_service_9r_write,
                acknowledge_gm_ddr_read_write=args.acknowledge_gm_ddr_read_write,
                acknowledge_gm_nor_read_write=args.acknowledge_gm_nor_read_write,
                force_all_segments=args.force_all_segments,
                qualification_rewrite_stock_image_data=(
                    args.qualification_rewrite_stock_image_data
                ),
                reference_transport=args.reference_transport or not args.dry_run,
                wire_trace_path=args.wire_trace,
                progress_every_chunks=args.progress_every,
            )
        )
    except FileNotFoundError as exc:
        _die(f"file not found: {exc.filename}")
    except ValueError as exc:
        _die(f"invalid flash plan: {exc}")


def main_flash() -> None:
    """Flash a TH-D75 firmware .KEX to a connected radio.

    Speaks the Kenwood FLDM serial protocol (the same one the official
    .NET updater uses). Cross-platform replacement for the Windows-only
    Kenwood updater. See the flasher design spec for the full protocol
    reference and the staged hardware-bring-up plan.
    """
    parser = _build_flash_parser()
    args = parser.parse_args()
    device_probe_mode = _flash_device_probe_mode(args)
    _validate_flash_mode_exclusivity_and_qualification(
        args, device_probe_mode=device_probe_mode
    )
    _validate_flash_setup_and_ack_flags(args, device_probe_mode=device_probe_mode)
    _validate_flash_trace_input_and_transport_flags(
        args, device_probe_mode=device_probe_mode
    )
    _validate_flash_raw_flags(args)
    _dispatch_flash(args)


def _parse_baud_ladder(text: str | None) -> tuple[int, ...]:
    if text is None:
        return flash.handshake.BAUD_LADDER
    try:
        return tuple(int(b.strip()) for b in text.split(","))
    except ValueError as exc:
        _die(f"invalid --baud-ladder {text!r}: {exc}")


def _parse_progress_every(raw: str) -> int:
    """Argparse converter for the data-phase progress interval."""
    try:
        value = int(raw, 0)
    except ValueError as exc:
        msg = f"progress interval must be an integer: {raw!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    if value < 0:
        msg = f"progress interval must be >= 0 (0 disables), got {value}"
        raise argparse.ArgumentTypeError(msg)
    return value


def _parse_chunk_size(raw: str) -> int:
    """Argparse converter for the loader's bounded chunk size."""
    try:
        value = int(raw, 0)
    except ValueError as exc:
        msg = f"chunk size must be an integer: {raw!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    max_size = flash.session.FlashSession.MAX_CHUNK_SIZE
    if not 1 <= value <= max_size:
        msg = f"chunk size must be 1..{max_size}, got {value}"
        raise argparse.ArgumentTypeError(msg)
    return value


def _extract_fc_tag(kex_image: kex.Kex) -> int:
    """Return the KEX file's top-level ``#FC=`` completion value.

    Stock V1.03's value is ``0x1DB0``. KEX mode passes it to
    ``FlashSession`` with the official two-byte width; the separately gated
    raw profile uses the locally tested four-byte encoding of the same value.

    The line itself appears in the top-level KEX metadata, which our
    parser currently stores inside the first block's metadata list
    (the ``#FC=`` line precedes the ``$ST`` segment-start marker, so
    everything between the file's start and ``$ED`` of the first
    block lives in ``blocks[0].metadata``).

    Raises:
        ValueError: If no valid value exists. A missing completion
            code must stop preflight rather than silently becoming zero.

    """
    for block in kex_image.blocks:
        for raw_line in block.metadata:
            # KEX parser stores metadata as raw bytes (each line
            # comes off the wire with byte semantics; we decode
            # liberally here because the file may contain non-ASCII
            # in surrounding comment lines).
            line_text = raw_line.decode("latin-1", errors="replace").strip()
            if not line_text.startswith("#FC="):
                continue
            value_str = line_text[4:].strip()
            try:
                return (
                    int(value_str, 16)
                    if value_str.lower().startswith("0x")
                    else int(value_str)
                )
            except ValueError:
                # Malformed; fall through to keep scanning in case
                # a later block has a usable line.
                continue
    msg = "KEX metadata has no valid #FC completion value"
    raise ValueError(msg)


def _collect_kex_metadata(kex_image: kex.Kex) -> dict[str, list[str]]:
    """Collect every ``#TAG=value`` line's values, keyed by tag.

    A tag may repeat across blocks, so each maps to the list of its values in
    encounter order. The vendor tag parser ignores an optional trailing
    ``;`` comment, so this strips it too.
    """
    values: dict[str, list[str]] = {}
    for block in kex_image.blocks:
        for raw_line in block.metadata:
            line = raw_line.decode("latin-1", errors="replace").strip()
            if not line.startswith("#") or "=" not in line:
                continue
            tag, _, raw_value = line[1:].partition("=")
            value = raw_value.split(";", 1)[0].strip()
            values.setdefault(tag, []).append(value)
    return values


def _require_one_metadata(values: dict[str, list[str]], tag: str) -> str:
    """Return the single value of ``#tag``, or raise if absent or conflicting.

    Raises:
        ValueError: If the tag is missing, or carries more than one distinct
            value.

    """
    found = values.get(tag, [])
    if not found:
        msg = f"KEX metadata is missing required #{tag}"
        raise ValueError(msg)
    distinct = set(found)
    if len(distinct) != 1:
        msg = f"KEX has conflicting #{tag} values: {found!r}"
        raise ValueError(msg)
    return found[0]


def _require_int_metadata(values: dict[str, list[str]], tag: str) -> int:
    """Return the single value of ``#tag`` parsed as an integer.

    Raises:
        ValueError: If the tag is missing, conflicting, or not an integer.

    """
    text = _require_one_metadata(values, tag)
    try:
        return int(text, 0)
    except ValueError as exc:
        msg = f"KEX #{tag} is not an integer: {text!r}"
        raise ValueError(msg) from exc


def _validate_d75_v103_kex_profile(kex_image: kex.Kex) -> bool:
    """Validate every top-level field the current session hard-codes.

    The direct flasher is locked to the stock D75 V1.03 profile proven by the
    retained OpenWood controls. Rejecting absent or different metadata is
    safer than silently applying TC/TU/baud/force assumptions from another
    update package. The transport-ordering repair completed this exact stock
    profile on hardware on 2026-07-26.

    Returns:
        The parsed ``#AF`` force-write policy.

    Raises:
        ValueError: If any required field is absent, conflicting, or not the
            audited D75 V1.03 value.

    """
    values = _collect_kex_metadata(kex_image)

    expected_ints = {
        "TC": 0,
        "TU": 1,
        "FC": flash.session.FlashSession.D75_V103_COMPLETE_CODE,
    }
    for tag, expected in expected_ints.items():
        actual = _require_int_metadata(values, tag)
        if actual != expected:
            msg = (
                f"unsupported KEX #{tag}=0x{actual:X}; D75 V1.03 profile "
                f"requires 0x{expected:X}"
            )
            raise ValueError(msg)

    always_flash_raw = _require_int_metadata(values, "AF")
    if always_flash_raw not in (0, 1):
        msg = f"KEX #AF must be 0 or 1, got {always_flash_raw}"
        raise ValueError(msg)

    declared_segments = _require_int_metadata(values, "DN")
    if declared_segments != len(kex_image.blocks):
        msg = (
            f"KEX #DN={declared_segments} but parser found "
            f"{len(kex_image.blocks)} segments"
        )
        raise ValueError(msg)
    if declared_segments != _D75_V103_SEGMENT_COUNT:
        msg = (
            f"unsupported KEX segment count {declared_segments}; "
            "audited D75 V1.03 profile has 7"
        )
        raise ValueError(msg)

    firmware_version = _require_one_metadata(values, "FV")
    if firmware_version != '"V1.03.000      "':
        msg = f"unsupported KEX #FV={firmware_version!r}; expected D75 V1.03"
        raise ValueError(msg)

    baud_profiles = set(values.get("BR", []))
    if "576000,1" not in baud_profiles:
        msg = "KEX lacks required #BR=576000,1 transfer profile"
        raise ValueError(msg)

    return bool(always_flash_raw)


def _stock_image_data_qualification_target(
    *,
    rendered_plaintext_sha256: str,
    segments: list[flash.segments.SegmentDescriptor],
    segment_data: dict[int, bytes],
    chunk_size: int,
) -> str:
    """Validate and describe the one selectively forced hardware segment."""
    flag = _STOCK_IMAGE_DATA_QUALIFICATION_FLAG
    if rendered_plaintext_sha256 != _OFFICIAL_V103_PLAINTEXT_KEX_SHA256:
        _die(
            f"{flag} requires the exact audited stock V1.03 rendered KEX hash "
            f"{_OFFICIAL_V103_PLAINTEXT_KEX_SHA256}; got "
            f"{rendered_plaintext_sha256}",
        )
    if len(segments) != _D75_V103_SEGMENT_COUNT:
        _die(
            f"{flag} requires the exact 7-segment stock V1.03 layout; "
            f"parsed {len(segments)} segments",
        )

    index = _STOCK_IMAGE_DATA_QUALIFICATION_INDEX
    descriptor = segments[index]
    section_info = None
    if descriptor.flash_start_addr >= int(FLASH_BASE):
        section_info = lookup_by_address(
            FlashAddress(descriptor.flash_start_addr - int(FLASH_BASE))
        )
    section_name = "<unknown>" if section_info is None else section_info.name
    actual_descriptor = (
        section_name,
        descriptor.flash_start_addr,
        descriptor.data_length,
        descriptor.erase_length,
        descriptor.checksum_length,
    )
    if actual_descriptor != _STOCK_IMAGE_DATA_QUALIFICATION_DESCRIPTOR:
        expected = _STOCK_IMAGE_DATA_QUALIFICATION_DESCRIPTOR
        _die(
            f"{flag} requires segment {index} {expected[0]} with "
            f"start=0x{expected[1]:08X}, data_length={expected[2]}, "
            f"erase_length={expected[3]}, checksum_length={expected[4]}; got "
            f"name={section_name}, start=0x{descriptor.flash_start_addr:08X}, "
            f"data_length={descriptor.data_length}, "
            f"erase_length={descriptor.erase_length}, "
            f"checksum_length={descriptor.checksum_length}",
        )

    payload = segment_data.get(index)
    if payload is None:
        _die(f"{flag} requires the retained segment {index} IMAGE_DATA payload")
    transmitted_payload = payload[: descriptor.data_length]
    payload_sha256 = hashlib.sha256(transmitted_payload).hexdigest()
    if payload_sha256 != _STOCK_IMAGE_DATA_QUALIFICATION_PAYLOAD_SHA256:
        _die(
            f"{flag} requires retained IMAGE_DATA payload SHA-256 "
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_PAYLOAD_SHA256}; got "
            f"{payload_sha256}",
        )

    effective_chunk_size = min(
        chunk_size,
        descriptor.chunk_size or chunk_size,
    )
    packet_count = descriptor.data_length // effective_chunk_size
    return (
        f"segment {index} IMAGE_DATA: {descriptor.data_length} bytes, "
        f"{packet_count} packets, payload_sha256={payload_sha256}"
    )


def _normal_gm_fast_flash_plan(
    *,
    rendered_plaintext_sha256: str,
    segments: list[flash.segments.SegmentDescriptor],
    segment_data: dict[int, bytes],
) -> tuple[
    list[flash.segments.SegmentDescriptor],
    dict[int, bytes],
    tuple[int, ...],
]:
    """Omit the pinned stock DATA_0160 block from the exact normal-GM plan.

    This is update semantics, not recovery semantics. The exact normal-GM KEX
    changes only main FIRMWARE; stock recovery deliberately keeps its complete
    seven-segment plan. Fail closed if the artifact classification, layout,
    descriptor, or transmitted DATA_0160 bytes drift.

    Returns:
        Reindexed descriptors and payloads plus each entry's original KEX
        source index. The source-index tuple keeps dry-run output explicit
        after pruning.

    """
    if rendered_plaintext_sha256 not in _NORMAL_GM_FAST_PLAINTEXT_KEX_SHA256:
        admitted_hashes = ", ".join(sorted(_NORMAL_GM_FAST_PLAINTEXT_KEX_SHA256))
        _die(
            "normal-GM fast flash requires an exact audited DDR/NOR rendered "
            f"KEX hash ({admitted_hashes}); got "
            f"{rendered_plaintext_sha256}",
        )
    if len(segments) != _D75_V103_SEGMENT_COUNT:
        _die(
            "normal-GM fast flash requires the exact seven-segment V1.03 "
            f"layout; parsed {len(segments)} segments",
        )
    expected_data_indices = set(range(len(segments)))
    if set(segment_data) != expected_data_indices:
        _die(
            "normal-GM fast flash requires payloads for exactly source "
            f"segments 0..6; got {sorted(segment_data)}",
        )

    omitted_index = _NORMAL_GM_FAST_OMIT_INDEX
    descriptor = segments[omitted_index]
    descriptor_bytes = descriptor.to_recovery_wire()
    if descriptor_bytes != _NORMAL_GM_FAST_DATA_0160_DESCRIPTOR:
        _die(
            "normal-GM fast flash refuses changed DATA_0160 descriptor: "
            f"expected {_NORMAL_GM_FAST_DATA_0160_DESCRIPTOR.hex()}, got "
            f"{descriptor_bytes.hex()}",
        )

    payload = segment_data.get(omitted_index)
    if payload is None:
        _die("normal-GM fast flash requires source segment 3 DATA_0160")
    transmitted_payload = payload[: descriptor.data_length]
    payload_sha256 = hashlib.sha256(transmitted_payload).hexdigest()
    if payload_sha256 != _NORMAL_GM_FAST_DATA_0160_PAYLOAD_SHA256:
        _die(
            "normal-GM fast flash refuses changed DATA_0160 payload: expected "
            f"{_NORMAL_GM_FAST_DATA_0160_PAYLOAD_SHA256}, got {payload_sha256}",
        )

    source_indices = tuple(
        index for index in range(len(segments)) if index != omitted_index
    )
    pruned_segments = [segments[index] for index in source_indices]
    pruned_data = {
        plan_index: segment_data[source_index]
        for plan_index, source_index in enumerate(source_indices)
    }
    return pruned_segments, pruned_data, source_indices


def _open_flash_transport(
    port: str,
    *,
    baud: int,
    reference_transport: bool,
) -> flash.serial_io.SerialIO | flash.serial_io.ReferenceSerialIO:
    """Open the FLDM transport the operator selected.

    Real writes require ``reference_transport=True``. Probe/calibration callers
    may still select the legacy transport for controlled diagnostics. Callers
    pass the baud the session will actually run at because the reference
    transport refuses to reconfigure a live port.
    """
    if reference_transport:
        # The timeout is fixed when the port opens. Reassigning that same
        # value before every low-level ACK read makes pyserial reapply the
        # macOS IOSSIOSPEED custom-baud ioctl tens of thousands of times
        # during one main-firmware transfer. It contributes no timeout or
        # framing semantics and leaves a residual baud-reconfiguration race
        # even after write()+tcdrain(). Keep the proven direct-open,
        # write/drain, staged-read profile while leaving the established
        # 576000 baud untouched for the complete session.
        return flash.serial_io.ReferenceSerialIO(
            port,
            baud=baud,
            options=flash.serial_io.ReferenceSerialOptions(reassert_read_timeout=False),
        )
    return flash.serial_io.SerialIO(port, baud=baud, timeout=1.0)


def _run_flash_probe(port: str, baud_ladder_text: str | None) -> None:
    """Probe-only mode: handshake (unlock) only, then disconnect."""
    _log(f"TH-D75 Flasher Probe\n  Port: {port}")
    try:
        with flash.serial_io.SerialIO(port, baud=9600, timeout=1.0) as transport:
            result = flash.handshake.perform_handshake(
                transport,
                baud_ladder=_parse_baud_ladder(baud_ladder_text),
            )
            _log(
                f"  handshake at baud {result.baud}, XOR key 0x{result.xor_key:02X}",
            )
    except flash.serial_io.SerialCloseError as exc:
        _die(f"probe transport close failure: {exc}", code=3)
    except flash.handshake.HandshakeError as exc:
        _die(f"handshake failed: {exc}", code=3)
    except OSError as exc:
        _die(f"probe transport failed: {type(exc).__name__}: {exc}", code=3)
    finally:
        _log(
            "MANDATORY: disconnect USB and fully power-cycle the radio before "
            "constructing any new FLDM session.",
        )


def _run_flash_probe_target(port: str, baud_ladder_text: str | None) -> None:
    """Deep probe: handshake + ordered FLDM entry + QUERY_TARGET."""
    _log(f"TH-D75 Flasher Probe (deep)\n  Port: {port}")
    try:
        with flash.serial_io.SerialIO(port, baud=9600, timeout=1.0) as transport:
            session = flash.session.FlashSession(transport)
            target = session.probe_target_only(
                baud_ladder=_parse_baud_ladder(baud_ladder_text),
            )
        # Preserve the byte roles the official D75 host actually uses. It
        # consumes bytes 0..7 for #TT/$TT compatibility, ignores bytes 8..15,
        # and separately consumes byte 16. D74's <QQB> field names are not D75
        # evidence and must not be projected onto this response.
        _log(
            f"  target mask bytes:   {target.target_mask_bytes.hex(' ')}",
        )
        _log(
            f"  opaque bytes 8..15:  {target.opaque_bytes_8_15.hex(' ')}",
        )
        _log(f"  trailing status:     0x{target.trailing_status:02X}")
        _log(f"  raw payload (17 B):  {target.raw_payload.hex(' ')}")
        # Sanity-check against the known-good D75 V1.03 baseline.
        if target.matches_d75_v103():
            _log("  match:               OK — stock D75 V1.03 values")
        else:
            _log("  match:               MISMATCH — radio is NOT a stock D75 V1.03:")
            for reason in target.d75_mismatch_reasons():
                _log(f"    - {reason}")
            _log(
                "  Do not flash. Mismatches can indicate a different model, "
                "a different firmware version, or a fault; the real flash "
                "preflight rejects them.",
            )
    except flash.serial_io.SerialCloseError as exc:
        _die(f"deep probe transport close failure: {exc}", code=3)
    except flash.handshake.HandshakeError as exc:
        _die(f"handshake failed: {exc}", code=3)
    except flash.session.FlashError as exc:
        _die(
            f"deep probe failed:\n\n{_render_flash_error(exc)}",
            code=3,
        )
    except TimeoutError as exc:
        # Raised by FlashSession._read_one_response when a framed
        # command goes unanswered. Surface cleanly with diagnostic
        # context (which step we were on) so the operator knows
        # which verb the radio refused to answer.
        _die(
            f"deep probe: no response from radio after handshake "
            f"({exc}). Most likely the radio is in a state that "
            f"doesn't accept the next framed verb (ENTER_PROGRAM). "
            f"Power-cycle radio to clean FPM and report which verb.",
            code=3,
        )
    except OSError as exc:
        _die(f"deep probe transport failed: {type(exc).__name__}: {exc}", code=3)
    finally:
        _log(
            "MANDATORY: disconnect USB and fully power-cycle the radio before "
            "constructing any new FLDM session.",
        )


def _run_setup_calibration(
    port: str,
    *,
    mismatch_repeat: bool,
    reference_transport: bool = False,
) -> None:
    """Run one exact, single-use USB-C SETUP calibration plan."""
    label = "mismatch/repeat" if mismatch_repeat else "positive controls"
    _log(
        f"TH-D75 SETUP calibration ({label})\n"
        f"  Port: {port}\n"
        "  Transport: USB-C FLDM, cleartext FPROMOD at 576000\n"
        "  Host verbs: ENTER, TIMED, QUERY, BAUD, fixed SETUP only\n"
        "  No known erase/program/finalization verb will be sent.\n"
        "  Target-side SETUP nonmutation is not proven.",
    )
    if reference_transport:
        # Cheapest hardware A/B available: the calibration modes exercise
        # unlock, entry ordering, and framed round-trips without sending any
        # erase/program/finalization verb.
        _log(
            "  Transport variant: stabilized direct-open profile "
            "(--reference-transport)"
        )
    attempted = False
    try:
        attempted = True
        # The calibration session runs entirely at 576000, so opening there
        # leaves the direct-open transport nothing to reconfigure.
        with _open_flash_transport(
            port,
            baud=576_000,
            reference_transport=reference_transport,
        ) as transport:
            session = flash.session.FlashSession(transport)
            outcome = (
                session.calibrate_setup_mismatch_repeat_only()
                if mismatch_repeat
                else session.calibrate_setup_controls_only()
            )
        _log(f"  target bytes: {outcome.target.raw_payload.hex(' ')}")
        _log(f"  SETUP results: {outcome.setup_results!r}")
        _log("  calibration result: PASS")
    except flash.serial_io.SerialCloseError as exc:
        _die(f"SETUP calibration transport close failure: {exc}", code=3)
    except flash.session.FlashError as exc:
        _die(
            f"SETUP calibration failed at {exc.step}: {exc.cause} "
            f"(recoverable={exc.recoverable})",
            code=3,
        )
    except OSError as exc:
        _die(f"SETUP calibration transport failed: {exc}", code=3)
    finally:
        if attempted:
            _log(
                "MANDATORY: disconnect USB and fully power-cycle the radio before "
                "constructing any new FLDM session.",
            )


# NOTE: _run_flash_probe_entry_sequence was removed because a probe
# must not pretend to rehearse the destructive session state machine.
# --probe-target intentionally stops after target identification.


@dataclass(frozen=True, slots=True, kw_only=True)
class _FlashRequest:
    """One resolved ``thd75-flash`` request, as ``main_flash`` assembles it.

    Groups every input :func:`_run_flash` consumes so the argument list stays
    within the project's ceiling. Defaults match the argparse defaults.

    Attributes:
        input_path: The ``.KEX`` image, or the flat ``.bin`` under ``raw``.
        port: Enumerated TH-D75 USB node, or ``None`` for an offline dry run.
        baud_ladder_text: ``--baud-ladder`` override, or ``None``.
        skip_prompt: ``--yes``: skip the pre-flash operator confirmation.
        dry_run: Validate and print the plan offline; open no device.
        show_post_hint: Print the post-flash Full Reset reminder on success.
        chunk_size: SEND_CHUNK payload ceiling.
        raw: Treat ``input_path`` as a flat binary, not a ``.KEX``.
        flash_addr: NOR address modeled in the ``--raw`` plan, or ``None``.
        raw_complete_code: ``--complete-code`` for the raw profile, or ``None``.
        single_segment: Resolve ``--raw`` as one diagnostic segment.
        cleartext_unlock: Use the cleartext ``FPROMOD`` unlock path.
        cleartext_baud: Baud the port opens at under ``cleartext_unlock``.
        acknowledge_service_9r_write: Dedicated service-9R write gate.
        acknowledge_gm_ddr_read_write: Dedicated normal-gm-ddr-read write gate.
        acknowledge_gm_nor_read_write: Dedicated normal-gm-nor-read write gate.
        force_all_segments: Model the vendor ``#AF=1`` force policy (dry-run).
        qualification_rewrite_stock_image_data: Selective IMAGE_DATA rewrite.
        reference_transport: Drive the stabilized direct-open serial profile.
        wire_trace_path: Where to record the frame trace, or ``None``.
        progress_every_chunks: Throughput-line cadence; 0 disables it.

    """

    input_path: Path
    port: str | None
    baud_ladder_text: str | None
    skip_prompt: bool
    dry_run: bool
    show_post_hint: bool
    chunk_size: int
    raw: bool
    flash_addr: int | None
    raw_complete_code: int | None = None
    single_segment: bool = False
    cleartext_unlock: bool = False
    cleartext_baud: int = _PROVEN_CLEARTEXT_BAUD
    acknowledge_service_9r_write: bool = False
    acknowledge_gm_ddr_read_write: bool = False
    acknowledge_gm_nor_read_write: bool = False
    force_all_segments: bool = False
    qualification_rewrite_stock_image_data: bool = False
    reference_transport: bool = True
    wire_trace_path: Path | None = None
    progress_every_chunks: int = _DEFAULT_PROGRESS_EVERY_CHUNKS


@dataclass(frozen=True, slots=True, kw_only=True)
class _FlashPlan:
    """The resolved segment plan and its provenance, shared between phases.

    Built once by :func:`_build_flash_plan` and then read by the dry-run
    report, the acknowledgement gates, and the hardware write.

    Attributes:
        segments: Descriptors in transmit order.
        segment_data: Flat payload bytes per plan-segment index.
        source_segment_indices: Each plan segment's original KEX index, kept
            explicit after any pruning so the dry-run report can show it.
        complete_update_value: Numeric ``#FC`` completion code.
        complete_update_width: COMPLETE_UPDATE payload width in bytes.
        always_flash: The resolved ``#AF`` force policy.
        qualification_force_indices: Segment indices force-written despite a
            "current" SETUP result.
        qualification_mode: Qualification label for the banner, or ``None``.
        qualification_target: Qualification target description, or ``None``.
        audited_kex_label: Audited-artifact label, or ``None`` when unpinned.
        image_sha256: Digest of the bytes this run would transmit, or ``None``.
        host_omission: Fast-plan omission note, or ``None``.
        is_service_9r_image: The rendered KEX is the exact service-9R artifact.
        is_gm_ddr_image: The rendered KEX is the exact normal-gm-ddr-read one.
        is_gm_nor_image: The rendered KEX is in the normal-gm-nor-read family.
        is_gm_nor_usb_recover_image: The rendered KEX is the V18 recovery one.
        is_azimuth_image: The rendered KEX is an admitted Azimuth automation
            image, with or without the orange-on-black theme.

    """

    segments: list[flash.segments.SegmentDescriptor]
    segment_data: dict[int, bytes]
    source_segment_indices: tuple[int, ...]
    complete_update_value: int
    complete_update_width: int
    always_flash: bool
    qualification_force_indices: frozenset[int] = frozenset()
    qualification_mode: str | None = None
    qualification_target: str | None = None
    audited_kex_label: str | None = None
    image_sha256: str | None = None
    host_omission: str | None = None
    is_service_9r_image: bool = False
    is_gm_ddr_image: bool = False
    is_gm_nor_image: bool = False
    is_gm_nor_usb_recover_image: bool = False
    is_azimuth_image: bool = False


def _log_flash_intro(request: _FlashRequest) -> None:
    """Log the flasher banner lines before any plan work."""
    _log("TH-D75 Firmware Flasher")
    _log(f"  Image: {request.input_path}{' (raw .bin)' if request.raw else ''}")
    if request.port is not None:
        _log(f"  Port:  {request.port}")
    if request.reference_transport:
        _log("  Transport: stabilized direct-open 576000 profile")
    if request.dry_run:
        _log("  DRY RUN: offline validation only; no device I/O")


def _check_qualification_and_force_gates(request: _FlashRequest) -> None:
    """Reject conflicting qualification/force flags before any plan work."""
    if request.qualification_rewrite_stock_image_data and request.force_all_segments:
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} conflicts with "
            "--force-all-segments",
        )
    if request.qualification_rewrite_stock_image_data and (
        request.dry_run or request.raw
    ):
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} is valid only for a real "
            "write of the exact audited stock V1.03 KEX",
        )
    if (
        request.qualification_rewrite_stock_image_data
        and request.wire_trace_path is None
    ):
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} requires --wire-trace "
            "with a new evidence path",
        )
    if (
        request.qualification_rewrite_stock_image_data
        and request.wire_trace_path is not None
        and request.wire_trace_path.exists()
    ):
        _die(
            f"{_STOCK_IMAGE_DATA_QUALIFICATION_FLAG} refuses to replace "
            f"existing --wire-trace evidence: {request.wire_trace_path}",
        )
    if request.wire_trace_path is not None and _names_same_file(
        request.wire_trace_path, request.input_path
    ):
        _die(_wire_trace_alias_error(request.wire_trace_path))
    if request.force_all_segments and not request.dry_run:
        _die(_FORCE_ALL_SEGMENTS_DRY_RUN_ERROR)


def _build_raw_flash_plan(request: _FlashRequest) -> _FlashPlan:
    """Resolve a flat-binary ``--raw`` request into a segment plan.

    Raises:
        ValueError: If ``raw_complete_code`` is absent (checked in
            ``main_flash`` before ``_run_flash``).

    """
    # Flat-binary path: synthesize a single SegmentDescriptor in
    # memory, no .KEX parsing. Used for custom payloads built
    # outside the official updater (e.g. the firmware/dumper).
    flash_addr = request.flash_addr
    if flash_addr is None:  # checked in main_flash before _run_flash
        msg = "raw flash requires --flash-addr"
        raise ValueError(msg)
    input_image = request.input_path.read_bytes()
    # Pad the transmitted flash payload with erased bytes so no short
    # final packet is generated: the loader's handling of a below-$DU
    # packet is unproven, and every stock segment length divides its own
    # $DU exactly, so a short packet is a shape the radio has never been
    # shown. The stock-style CHECKBYTES and FINAL_ZZZ overlays carry their
    # own $DU and remain exact packets.
    #
    # This padded to whatever ``chunk_size`` is, but justified itself with
    # "real D75 success is established only for equal 256-byte body
    # packets". That is not established, and the code never depended on it:
    # padding to the packet size in use is what avoids the short final
    # packet, whatever that size is.
    padding = (-len(input_image)) % request.chunk_size
    image = input_image + b"\xff" * padding
    input_sha256 = hashlib.sha256(input_image).hexdigest()
    flash_sha256 = hashlib.sha256(image).hexdigest()
    _log(f"  Input SHA-256: {input_sha256}")
    _log(f"  Padded final-image SHA-256: {flash_sha256}")
    if padding:
        _log(
            f"  Packet padding: {len(input_image):,} + {padding} erased "
            f"bytes = {len(image):,} ({request.chunk_size}-byte aligned)",
        )
    erase_span = flash.segments.d75_v103_raw_erase_span(len(image))
    try:
        flash.segments.validate_main_firmware_region(
            flash_addr,
            erase_span,
        )
    except flash.segments.BootloaderRegionError as exc:
        _die(str(exc))
    end_addr = flash_addr + len(image)
    _log(
        f"  Region: 0x{flash_addr:08X}..0x{end_addr:08X} "
        f"({len(image):,} transmitted bytes) — main-firmware slot "
        "(protected low-NOR candidate untouched)",
    )
    _log(
        f"  Erase/check span: 0x{flash_addr:08X}.."
        f"0x{flash_addr + erase_span:08X} ({erase_span:,} bytes; "
        "exact stock-V1.03 main envelope)",
    )

    # The CLI accepts ``--flash-addr`` as a NOR-relative offset
    # (the way users think of it: "0x00200000 = main-firmware
    # slot"), but the descriptor on the wire needs the
    # CPU-visible address — the OMAP-L138 maps NOR through its
    # EMIFA chip-select at base ``FLASH_BASE = 0x60000000``, so
    # every $SA field in the stock V1.03 KEX is of the form
    # ``0x602xxxxx`` etc. The radio accepted ``0x00200000`` in
    # earlier hardware tests (the loader appears to mask off the
    # high bits internally), but sending the CPU-visible form
    # matches the vendor pattern exactly and removes any ambiguity
    # about how the loader interprets the address.
    wire_flash_addr = flash_addr + FLASH_BASE

    # Raw mode uses the explicit D75 V1.03 hardware-tested profile:
    # numeric code 0x1DB0 encoded as LE u32. No automatic D74 fallback.
    if request.raw_complete_code is None:
        msg = "raw flash requires an explicit completion code"
        raise ValueError(msg)

    # Default: reproduce the vendor's finalization order: body with
    # 0x40..0x7f erased, CHECKBYTES overlay, FINAL_ZZZ overlay last.
    # --single-segment exists for offline descriptor diagnostics only.
    if request.single_segment:
        segments = [
            flash.segments.SegmentDescriptor.for_flat_image(
                flash_start_addr=wire_flash_addr,
                image=image,
            ),
        ]
        segment_data = {0: image}
        _log("  Flash strategy: single segment (offline diagnostic only)")
    else:
        pairs = flash.segments.split_for_safe_zzz_flash(
            flash_start_addr=wire_flash_addr,
            image=image,
        )
        segments = [desc for desc, _ in pairs]
        segment_data = {idx: payload for idx, (_, payload) in enumerate(pairs)}
        _log(
            "  Flash strategy: 3-segment vendor finalization order "
            "(body with 0x40..0x7F erased, CHECKBYTES, FINAL_ZZZ last)",
        )
    return _FlashPlan(
        segments=segments,
        segment_data=segment_data,
        source_segment_indices=tuple(range(len(segments))),
        complete_update_value=request.raw_complete_code,
        complete_update_width=_HARDWARE_COMPLETE_UPDATE_WIDTH,
        always_flash=True,
        image_sha256=flash_sha256,
    )


def _build_kex_flash_plan(request: _FlashRequest) -> _FlashPlan:
    """Resolve a ``.KEX`` request into a segment plan and its provenance."""
    if request.input_path.suffix != ".KEX":
        _die(
            "input must be a .KEX file "
            "(use thd75-extract to extract from .exe, or --raw for flat binary)",
        )
    input_container = request.input_path.read_bytes()
    input_container_sha256 = hashlib.sha256(input_container).hexdigest()
    _log("  Input format: canonical plaintext external KEX (no decryption)")
    _log(f"  Input container SHA-256: {input_container_sha256}")
    kex_image = kex.parse_kex_bytes(input_container)
    rendered_plaintext = kex.render(kex_image)
    rendered_plaintext_sha256 = hashlib.sha256(rendered_plaintext).hexdigest()
    _log(f"  Rendered plaintext KEX SHA-256: {rendered_plaintext_sha256}")
    audited_kex_label = _AUDITED_PLAINTEXT_KEX_SHA256.get(rendered_plaintext_sha256)
    is_service_9r_image = rendered_plaintext_sha256 == _SERVICE_9R_PLAINTEXT_KEX_SHA256
    is_gm_ddr_image = rendered_plaintext_sha256 == _NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256
    is_gm_nor_image = (
        rendered_plaintext_sha256 in _NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY
    )
    is_gm_nor_usb_recover_image = (
        rendered_plaintext_sha256 == _NORMAL_GM_NOR_USB_RECOVER_PLAINTEXT_KEX_SHA256
    )
    is_azimuth_image = (
        rendered_plaintext_sha256 in _RADIO_AUTOMATION_PLAINTEXT_KEX_SHA256_FAMILY
    )
    _log(
        "  Audited KEX artifact: "
        + (audited_kex_label or "NO — dry-run inspection only")
    )
    segments = [
        flash.segments.SegmentDescriptor.from_kex_block(b) for b in kex_image.blocks
    ]
    # Per-segment data extraction (records → flat bytes via intel_hex.parse)
    segment_data = {
        idx: intel_hex.parse(block.records).data
        for idx, block in enumerate(kex_image.blocks)
    }
    # Pull the top-level ``#FC`` completion code. Stock V1.03 has
    # ``#FC=0x1DB0``. It lives in
    # the first block's metadata when our KEX parser captures it.
    complete_update_value = _extract_fc_tag(kex_image)
    # OpenWood's u32 completion payload is part of the exact profile that
    # completed both retained D75 restores. The official host's u16 form
    # remains covered by vendor-parity tests, but real recovery must not
    # silently switch away from the empirical control.
    always_flash = _validate_d75_v103_kex_profile(kex_image)
    if not request.force_all_segments:
        # Default: override the KEX's #AF=1 and let the loader's own SETUP
        # equality answer decide. This is OpenWood's behaviour
        # (program_segment skip_if_current=True). In the acknowledged mode
        # the transfer is bounded by per-packet round trips rather than the
        # nominal baud, so skipping 12.7 MB of already-correct data removes
        # the great majority of the packets a code-only patch would
        # otherwise send.
        #
        # Stated as packets, not as time: no flash in this project has been
        # timed, so "costs real minutes" (what this said before) is not
        # something the repo can support.
        always_flash = False
    qualification_force_indices: frozenset[int] = frozenset()
    qualification_mode: str | None = None
    qualification_target: str | None = None
    if request.qualification_rewrite_stock_image_data:
        qualification_target = _stock_image_data_qualification_target(
            rendered_plaintext_sha256=rendered_plaintext_sha256,
            segments=segments,
            segment_data=segment_data,
            chunk_size=request.chunk_size,
        )
        qualification_force_indices = _STOCK_IMAGE_DATA_QUALIFICATION_INDICES
        qualification_mode = _STOCK_IMAGE_DATA_QUALIFICATION_NAME
    source_segment_indices = tuple(range(len(segments)))
    host_omission: str | None = None
    if (is_gm_ddr_image or is_gm_nor_image) and not request.force_all_segments:
        segments, segment_data, source_segment_indices = _normal_gm_fast_flash_plan(
            rendered_plaintext_sha256=rendered_plaintext_sha256,
            segments=segments,
            segment_data=segment_data,
        )
        host_omission = _NORMAL_GM_FAST_OMISSION
        _log(f"  Fast plan: {host_omission}")
    return _FlashPlan(
        segments=segments,
        segment_data=segment_data,
        source_segment_indices=source_segment_indices,
        complete_update_value=complete_update_value,
        complete_update_width=_HARDWARE_COMPLETE_UPDATE_WIDTH,
        always_flash=always_flash,
        qualification_force_indices=qualification_force_indices,
        qualification_mode=qualification_mode,
        qualification_target=qualification_target,
        audited_kex_label=audited_kex_label,
        image_sha256=rendered_plaintext_sha256,
        host_omission=host_omission,
        is_service_9r_image=is_service_9r_image,
        is_gm_ddr_image=is_gm_ddr_image,
        is_gm_nor_image=is_gm_nor_image,
        is_gm_nor_usb_recover_image=is_gm_nor_usb_recover_image,
        is_azimuth_image=is_azimuth_image,
    )


def _build_flash_plan(request: _FlashRequest) -> _FlashPlan:
    """Resolve the request into a segment plan before the operator prompt.

    Build segments before the prompt so the operator sees the resolved region
    (and any safety errors fire) before we ask them to push buttons on the
    radio.
    """
    if request.raw:
        return _build_raw_flash_plan(request)
    return _build_kex_flash_plan(request)


def _validate_flash_plan_or_die(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Run the zero-I/O preflight the session also runs, and surface failures.

    The same pure preflight runs here (before the prompt and before SerialIO
    is opened) and again inside FlashSession for callers that bypass the CLI.
    """
    try:
        flash.session.FlashSession.validate_plan(
            plan.segments,
            plan.segment_data,
            complete_update_value=plan.complete_update_value,
            complete_update_width=plan.complete_update_width,
            chunk_size=request.chunk_size,
        )
    except flash.session.FlashError as exc:
        _die(f"invalid flash plan at {exc.step}: {exc.cause}")


def _check_service_9r_acknowledgement(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Gate a real service-9R write behind its dedicated acknowledgement."""
    if request.acknowledge_service_9r_write and (
        request.raw or request.dry_run or not plan.is_service_9r_image
    ):
        _die(
            "--acknowledge-service-9r-write is valid only for a real write of "
            "the exact service-9r-nor-read plaintext KEX",
        )
    if (
        plan.is_service_9r_image
        and not request.dry_run
        and not request.acknowledge_service_9r_write
    ):
        _die(
            "writing the exact service-9r-nor-read KEX requires "
            "--acknowledge-service-9r-write after this completed order: the "
            "stock USB-C baseline; positive SETUP controls pass; a full radio "
            "power cycle; the exact mismatch/repeat result (1,0) passes; "
            "another full radio power cycle; and a verified stock restore "
            "artifact retained. The patched read/bounds check follows this "
            "write; --yes does not satisfy this dedicated gate",
        )


def _check_gm_ddr_acknowledgement(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Gate a real normal-gm-ddr-read write behind its acknowledgement."""
    if request.acknowledge_gm_ddr_read_write and (
        request.raw or request.dry_run or not plan.is_gm_ddr_image
    ):
        _die(
            "--acknowledge-gm-ddr-read-write is valid only for a real write of "
            "the exact normal-gm-ddr-read plaintext KEX",
        )
    if (
        plan.is_gm_ddr_image
        and not request.dry_run
        and not request.acknowledge_gm_ddr_read_write
    ):
        _die(
            "writing the exact normal-gm-ddr-read KEX requires "
            "--acknowledge-gm-ddr-read-write after this completed order: "
            "Firmware Programming Mode entry proven on the stock radio; a "
            "verified stock restore artifact generated and retained; and the "
            "radio fully charged. This patch destroys the GM GPS-mode command "
            "and is reverted only by a stock reflash. The first post-flash "
            "operation must be the escalating read probe followed by an "
            "out-of-bounds request that is REJECTED, because a successful read "
            "proves nothing about the bound; --yes does not satisfy this "
            "dedicated gate",
        )


def _gm_nor_post_flash_requirement(plan: _FlashPlan) -> str:
    """Return the first-post-flash-operation clause for the NOR family gate."""
    if plan.is_azimuth_image:
        return (
            "The first post-flash operation must be the ABI-3 byte-exact Azimuth "
            "automation qualifier, followed by the missing-snapshot, "
            "changed-context, command-4 zero-prefix, and atomic-991 route "
            "canaries before any audit key is dispatched. "
        )
    if plan.is_gm_nor_usb_recover_image:
        return (
            "The first post-flash operation must be "
            "usb_apply_trigger attest-trigger, followed after USB "
            "storage re-enumeration by its one-shot qualify action. "
        )
    return (
        "The first post-flash operation must be the bounded "
        "gm-nor-check; outside its exact flashed-main "
        "attestations, never request offsets above 1FFFFF. "
    )


def _check_gm_nor_acknowledgement(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Gate a real normal-gm-nor-read family write behind its acknowledgement."""
    if request.acknowledge_gm_nor_read_write and (
        request.raw or request.dry_run or not plan.is_gm_nor_image
    ):
        _die(
            "--acknowledge-gm-nor-read-write is valid only for a real write of "
            "the exact normal-gm-nor-read family plaintext KEX",
        )
    if (
        plan.is_gm_nor_image
        and not request.dry_run
        and not request.acknowledge_gm_nor_read_write
    ):
        _die(
            "writing the exact normal-gm-nor-read family KEX requires "
            "--acknowledge-gm-nor-read-write after retaining the verified "
            "stock restore and auditing its one-byte base delta against the "
            "hardware-qualified normal-gm-ddr-read image. This patch destroys "
            "the GM GPS-mode command and is reverted only by a stock reflash. "
            f"{_gm_nor_post_flash_requirement(plan)}"
            "--yes does not satisfy this dedicated gate",
        )


def _check_write_acknowledgements(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Run every dedicated artifact-specific write gate, in the fixed order."""
    _check_service_9r_acknowledgement(request, plan)
    _check_gm_ddr_acknowledgement(request, plan)
    _check_gm_nor_acknowledgement(request, plan)


def _log_dry_run_plan(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Print the resolved offline plan and each segment's transmitted bytes."""
    completion_bytes = plan.complete_update_value.to_bytes(
        plan.complete_update_width,
        "little",
    )
    _log(
        f"  Completion: 0x{plan.complete_update_value:X} as LE u"
        f"{plan.complete_update_width * 8} ({completion_bytes.hex(' ')})",
    )
    _log(
        f"  Force policy: {'write every segment' if plan.always_flash else 'skip current'}"
    )
    if plan.host_omission is not None:
        _log(f"  Host omission: {plan.host_omission}")
    for idx, (source_idx, descriptor) in enumerate(
        zip(plan.source_segment_indices, plan.segments, strict=True)
    ):
        effective_chunk = min(
            request.chunk_size,
            descriptor.chunk_size or request.chunk_size,
        )
        verify = (
            f"yes, {descriptor.checksum_length:,} bytes"
            if descriptor.checksum_length != 0
            else "no ($CL=0 vendor overlay pattern)"
        )
        payload = plan.segment_data[idx][: descriptor.data_length]
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        source_label = (
            "" if source_idx == idx else f" (original source segment {source_idx})"
        )
        _log(
            f"  Segment {idx}{source_label}: "
            f"start=0x{descriptor.flash_start_addr:08X}, "
            f"data={descriptor.data_length:,}, erase={descriptor.erase_length:,}, "
            f"packet={effective_chunk}, packets="
            f"{descriptor.data_length // effective_chunk}, verify={verify}, "
            f"CB=0x{descriptor.expected_before_checksum:04X}, "
            f"CA=0x{descriptor.expected_after_checksum:04X}, "
            f"payload_sha256={payload_sha256}, "
            f"descriptor={descriptor.to_recovery_wire().hex(' ')}",
        )
    _log("Dry run complete: no serial device opened and no bytes sent.")


def _refuse_unwritable_hardware_request(
    request: _FlashRequest, plan: _FlashPlan
) -> None:
    """Refuse every request that is not the exact proven hardware-write path."""
    if request.raw:
        _die(
            "hardware raw-image writes are disabled: the retained firmware/ "
            "payload returns data only through physical UART0, not USB-C or "
            "Bluetooth. Use --dry-run for raw-plan inspection; re-enable a "
            "real raw write only after an allowed return transport is "
            "implemented, audited, and hash-pinned"
        )

    if plan.audited_kex_label is None:
        _die(
            "hardware KEX writes are limited to the exact audited stock V1.03, "
            "service-9r-nor-read, normal-gm-ddr-read, or normal-gm-nor-read "
            "family plaintext hashes; use --dry-run to inspect any other "
            "artifact"
        )

    if request.single_segment:
        _die(
            "--single-segment is valid only for offline --dry-run --raw "
            "inspection; raw hardware writes are disabled",
        )

    # Second gate. `main_flash` checks the same thing before dispatch; this one
    # also covers callers that reach `_run_flash` directly, which is why the
    # rule is stated in both places rather than assumed.
    if request.chunk_size not in _WRITABLE_CHUNK_SIZES:
        _die(
            f"hardware writes require --chunk-size {_DEFAULT_CHUNK_SIZE}, the "
            "profile proven by two complete D75 stock restores; "
            f"got {request.chunk_size}. Use --dry-run to inspect other sizes"
        )

    if not request.cleartext_unlock or request.cleartext_baud != _PROVEN_CLEARTEXT_BAUD:
        _die(
            "hardware writes are gated to the proven D75 path: use "
            "--cleartext --cleartext-baud 576000",
        )

    if not request.reference_transport:
        _die(
            "hardware writes require the stabilized direct-open 576000 "
            "transport; the legacy 9600-to-576000 live reconfiguration is "
            "available only to non-writing diagnostics",
        )


def _build_flash_config(
    request: _FlashRequest, plan: _FlashPlan
) -> flash.diagnostics.FlashConfig:
    """Assemble the configuration banner from the request and resolved plan.

    Built before the port opens so it survives a run that dies at open. Every
    past attempt logged the image, the port and the outcome and nothing else,
    which left chunk size, transfer mode, ACK policy and baud to be
    reconstructed afterwards from edit timestamps. The protocol figures come
    from the same call that builds the payload the session sends, so the banner
    cannot drift from it.
    """
    transfer_mode = flash.session.negotiated_transfer_mode()
    return flash.diagnostics.FlashConfig(
        image=str(request.input_path),
        image_sha256=plan.image_sha256,
        image_label=plan.audited_kex_label,
        port=request.port or "<none>",
        open_baud=request.cleartext_baud,
        unlock_path="cleartext",
        unlock_baud=request.cleartext_baud,
        post_unlock_baud=None,
        baud_ladder=None,
        baud_and_ack_payload=transfer_mode.payload,
        transfer_mode_code=transfer_mode.code,
        transfer_declared_baud=transfer_mode.declared_baud,
        ack_each_data_packet=transfer_mode.ack_each_data_packet,
        base_reply_timeout_seconds=flash.session.DEFAULT_REPLY_TIMEOUT_SECONDS,
        chunk_size=request.chunk_size,
        force_all_segments=plan.always_flash,
        qualification=plan.qualification_mode,
        forced_segment_indices=tuple(sorted(plan.qualification_force_indices)),
        qualification_target=plan.qualification_target,
        complete_update_value=plan.complete_update_value,
        complete_update_width=plan.complete_update_width,
        segment_count=len(plan.segments),
        planned_bytes=sum(d.data_length for d in plan.segments),
        wire_trace_path=(
            None if request.wire_trace_path is None else str(request.wire_trace_path)
        ),
        progress_every_chunks=request.progress_every_chunks,
        tool_version=__version__,
        git_revision=flash.diagnostics.git_revision(),
        source_digest=flash.diagnostics.flasher_source_digest(),
        host_omission=plan.host_omission,
    )


def _prompt_before_flash(request: _FlashRequest) -> None:
    """Wait for the operator to confirm programming mode unless ``--yes``."""
    if request.skip_prompt:
        return
    print(_pre_flash_message())
    print(
        "Press Enter when the radio is in programming mode (Ctrl-C to abort): ",
        end="",
    )
    try:
        _ = input()
    except KeyboardInterrupt:
        _die("aborted by operator", code=2)


def _open_wire_trace(
    request: _FlashRequest,
    plan: _FlashPlan,
    config: flash.diagnostics.FlashConfig,
) -> flash.diagnostics.WireTrace | None:
    """Open the wire trace after the prompt, before the transport.

    Opened after the prompt so an aborted run leaves no empty trace, and before
    the transport so the banner header is on disk even if the port never opens.
    """
    if request.wire_trace_path is None:
        return None
    try:
        return flash.diagnostics.WireTrace(
            request.wire_trace_path,
            header_lines=config.comment_lines(),
            exclusive=bool(plan.qualification_force_indices),
        )
    except OSError as exc:
        _die(f"cannot open wire trace {request.wire_trace_path}: {exc}")


def _drive_flash_session(
    request: _FlashRequest,
    plan: _FlashPlan,
    trace: flash.diagnostics.WireTrace | None,
) -> None:
    """Open the transport, run the flash, and always print the mandatory notice."""
    listener = flash_ui.RichProgressListener()
    hardware_session_attempted = False
    try:
        if request.port is None:
            msg = "real flash requires --port"
            raise AssertionError(msg)
        hardware_session_attempted = True
        with _open_flash_transport(
            request.port,
            baud=request.cleartext_baud,
            reference_transport=request.reference_transport,
        ) as transport:
            session = flash.session.FlashSession(
                transport,
                flash.session.FlashSessionOptions(
                    chunk_size=request.chunk_size,
                    progress_every_chunks=request.progress_every_chunks,
                ),
                progress=listener,
                trace=trace,
            )
            outcome = session.flash_segments(
                plan.segments,
                plan.segment_data,
                flash.session.FlashRunOptions(
                    baud_ladder=_parse_baud_ladder(request.baud_ladder_text),
                    complete_update_value=plan.complete_update_value,
                    complete_update_width=plan.complete_update_width,
                    always_flash=plan.always_flash,
                    force_segment_indices=plan.qualification_force_indices,
                    cleartext_unlock=request.cleartext_unlock,
                    cleartext_baud=request.cleartext_baud,
                ),
            )
        _log(
            f"\nFlash complete in {outcome.elapsed_seconds:.1f}s — "
            f"{outcome.bytes_written:,} bytes across "
            f"{outcome.segments_written} segments.",
        )
        if request.show_post_hint:
            print(_post_flash_message())
    except flash.serial_io.SerialCloseError as exc:
        _die(f"flash transport close failure: {exc}", code=3)
    except FileNotFoundError as exc:
        _die(f"file not found: {exc.filename}")
    except flash.handshake.HandshakeError as exc:
        _die(f"handshake failed: {exc}", code=3)
    except flash.session.FlashError as exc:
        _die(_render_flash_error(exc), code=3)
    except OSError as exc:
        _die(f"flash transport failed: {type(exc).__name__}: {exc}", code=3)
    finally:
        if trace is not None:
            # Runs on the failure paths too: a hung or aborted flash is
            # exactly the run whose trace is worth keeping.
            trace.close()
            _log(
                f"Wire trace: {trace.record_count:,} frames written to {trace.path}",
            )
        if hardware_session_attempted:
            _log(
                "MANDATORY: disconnect USB and fully power-cycle the radio "
                "before constructing any new FLDM session.",
            )


def _execute_hardware_flash(request: _FlashRequest, plan: _FlashPlan) -> None:
    """Print the banner, prompt, open the trace, and run the flash session.

    Open directly at the operating rate, exactly as in both successful D75
    restores. No live baud transition occurs during the loader session.
    """
    config = _build_flash_config(request, plan)
    _log(config.render())
    _prompt_before_flash(request)
    trace = _open_wire_trace(request, plan, config)
    _drive_flash_session(request, plan, trace)


def _run_flash(request: _FlashRequest) -> None:
    """Full flash branch: resolve the plan, gate it, then dry-run or write."""
    _log_flash_intro(request)
    _check_qualification_and_force_gates(request)
    plan = _build_flash_plan(request)
    _validate_flash_plan_or_die(request, plan)
    _check_write_acknowledgements(request, plan)
    if request.dry_run:
        _log_dry_run_plan(request, plan)
        return
    _refuse_unwritable_hardware_request(request, plan)
    _execute_hardware_flash(request, plan)


def _pre_flash_message() -> str:
    return """
Before continuing, on the radio:
  1. Install a fully charged battery pack.
  2. Turn the radio power OFF.
  3. Turn the radio power ON while pressing and holding [PTT] + [1].
     The radio is now in Firmware Programming Mode (display may be dark).
  4. Connect the USB cable.
"""


def _post_flash_message() -> str:
    return """
To finish the TH-D75 firmware update:
  1. Turn the radio power OFF.
  2. Disconnect the USB cable.
  3. Turn the radio power ON while pressing and holding [F].
     The Reset screen will appear.
  4. Select "Full Reset" and press [A/B], then press [A/B] again to confirm.
"""


def _render_flash_error(exc: flash.session.FlashError) -> str:
    recovery = (
        "Power-cycle the radio (PTT+1 to re-enter programming mode) "
        "and diagnose this exact failed step before considering another write."
    )
    if not exc.recoverable:
        recovery = (
            "Stop. The USB-C/Bluetooth-only workflow has no in-scope recovery "
            "action for a damaged bootloader; do not attempt another write."
        )
    return f"{exc.step}: {exc.cause}\n\n{recovery}"
