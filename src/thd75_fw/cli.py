"""Command-line entry points for TH-D75 firmware tools."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from collections.abc import Iterable

from . import (
    __version__,
    file_cipher,
    images,
    intel_hex,
    resource,
    serial_cipher,
    voice,
)
from .sections import FLASH_BASE, SECTIONS, FlashAddress, lookup_by_address

__all__: list[str] = [
    "main_extract",
    "main_extract_images",
    "main_extract_voice",
    "main_serial_cipher",
]


# ── shared helpers ─────────────────────────────────────────────────


def _log(msg: str) -> None:
    """Write a progress message to stderr, leaving stdout for real output."""
    print(msg, file=sys.stderr)


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


def _validate_output_dir(path: Path) -> None:
    """Ensure ``path`` is a directory we can write into (or doesn't exist yet)."""
    if path.exists() and not path.is_dir():
        _die(f"output path exists and is not a directory: {path}")


def _add_version(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )


# ── thd75-extract ──────────────────────────────────────────────────


def main_extract() -> None:
    """Extract firmware sections from a TH-D75 updater .exe."""
    parser = argparse.ArgumentParser(
        prog="thd75-extract",
        description="Extract firmware sections from the TH-D75 updater .exe.",
        epilog=(
            "Example:\n"
            "  thd75-extract TH-D75_V103_e.exe ./extracted/\n\n"
            "Other tools in this package: thd75-extract-voice, "
            "thd75-extract-images, thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    parser.add_argument(
        "input", type=Path, help="Path to the TH-D75 updater .exe to extract from",
    )
    parser.add_argument(
        "output", type=Path, help="Output directory for extracted .bin files",
    )
    parser.add_argument(
        "--verify", type=Path, metavar="DIR",
        help="Verify extracted files byte-for-byte against a reference directory",
    )
    parser.add_argument(
        "--resource", type=Path, metavar="FILE",
        help="Use a pre-extracted resource file (e.g., from ilspycmd)",
    )
    args = parser.parse_args()

    try:
        _run_extract(args.input, args.output, args.verify, args.resource)
    except FileNotFoundError as exc:
        _die(f"file not found: {exc.filename}")
    except (ValueError, UnicodeDecodeError) as exc:
        _die(str(exc), code=1)


def _run_extract(
    exe_path: Path,
    output_dir: Path,
    verify_dir: Path | None,
    resource_path: Path | None,
) -> None:
    """Execute the full extraction pipeline."""
    _validate_output_dir(output_dir)

    _log(f"TH-D75 Firmware Extractor\n  Input: {exe_path}")

    _log("\n[1/3] Loading firmware resource...")
    if resource_path is not None:
        resource_text: str = resource_path.read_text(encoding="utf-8")
    else:
        resource_text = resource.load(exe_path)
    _log(f"  {len(resource_text):,} chars")

    _log("\n[2/3] Decrypting...")
    decrypted: file_cipher.DecryptedResource = file_cipher.decrypt_resource(
        resource_text
    )
    _log(f"  Blocks: {len(decrypted.blocks)}")
    _log(f"  Metadata: {len(decrypted.metadata)} entries")

    # Parse each block's Intel HEX independently and route by $SA= metadata.
    sections: dict[FlashAddress, bytes] = {}
    total_records: int = 0
    all_parse_errors: list[str] = []

    for block_index, block in enumerate(decrypted.blocks):
        if not block.data:
            continue
        parsed: intel_hex.ParseResult = intel_hex.parse(block.data)
        total_records += parsed.record_count
        for err in parsed.errors:
            all_parse_errors.append(f"block {block_index}: {err}")

        if parsed.data:
            section_addr = _extract_flash_address(block, block_index)
            sections[section_addr] = parsed.data

    _log(f"  Total records: {total_records:,}")
    _log(f"  Sections: {len(sections)}")

    if all_parse_errors:
        _log(f"\n  WARNING: {len(all_parse_errors)} Intel HEX parse error(s):")
        for err in all_parse_errors:
            _log(f"    {err}")
        _die(
            "output may be incomplete or corrupt; "
            "re-run with a known-good updater .exe",
            code=1,
        )

    _log(f"\n[3/3] Saving {len(sections)} sections to {output_dir}/")
    output_dir.mkdir(parents=True, exist_ok=True)

    for addr in _sort_sections_by_definition_order(sections.keys()):
        data: bytes = sections[addr]
        info = lookup_by_address(addr)
        filename: str = info.filename if info else f"UNKNOWN_0x{addr:08X}.bin"
        (output_dir / filename).write_bytes(data)
        preview: str = " ".join(f"{b:02X}" for b in data[:8])
        _log(f"  {filename}: {len(data):>10,} bytes  [{preview}...]")

    if verify_dir is not None:
        verify_passed: bool = _verify(output_dir, verify_dir)
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
    block: file_cipher.DecryptedBlock, block_index: int,
) -> FlashAddress:
    """Extract a section's flash-relative address from block metadata.

    Each block in the encrypted resource is preceded by a ``$SA=`` line
    holding the section's *physical* address — that includes the OMAP-L138's
    NOR flash base (``0x60000000``). Subtracting the base gives the
    flash-relative offset used everywhere else (filenames, ``SectionInfo.
    flash_address``, the README's section table). See ``docs/FORMAT.md``
    "Block / section metadata format" for the broader resource format.

    Raises:
        ValueError: If the block has no parseable ``$SA=`` line. The
            previous behavior fell back to ``SECTIONS[block_index]``,
            which silently misroutes the block when ``$SA=`` is
            corrupted or the SECTIONS tuple is reordered — exactly
            the silent-failure mode this tool must avoid.
    """
    for meta_line in block.metadata:
        stripped = meta_line.strip()
        if stripped.startswith("$SA="):
            val: str = stripped[4:]
            try:
                physical_addr = int(val, 16) if val.startswith("0x") else int(val)
            except ValueError as exc:
                raise ValueError(
                    f"Block {block_index} has unparseable $SA= value: {val!r}"
                ) from exc
            return FlashAddress(physical_addr - FLASH_BASE)
    raise ValueError(
        f"Block {block_index} has no $SA= metadata line; cannot determine "
        f"flash address. Block metadata: {block.metadata!r}"
    )


def _verify(output_dir: Path, reference_dir: Path) -> bool:
    """Compare extracted files byte-for-byte against a reference."""
    _log(f"\nVerifying against: {reference_dir}")
    all_match: bool = True

    for ref_file in sorted(reference_dir.glob("*.bin")):
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
    filename: str, reference_data: bytes, output_data: bytes,
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
            "thd75-extract-images."
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
        action_parser.add_argument(
            "input", type=Path, help="Path to the input file",
        )
        action_parser.add_argument(
            "-o", "--output",
            type=Path,
            help="Path to the output file (if omitted, prints a hex dump of "
                 "the first 64 bytes to stdout)",
        )
        action_parser.add_argument(
            "--key",
            type=lambda x: int(x, 0),
            default=serial_cipher.DEFAULT_KEY,
            help=(
                "Cipher key as decimal, 0xHEX, or 0oOCT "
                f"(default: 0x{serial_cipher.DEFAULT_KEY:02X}; 0 = passthrough)"
            ),
        )

    sub.add_parser(
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
    except FileNotFoundError as exc:
        _die(f"file not found: {exc.filename}")

    # Guard against ``-o some/dir/`` where some/dir/ exists as a directory:
    # write_bytes() would raise IsADirectoryError mid-pipeline. Reject up front.
    if args.output is not None and args.output.is_dir():
        _die(f"output path is a directory, expected a file: {args.output}")

    cipher_func = (
        serial_cipher.decrypt if args.command == "decrypt" else serial_cipher.encrypt
    )
    result: bytes = cipher_func(data, args.key)

    if args.output:
        args.output.write_bytes(result)
        _log(f"Wrote {len(result):,} bytes to {args.output}")
    else:
        _hexdump(result[:64])
        if len(result) > 64:
            _log(f"  ... ({len(result) - 64:,} more bytes, use -o to write)")


def _hexdump(data: bytes, width: int = 16) -> None:
    """Print a compact hex dump."""
    for offset in range(0, len(data), width):
        chunk: bytes = data[offset : offset + width]
        hex_part: str = " ".join(f"{b:02X}" for b in chunk)
        ascii_part: str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
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
            "thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    parser.add_argument(
        "input", type=Path, help="Path to a DATA_0160 .bin file from thd75-extract",
    )
    parser.add_argument(
        "output", type=Path, help="Output directory for the extracted WAV files",
    )
    parser.add_argument(
        "--lang", choices=["en", "ja", "zh", "all"], default="all",
        help="Language code to filter by (default: all three languages)",
    )
    args = parser.parse_args()

    try:
        data: bytes = args.input.read_bytes()
    except FileNotFoundError as exc:
        _die(f"file not found: {exc.filename}")

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
            "thd75-serial-cipher."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_version(parser)
    parser.add_argument(
        "input", type=Path,
        help="Path to an IMAGE_DATA .bin file from thd75-extract",
    )
    parser.add_argument(
        "output", type=Path, help="Output directory for the extracted PNG files",
    )
    args = parser.parse_args()

    try:
        data: bytes = args.input.read_bytes()
    except FileNotFoundError as exc:
        _die(f"file not found: {exc.filename}")

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
