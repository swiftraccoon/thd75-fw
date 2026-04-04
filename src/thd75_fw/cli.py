"""Command-line entry points for TH-D75 firmware tools."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import file_cipher, intel_hex, resource, serial_cipher
from .sections import SECTIONS, name_for_address

__all__: list[str] = ["main_extract", "main_serial_cipher"]

# ── thd75-extract ──────────────────────────────────────────────────


def main_extract() -> None:
    """Extract firmware sections from a TH-D75 updater .exe."""
    parser = argparse.ArgumentParser(
        prog="thd75-extract",
        description="Extract firmware sections from the TH-D75 updater .exe",
    )
    parser.add_argument("exe", type=Path, help="Path to TH-D75 updater .exe")
    parser.add_argument("output", type=Path, help="Output directory for .bin files")
    parser.add_argument(
        "--verify", type=Path, metavar="DIR", help="Verify against reference files"
    )
    parser.add_argument(
        "--resource", type=Path, metavar="FILE", help="Pre-extracted resource file"
    )
    args = parser.parse_args()

    _run_extract(args.exe, args.output, args.verify, args.resource)


def _run_extract(
    exe_path: Path,
    output_dir: Path,
    verify_dir: Path | None,
    resource_path: Path | None,
) -> None:
    """Execute the full extraction pipeline."""
    print(f"TH-D75 Firmware Extractor\n  Input: {exe_path}")

    # 1. Load resource
    print("\n[1/3] Loading firmware resource...")
    if resource_path is not None:
        resource_text: str = resource_path.read_text(encoding="utf-8")
    else:
        resource_text = resource.load(exe_path)
    print(f"  {len(resource_text):,} chars")

    # 2. Decrypt
    print("\n[2/3] Decrypting...")
    result: file_cipher.DecryptedResource = file_cipher.decrypt_resource(resource_text)
    print(f"  Blocks: {len(result.blocks)}")
    print(f"  Metadata: {len(result.metadata)} entries")

    # Parse each block's Intel HEX independently
    sections: dict[int, bytes] = {}
    total_records: int = 0

    for block_idx, block in enumerate(result.blocks):
        hex_data: str = block.data_hex
        if len(hex_data) % 2:
            hex_data = hex_data[:-1]
        if not hex_data:
            continue
        raw: bytes = bytes.fromhex(hex_data)
        parsed: intel_hex.ParseResult = intel_hex.parse(raw)
        total_records += parsed.record_count

        if parsed.data:
            section_addr: int = _extract_flash_address(block, block_idx)
            sections[section_addr] = bytes(parsed.data)

    print(f"  Total records: {total_records:,}")
    print(f"  Sections: {len(sections)}")

    # 3. Save
    print(f"\n[3/3] Saving {len(sections)} sections to {output_dir}/")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Sort sections in the order they appear in the SECTIONS definition
    # (not by flash address, which puts CHECKBYTES before IMAGE_DATA)
    section_order: list[int] = [s.flash_address for s in SECTIONS]
    sorted_addrs: list[int] = sorted(
        sections.keys(),
        key=lambda a: section_order.index(a) if a in section_order else 999,
    )

    for idx, addr in enumerate(sorted_addrs):
        data: bytes = sections[addr]
        name: str = name_for_address(addr)
        filename: str = f"{idx}_{name}_0x{addr:08X}.bin"
        (output_dir / filename).write_bytes(data)
        preview: str = " ".join(f"{b:02X}" for b in data[:8])
        print(f"  {filename}: {len(data):>10,} bytes  [{preview}...]")

    # 4. Verify
    if verify_dir is not None:
        ok: bool = _verify(output_dir, verify_dir)
        print(f"\nVerification: {'PASS' if ok else 'FAIL'}")
        if not ok:
            sys.exit(1)

    print("\nDone.")


_DDR_BASE: int = 0x6000_0000


def _extract_flash_address(block: file_cipher.DecryptedBlock, fallback_idx: int) -> int:
    """Extract flash address from block metadata ($SA field).

    The updater stores addresses with a 0x60000000 DDR base offset.
    Falls back to the SECTIONS table if metadata is unavailable.
    """
    for meta_line in block.metadata:
        meta_line = meta_line.strip()
        if meta_line.startswith("$SA="):
            val: str = meta_line[4:]
            stored_addr: int = int(val, 16) if val.startswith("0x") else int(val)
            return stored_addr - _DDR_BASE
    # Fallback: use hardcoded section order
    if fallback_idx < len(SECTIONS):
        return SECTIONS[fallback_idx].flash_address
    return fallback_idx


def _verify(output_dir: Path, reference_dir: Path) -> bool:
    """Compare extracted files byte-for-byte against a reference."""
    print(f"\nVerifying against: {reference_dir}")
    all_match: bool = True

    for ref_file in sorted(reference_dir.glob("*.bin")):
        out_file: Path = output_dir / ref_file.name
        if not out_file.exists():
            print(f"  {ref_file.name}: MISSING")
            all_match = False
            continue

        ref_data: bytes = ref_file.read_bytes()
        out_data: bytes = out_file.read_bytes()

        if ref_data == out_data:
            print(f"  {ref_file.name}: MATCH ({len(ref_data):,} bytes)")
        else:
            all_match = False
            _report_mismatch(ref_file.name, ref_data, out_data)

    return all_match


def _report_mismatch(name: str, ref: bytes, out: bytes) -> None:
    """Print a human-readable mismatch report."""
    for j in range(min(len(ref), len(out))):
        if ref[j] != out[j]:
            print(
                f"  {name}: MISMATCH at byte {j} "
                f"(got 0x{out[j]:02X}, expected 0x{ref[j]:02X})"
            )
            return
    print(f"  {name}: SIZE MISMATCH (got {len(out):,}, expected {len(ref):,})")


# ── thd75-serial-cipher ───────────────────────────────────────────


def main_serial_cipher() -> None:
    """Encrypt or decrypt TH-D75 serial transfer packets."""
    parser = argparse.ArgumentParser(
        prog="thd75-serial-cipher",
        description="Encrypt/decrypt TH-D75 serial transfer packets",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", type=Path)
    dec.add_argument("-o", "--output", type=Path)
    dec.add_argument("--key", type=lambda x: int(x, 0), default=serial_cipher.DEFAULT_KEY)

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", type=Path)
    enc.add_argument("-o", "--output", type=Path)
    enc.add_argument("--key", type=lambda x: int(x, 0), default=serial_cipher.DEFAULT_KEY)

    sub.add_parser("verify", help="Run round-trip self-test")

    args = parser.parse_args()

    if args.command == "verify":
        serial_cipher.verify_round_trip()
        print("PASS: round-trip verified for all 256 byte values")
        return

    data: bytes = args.input.read_bytes()
    func = serial_cipher.decrypt if args.command == "decrypt" else serial_cipher.encrypt
    result: bytes = func(data, args.key)

    if args.output:
        args.output.write_bytes(result)
        print(f"Wrote {len(result):,} bytes to {args.output}")
    else:
        _hexdump(result[:64])
        if len(result) > 64:
            print(f"  ... ({len(result) - 64:,} more bytes, use -o to write)")


def _hexdump(data: bytes, width: int = 16) -> None:
    """Print a compact hex dump."""
    for offset in range(0, len(data), width):
        chunk: bytes = data[offset : offset + width]
        hex_part: str = " ".join(f"{b:02X}" for b in chunk)
        ascii_part: str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {offset:04X}: {hex_part:<{width * 3}}  {ascii_part}")
