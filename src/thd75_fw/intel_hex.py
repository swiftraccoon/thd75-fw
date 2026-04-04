"""Intel HEX format parser for TH-D75 firmware images.

After decryption, the firmware resource contains Intel HEX records
packed as raw bytes (not the textual ``:`` representation). Records
follow the standard format:

    LL AAAA TT [DD...] CC

    LL   = data byte count
    AAAA = 16-bit address within the current segment
    TT   = record type
    DD   = data bytes (LL of them)
    CC   = checksum byte

Record types:
    0x00 = Data
    0x01 = End Of File
    0x04 = Extended Linear Address (sets upper 16 bits)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

__all__: list[str] = ["ParseResult", "RecordType", "parse"]


class RecordType(IntEnum):
    """Intel HEX record types used in TH-D75 firmware images."""

    DATA = 0x00
    EOF = 0x01
    EXTENDED_LINEAR_ADDRESS = 0x04


@dataclass
class ParseResult:
    """Result of parsing an Intel HEX byte stream."""

    data: bytearray = field(default_factory=bytearray)
    base_address: int = 0
    record_count: int = 0
    errors: list[str] = field(default_factory=lambda: list[str]())


def parse(raw: bytes) -> ParseResult:
    """Parse a raw byte stream of packed Intel HEX records.

    Args:
        raw: Binary data containing sequential Intel HEX records.
             This is the *decoded* stream after cipher decryption and
             hex-to-binary conversion — not textual ``:``-prefixed lines.

    Returns:
        A ``ParseResult`` with the reconstructed firmware binary,
        base address, record count, and any parse errors.
    """
    result = ParseResult()
    pos = 0

    while pos < len(raw) - 4:
        byte_count: int = raw[pos]
        addr_hi: int = raw[pos + 1]
        addr_lo: int = raw[pos + 2]
        rec_type: int = raw[pos + 3]
        local_addr: int = (addr_hi << 8) | addr_lo

        # Skip null padding (all-zero 4-byte headers that aren't valid records).
        # Valid records with byte_count=0 always have a non-zero rec_type
        # (0x01 for EOF, 0x04 for extended address).
        if byte_count == 0 and local_addr == 0 and rec_type == 0:
            while pos < len(raw) and raw[pos] == 0x00:
                pos += 1
            continue

        record_len: int = 4 + byte_count + 1  # header + data + checksum

        if pos + 4 + byte_count > len(raw):
            result.errors.append(
                f"Truncated record at offset {pos}: "
                f"need {4 + byte_count} bytes, have {len(raw) - pos}"
            )
            break

        if rec_type == RecordType.DATA:
            data: bytes = raw[pos + 4 : pos + 4 + byte_count]
            full_addr: int = result.base_address + local_addr
            _write_at(result.data, full_addr, data)
            result.record_count += 1

        elif rec_type == RecordType.EXTENDED_LINEAR_ADDRESS:
            if byte_count >= 2:
                upper: int = (raw[pos + 4] << 8) | raw[pos + 5]
                result.base_address = upper << 16

        elif rec_type == RecordType.EOF:
            break

        pos += record_len

    return result


def _write_at(buf: bytearray, offset: int, data: bytes) -> None:
    """Write ``data`` into ``buf`` at ``offset``, extending with 0xFF as needed."""
    end: int = offset + len(data)
    if end > len(buf):
        buf.extend(b"\xFF" * (end - len(buf)))
    buf[offset:end] = data
