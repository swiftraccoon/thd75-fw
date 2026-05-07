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

from dataclasses import dataclass
from enum import IntEnum

__all__: list[str] = ["ParseResult", "RecordType", "parse"]


class RecordType(IntEnum):
    """Intel HEX record types used in TH-D75 firmware images."""

    DATA = 0x00
    EOF = 0x01
    EXTENDED_LINEAR_ADDRESS = 0x04


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Result of parsing an Intel HEX byte stream.

    Frozen so consumers can't accidentally mutate ``data`` or ``errors``
    and confuse "parser produced this" with "parser was told this".
    A non-empty ``errors`` tuple means the stream had problems even if
    ``data`` looks plausible — always check it.
    """

    data: bytes
    base_address: int
    record_count: int
    errors: tuple[str, ...]


def parse(raw: bytes) -> ParseResult:
    """Parse a raw byte stream of packed Intel HEX records.

    Args:
        raw: Binary data containing sequential Intel HEX records.
             This is the *decoded* stream after cipher decryption and
             hex-to-binary conversion — not textual ``:``-prefixed lines.

    Returns:
        A ``ParseResult`` with the reconstructed firmware binary,
        base address at parse end, record count, and any parse errors.
        Callers must check ``errors`` to detect truncation, unknown
        record types, or other corruption — these no longer fail
        silently in the parser.
    """
    image_data = bytearray()
    error_messages: list[str] = []
    base_address: int = 0
    record_count: int = 0
    pos = 0
    saw_eof = False

    while pos + 5 <= len(raw):
        byte_count: int = raw[pos]
        addr_hi: int = raw[pos + 1]
        addr_lo: int = raw[pos + 2]
        record_type: int = raw[pos + 3]
        local_addr: int = (addr_hi << 8) | addr_lo

        # Skip null padding (all-zero 4-byte headers that aren't valid records).
        # Valid records with byte_count=0 always have a non-zero record_type
        # (0x01 for EOF, 0x04 for extended address).
        if byte_count == 0 and local_addr == 0 and record_type == 0:
            while pos < len(raw) and raw[pos] == 0x00:
                pos += 1
            continue

        record_len: int = 4 + byte_count + 1  # header + data + checksum

        if pos + 4 + byte_count > len(raw):
            error_messages.append(
                f"Truncated record at offset {pos}: "
                f"need {4 + byte_count} bytes, have {len(raw) - pos}"
            )
            break

        if record_type == RecordType.DATA:
            data: bytes = raw[pos + 4 : pos + 4 + byte_count]
            full_addr: int = base_address + local_addr
            _write_at(image_data, full_addr, data)
            record_count += 1

        elif record_type == RecordType.EXTENDED_LINEAR_ADDRESS:
            if byte_count < 2:
                error_messages.append(
                    f"Extended-linear-address record at offset {pos} has "
                    f"byte_count={byte_count} (need >=2); base address unchanged"
                )
            else:
                upper: int = (raw[pos + 4] << 8) | raw[pos + 5]
                base_address = upper << 16

        elif record_type == RecordType.EOF:
            saw_eof = True
            break

        else:
            error_messages.append(
                f"Unknown record type 0x{record_type:02X} at offset {pos} "
                f"(byte_count={byte_count}); record skipped"
            )

        pos += record_len

    # Trailing bytes that didn't form a complete record (and aren't pure padding)
    # are a sign of truncation or stream corruption.
    if not saw_eof and pos < len(raw) and any(b not in (0x00, 0xFF) for b in raw[pos:]):
        error_messages.append(
            f"{len(raw) - pos} trailing byte(s) at offset {pos} did not form a "
            f"complete record (no EOF marker seen)"
        )

    return ParseResult(
        data=bytes(image_data),
        base_address=base_address,
        record_count=record_count,
        errors=tuple(error_messages),
    )


def _write_at(buf: bytearray, offset: int, data: bytes) -> None:
    """Write ``data`` into ``buf`` at ``offset``, extending with 0xFF as needed."""
    end: int = offset + len(data)
    if end > len(buf):
        buf.extend(b"\xFF" * (end - len(buf)))
    buf[offset:end] = data
