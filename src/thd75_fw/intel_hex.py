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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from .patch import ByteChange

__all__: list[str] = [
    "ParseResult",
    "Record",
    "RecordType",
    "iter_records",
    "parse",
    "patch_image",
    "record_checksum",
    "to_text_lines",
]


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


@dataclass(frozen=True, slots=True)
class Record:
    """One Intel HEX record located within a packed byte stream.

    Frozen so a record can't drift out of sync with the stream it was
    read from. ``base_address`` is the extended-linear base in effect
    when this record was reached, so a data record's flat-image offset
    is ``base_address + address``. ``start`` is the record's byte offset
    within the stream — the anchor for an in-place edit.
    """

    start: int
    byte_count: int
    address: int
    record_type: int
    data: bytes
    checksum: int
    base_address: int


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
    saw_any_record = False

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

        # Verify the record's checksum byte — every record's bytes sum
        # to zero mod 256. A stale or corrupted record that slips past
        # this check would silently bake bad data into the flat image
        # (and any subsequent re-checksum after patching would mask the
        # original corruption with a fresh-but-incorrect checksum).
        payload_end: int = pos + 4 + byte_count
        if payload_end < len(raw):
            stored_checksum: int = raw[payload_end]
            expected_checksum: int = (-sum(raw[pos:payload_end])) & 0xFF
            if stored_checksum != expected_checksum:
                error_messages.append(
                    f"Bad record checksum at offset {pos}: "
                    f"stored 0x{stored_checksum:02X}, "
                    f"computed 0x{expected_checksum:02X}"
                )

        saw_any_record = True

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

    # A stream containing data records but no EOF marker is itself a
    # truncation signal — even when the stream happens to end exactly
    # at a record boundary (no trailing bytes). The radio's loader
    # relies on EOF; the absence of one is silent corruption.
    if saw_any_record and not saw_eof and not error_messages:
        error_messages.append(
            "Stream ended without an EOF (type 0x01) record; "
            "truncation cannot be ruled out"
        )

    return ParseResult(
        data=bytes(image_data),
        base_address=base_address,
        record_count=record_count,
        errors=tuple(error_messages),
    )


def iter_records(raw: bytes) -> Iterator[Record]:
    """Walk a packed Intel HEX stream, yielding one ``Record`` per record.

    Unlike ``parse``, which reconstructs a flat image, this preserves
    record boundaries — needed to edit a specific record in place or to
    re-emit the stream as textual ``:``-prefixed lines.

    Args:
        raw: A packed Intel HEX stream (e.g. one decrypted resource
            block's data).

    Yields:
        ``Record`` instances in stream order, including the trailing
        End-Of-File record. The extended-linear base address is tracked
        across records. Iteration stops after EOF.

    Raises:
        ValueError: if a record's declared length exceeds the bytes
            remaining in the stream. Truncation would otherwise
            silently lose every later record — and the asymmetry
            with ``parse`` (which reports truncation via
            ``ParseResult.errors``) is the kind of silent failure
            this codebase exists to surface.
    """
    pos = 0
    base_address = 0
    while pos + 5 <= len(raw):
        byte_count: int = raw[pos]
        record_end: int = pos + 4 + byte_count + 1
        if record_end > len(raw):
            msg = (
                f"truncated record at offset {pos}: "
                f"need {4 + byte_count + 1} bytes, have {len(raw) - pos}"
            )
            raise ValueError(msg)
        record_type: int = raw[pos + 3]
        yield Record(
            start=pos,
            byte_count=byte_count,
            address=(raw[pos + 1] << 8) | raw[pos + 2],
            record_type=record_type,
            data=raw[pos + 4 : pos + 4 + byte_count],
            checksum=raw[record_end - 1],
            base_address=base_address,
        )
        if record_type == RecordType.EXTENDED_LINEAR_ADDRESS and byte_count >= 2:
            base_address = ((raw[pos + 4] << 8) | raw[pos + 5]) << 16
        if record_type == RecordType.EOF:
            return
        pos = record_end


def to_text_lines(raw: bytes) -> list[str]:
    """Re-emit a packed Intel HEX stream as textual ``:``-prefixed lines.

    Each record becomes one ``:LLAAAATT...CC`` line of uppercase hex —
    the one-record-per-line form a plaintext .KEX firmware file uses,
    and the form the updater's record parser consumes.

    Args:
        raw: A packed Intel HEX stream.

    Returns:
        One string per record, in stream order, each starting with
        ``:``. Records past a truncated record, or past EOF, are not
        emitted (see ``iter_records``).
    """
    return [
        ":" + raw[rec.start : rec.start + 4 + rec.byte_count + 1].hex().upper()
        for rec in iter_records(raw)
    ]


def record_checksum(payload: bytes) -> int:
    """Compute the checksum byte for an Intel HEX record.

    Args:
        payload: Every byte of a record *except* the checksum — the
            count byte, the two address bytes, the type byte, and the
            data bytes. For a TH-D75 packed record this is the record
            slice with its final byte dropped.

    Returns:
        The checksum byte: the two's-complement of the sum of
        ``payload`` modulo 256. Appended to ``payload`` it makes the
        whole record sum to zero — the invariant that must be
        restored after editing a data byte.
    """
    return (-sum(payload)) & 0xFF


def patch_image(raw: bytes, changes: Iterable[ByteChange]) -> bytes:
    """Apply byte changes to a packed Intel HEX stream.

    For each change, locates the data record covering ``change.offset``,
    verifies that the current byte equals ``change.expect``, then writes
    ``change.value`` and recomputes that record's checksum.

    Args:
        raw: A packed Intel HEX stream.
        changes: The byte changes to apply, each declaring its expected
            current byte.

    Returns:
        The patched packed stream — same length and record layout as
        ``raw``, differing only in the patched data bytes and their
        records' checksum bytes.

    Raises:
        PatchVerificationError: if any change's ``expect`` does not match
            the current byte in the firmware.
        ValueError: if an offset falls within no data record.
    """
    # Lazy import: PatchVerificationError lives in patch.py, the
    # higher-level catalog module. A top-level import would create a
    # cycle if patch.py later grew an intel_hex dependency, so we
    # defer the import to call time.
    from .patch import PatchVerificationError

    # Build the pending dict and confirm every change is distinct by
    # offset. ``Patch.__post_init__`` already enforces this for patches
    # parsed via ``parse_patch``, but ``patch_image`` accepts a raw
    # ``Iterable[ByteChange]`` from any caller — defense in depth.
    pending: dict[int, ByteChange] = {}
    for change in changes:
        if change.offset in pending:
            msg = f"duplicate change at offset 0x{change.offset:X}"
            raise ValueError(msg)
        pending[change.offset] = change
    if not pending:
        return raw

    buf = bytearray(raw)
    for rec in iter_records(raw):
        if rec.record_type != RecordType.DATA:
            continue
        record_lo: int = rec.base_address + rec.address
        hits: list[int] = [
            offset
            for offset in pending
            if record_lo <= offset < record_lo + rec.byte_count
        ]
        for offset in hits:
            change = pending.pop(offset)
            data_index: int = offset - record_lo
            actual: int = buf[rec.start + 4 + data_index]
            if actual != change.expect:
                raise PatchVerificationError(
                    offset=offset, expected=change.expect, actual=actual,
                )
            buf[rec.start + 4 + data_index] = change.value
        if hits:
            payload_end: int = rec.start + 4 + rec.byte_count
            buf[payload_end] = record_checksum(bytes(buf[rec.start : payload_end]))

    if pending:
        unmatched: str = ", ".join(f"0x{offset:X}" for offset in sorted(pending))
        msg = f"patch offset(s) not in any data record: {unmatched}"
        raise ValueError(msg)
    return bytes(buf)


def _write_at(buf: bytearray, offset: int, data: bytes) -> None:
    """Write ``data`` into ``buf`` at ``offset``, extending with 0xFF as needed."""
    end: int = offset + len(data)
    if end > len(buf):
        buf.extend(b"\xFF" * (end - len(buf)))
    buf[offset:end] = data
