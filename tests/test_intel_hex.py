"""Tests for the Intel HEX parser."""

from __future__ import annotations

from thd75_fw.intel_hex import ParseResult, RecordType, parse


def _record(
    byte_count: int,
    addr: int,
    rec_type: int,
    data: bytes = b"",
    checksum: int = 0,
) -> bytes:
    """Build a raw packed Intel HEX record."""
    return bytes(
        [byte_count, (addr >> 8) & 0xFF, addr & 0xFF, rec_type, *data, checksum]
    )


class TestDataRecords:
    """Type-0 data records reconstruct bytes at the address fields
    advertise; multiple records concatenate."""

    def test_single_record(self) -> None:
        data = b"\x1C\xF0\x9F\xE5"
        raw: bytes = _record(4, 0x0000, RecordType.DATA, data)
        result: ParseResult = parse(raw)
        assert result.record_count == 1
        assert bytes(result.data[:4]) == data

    def test_two_records(self) -> None:
        r1 = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB")
        r2 = _record(2, 0x0002, RecordType.DATA, b"\xCC\xDD")
        result = parse(r1 + r2)
        assert result.record_count == 2
        assert bytes(result.data) == b"\xAA\xBB\xCC\xDD"


class TestExtendedAddress:
    """Type-4 extended-linear-address records set the upper 16 bits of
    base_address for subsequent data records."""

    def test_sets_base(self) -> None:
        ext = _record(2, 0, RecordType.EXTENDED_LINEAR_ADDRESS, b"\x00\x20")
        data = _record(4, 0, RecordType.DATA, b"\xAA\xBB\xCC\xDD")
        eof = _record(0, 0, RecordType.EOF)
        result = parse(ext + data + eof)
        assert result.base_address == 0x0020_0000
        assert result.record_count == 1


class TestEOF:
    """Type-1 EOF records terminate parsing; trailing records after EOF
    are ignored."""

    def test_stops_parsing(self) -> None:
        r1 = _record(2, 0x0000, RecordType.DATA, b"\x11\x22")
        eof = _record(0, 0x0000, RecordType.EOF)
        r2 = _record(2, 0x0010, RecordType.DATA, b"\x33\x44")
        result = parse(r1 + eof + r2)
        assert result.record_count == 1


class TestNullPadding:
    """All-zero 4-byte regions between records are silently skipped
    (they're padding, not malformed records)."""

    def test_leading_nulls_skipped(self) -> None:
        padding = b"\x00" * 8
        data = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB")
        result = parse(padding + data)
        assert result.record_count == 1
        assert bytes(result.data[:2]) == b"\xAA\xBB"

    def test_all_nulls_produces_nothing(self) -> None:
        result = parse(b"\x00" * 32)
        assert result.record_count == 0


class TestErrorSurfacing:
    """The parser used to silently skip several malformed inputs.
    These tests pin the new behavior: errors are surfaced via
    ``ParseResult.errors`` so callers can detect corruption."""

    def test_truncated_record_logged(self) -> None:
        # byte_count=8 but only 2 data bytes follow → truncated.
        truncated = bytes([8, 0, 0, RecordType.DATA, 0xAA, 0xBB])
        result = parse(truncated)
        assert any("Truncated" in e for e in result.errors)

    def test_unknown_record_type_logged(self) -> None:
        # Type 0x05 is not one we handle; should be flagged, not silently
        # swallowed (which advanced pos and read subsequent records as if
        # nothing happened).
        unknown = _record(2, 0x0000, 0x05, b"\xAA\xBB")
        eof = _record(0, 0x0000, RecordType.EOF)
        result = parse(unknown + eof)
        assert any("Unknown record type 0x05" in e for e in result.errors)

    def test_extended_address_byte_count_too_small_logged(self) -> None:
        # Extended-linear-address needs >=2 data bytes; the old code
        # silently ignored short ones, leaving base_address wrong.
        bad_ext = _record(1, 0, RecordType.EXTENDED_LINEAR_ADDRESS, b"\x00")
        eof = _record(0, 0, RecordType.EOF)
        result = parse(bad_ext + eof)
        assert any("byte_count=1" in e for e in result.errors)
        assert result.base_address == 0

    def test_trailing_non_padding_logged(self) -> None:
        # No EOF marker, and trailing bytes aren't 0x00/0xFF padding.
        data = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB")
        trailing = b"\x42\x42\x42"
        result = parse(data + trailing)
        assert any("trailing" in e for e in result.errors)

    def test_immutable_result(self) -> None:
        """ParseResult is frozen — consumers can't mutate it accidentally."""
        result = parse(_record(0, 0, RecordType.EOF))
        # Ensure data is bytes (not bytearray) and errors is a tuple.
        assert isinstance(result.data, bytes)
        assert isinstance(result.errors, tuple)
