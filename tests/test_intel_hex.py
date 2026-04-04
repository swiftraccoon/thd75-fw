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
    def test_sets_base(self) -> None:
        ext = _record(2, 0, RecordType.EXTENDED_LINEAR_ADDRESS, b"\x00\x20")
        data = _record(4, 0, RecordType.DATA, b"\xAA\xBB\xCC\xDD")
        eof = _record(0, 0, RecordType.EOF)
        result = parse(ext + data + eof)
        assert result.base_address == 0x0020_0000
        assert result.record_count == 1


class TestEOF:
    def test_stops_parsing(self) -> None:
        r1 = _record(2, 0x0000, RecordType.DATA, b"\x11\x22")
        eof = _record(0, 0x0000, RecordType.EOF)
        r2 = _record(2, 0x0010, RecordType.DATA, b"\x33\x44")
        result = parse(r1 + eof + r2)
        assert result.record_count == 1


class TestNullPadding:
    def test_leading_nulls_skipped(self) -> None:
        padding = b"\x00" * 8
        data = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB")
        result = parse(padding + data)
        assert result.record_count == 1
        assert bytes(result.data[:2]) == b"\xAA\xBB"

    def test_all_nulls_produces_nothing(self) -> None:
        result = parse(b"\x00" * 32)
        assert result.record_count == 0
