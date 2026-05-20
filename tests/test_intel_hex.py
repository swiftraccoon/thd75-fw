"""Tests for the Intel HEX parser."""

from __future__ import annotations

import pytest

from thd75_fw.intel_hex import (
    ParseResult,
    Record,
    RecordType,
    iter_records,
    parse,
    patch_image,
    record_checksum,
    to_text_lines,
)
from thd75_fw.patch import ByteChange, PatchVerificationError


def _record(
    byte_count: int,
    addr: int,
    rec_type: int,
    data: bytes = b"",
    checksum: int | None = None,
) -> bytes:
    """Build a raw packed Intel HEX record.

    ``checksum=None`` (the default) auto-computes the correct
    two's-complement byte. Pass an explicit ``checksum`` to construct
    a *bad* record for negative testing.
    """
    header = [byte_count, (addr >> 8) & 0xFF, addr & 0xFF, rec_type, *data]
    if checksum is None:
        checksum = (-sum(header)) & 0xFF
    return bytes([*header, checksum])


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

    def test_bad_record_checksum_logged(self) -> None:
        # A data record with a wrong checksum byte must be flagged.
        # ``_record`` auto-computes the correct checksum when not given;
        # passing checksum=0 here forces a known-bad value.
        bad = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB", checksum=0x00)
        eof = _record(0, 0, RecordType.EOF)
        result = parse(bad + eof)
        assert any("Bad record checksum" in e for e in result.errors)

    def test_valid_record_checksum_silent(self) -> None:
        # The auto-computed checksum from ``_record`` is correct; parse
        # must not flag valid records.
        good = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB")
        eof = _record(0, 0, RecordType.EOF)
        result = parse(good + eof)
        assert all("checksum" not in e for e in result.errors)

    def test_stream_without_eof_logged(self) -> None:
        # A stream that ends after a valid data record but with no EOF
        # marker is a truncation signal — the radio's loader expects
        # EOF; the absence of one cannot be ruled out as corruption.
        data = _record(2, 0x0000, RecordType.DATA, b"\xAA\xBB")
        # No trailing bytes, no EOF — just the data record.
        result = parse(data)
        assert any("EOF" in e for e in result.errors)

    def test_eof_only_stream_does_not_complain_about_missing_eof(self) -> None:
        # An EOF record by itself is a legitimate (if degenerate)
        # stream — the missing-EOF guard should not fire.
        result = parse(_record(0, 0, RecordType.EOF))
        assert all("EOF" not in e for e in result.errors)


class TestRecordChecksum:
    """A record's checksum byte is the two's-complement of the sum of
    every other byte (count + address + type + data) — so the whole
    record sums to zero mod 256. ``record_checksum`` recomputes it for
    a record whose data bytes have been edited."""

    def test_canonical_spec_record(self) -> None:
        # The Intel HEX specification's own example record:
        #   :10010000214601360121470136007EFE09D2190140
        # Everything before the trailing 0x40 is the checksummed payload.
        payload = bytes.fromhex("10010000214601360121470136007EFE09D21901")
        assert record_checksum(payload) == 0x40

    def test_firmware_record(self) -> None:
        # A real TH-D75 FIRMWARE data record (the one covering flat image
        # offset 0x10444). Its stored checksum byte is 0x1F.
        payload = bytes.fromhex("10044000000E01001B2908DA9A4A490051184A78")
        assert record_checksum(payload) == 0x1F

    def test_patch_shifts_checksum_by_negated_delta(self) -> None:
        # Raising one data byte by 0x18 (the PF-key patch: 0x1B -> 0x33)
        # must lower the checksum by 0x18 so the record still sums to zero.
        original = bytes.fromhex("10044000000E01001B2908DA9A4A490051184A78")
        patched = bytes.fromhex("10044000000E0100332908DA9A4A490051184A78")
        assert record_checksum(patched) == (record_checksum(original) - 0x18) & 0xFF

    def test_empty_payload_checksums_to_zero(self) -> None:
        # Degenerate but well-defined: an empty payload sums to 0, and the
        # two's-complement of 0 is 0.
        assert record_checksum(b"") == 0x00


class TestIterRecords:
    """``iter_records`` walks a packed Intel HEX stream and yields one
    ``Record`` per record, tracking the extended-linear base address so
    each data record maps to a flat-image offset."""

    def test_single_data_record_fields(self) -> None:
        raw = _record(4, 0x0040, RecordType.DATA, b"\xAA\xBB\xCC\xDD", 0x11)
        records = list(iter_records(raw))
        assert len(records) == 1
        rec: Record = records[0]
        assert rec.start == 0
        assert rec.byte_count == 4
        assert rec.address == 0x0040
        assert rec.record_type == RecordType.DATA
        assert rec.data == b"\xAA\xBB\xCC\xDD"
        assert rec.checksum == 0x11
        assert rec.base_address == 0

    def test_records_carry_their_stream_offset(self) -> None:
        r1 = _record(2, 0, RecordType.DATA, b"\x01\x02")
        r2 = _record(3, 0, RecordType.DATA, b"\x03\x04\x05")
        records = list(iter_records(r1 + r2))
        assert [r.start for r in records] == [0, len(r1)]

    def test_extended_linear_address_updates_base(self) -> None:
        ext = _record(2, 0, RecordType.EXTENDED_LINEAR_ADDRESS, b"\x00\x01")
        data = _record(4, 0x0444, RecordType.DATA, b"\x00" * 4)
        records = list(iter_records(ext + data))
        # The data record sees base 0x0001_0000 → flat offset 0x10444.
        data_rec = records[1]
        assert data_rec.base_address == 0x0001_0000
        assert data_rec.base_address + data_rec.address == 0x10444

    def test_iteration_stops_at_eof(self) -> None:
        data = _record(2, 0, RecordType.DATA, b"\xAA\xBB")
        eof = _record(0, 0, RecordType.EOF)
        trailing = _record(2, 0, RecordType.DATA, b"\xCC\xDD")
        records = list(iter_records(data + eof + trailing))
        # EOF is yielded; records after it are not walked.
        assert [r.record_type for r in records] == [RecordType.DATA, RecordType.EOF]

    def test_truncated_record_raises(self) -> None:
        # A record claiming 8 data bytes with only 2 present is a real
        # error: silently stopping iteration would discard every later
        # record (an asymmetry with parse(), which surfaces truncation
        # via ParseResult.errors). Match the "loud failure" policy.
        truncated = bytes([8, 0, 0, RecordType.DATA, 0xAA, 0xBB])
        with pytest.raises(ValueError, match="truncated record"):
            list(iter_records(truncated))


class TestToTextLines:
    """``to_text_lines`` re-emits a packed Intel HEX stream as the
    standard textual ``:LLAAAATT...CC`` lines a plaintext .KEX file
    uses — one record per line, uppercase hex."""

    def test_single_record(self) -> None:
        raw = _record(2, 0x0010, RecordType.DATA, b"\xAB\xCD", 0x7A)
        assert to_text_lines(raw) == [":02001000ABCD7A"]

    def test_one_line_per_record(self) -> None:
        raw = _record(2, 0, RecordType.DATA, b"\x11\x22", 0xCB) + _record(
            0, 0, RecordType.EOF, b"", 0xFF
        )
        assert to_text_lines(raw) == [":020000001122CB", ":00000001FF"]

    def test_real_firmware_record_round_trips(self) -> None:
        # The real FIRMWARE record covering flat offset 0x10444: its
        # textual form must come back byte-identical.
        line = ":10044000000E01001B2908DA9A4A490051184A781F"
        assert to_text_lines(bytes.fromhex(line[1:])) == [line]


class TestPatchImage:
    """``patch_image`` edits bytes of a packed Intel HEX stream by
    flat-image offset, verifying each change's `expect` against the
    current byte before writing."""

    def test_patches_addressed_byte(self) -> None:
        raw = _record(4, 0x0000, RecordType.DATA, b"\x00\x11\x22\x33") + _record(
            0, 0, RecordType.EOF
        )
        out = parse(patch_image(raw, [ByteChange(offset=2, expect=0x22, value=0xFF)]))
        assert out.data == b"\x00\x11\xFF\x33"

    def test_patch_keeps_record_checksum_valid(self) -> None:
        payload = bytes([4, 0x00, 0x00, RecordType.DATA, 0x00, 0x11, 0x22, 0x33])
        raw = (
            payload
            + bytes([record_checksum(payload)])
            + _record(0, 0, RecordType.EOF)
        )
        out = patch_image(raw, [ByteChange(offset=1, expect=0x11, value=0x99)])
        data_rec = next(
            r for r in iter_records(out) if r.record_type == RecordType.DATA
        )
        whole = out[data_rec.start : data_rec.start + 4 + data_rec.byte_count + 1]
        assert sum(whole) % 256 == 0

    def test_offset_resolved_through_extended_base(self) -> None:
        stream = (
            _record(2, 0, RecordType.EXTENDED_LINEAR_ADDRESS, b"\x00\x01")
            + _record(4, 0x0444, RecordType.DATA, b"\xAA\xBB\xCC\xDD")
            + _record(0, 0, RecordType.EOF)
        )
        out = parse(patch_image(
            stream, [ByteChange(offset=0x10446, expect=0xCC, value=0xEE)],
        ))
        assert out.data[0x10446] == 0xEE

    def test_multiple_patches_in_one_call(self) -> None:
        raw = _record(8, 0, RecordType.DATA, bytes(8)) + _record(
            0, 0, RecordType.EOF
        )
        out = parse(patch_image(raw, [
            ByteChange(offset=0, expect=0x00, value=0xA1),
            ByteChange(offset=7, expect=0x00, value=0xB2),
        ]))
        assert out.data[0] == 0xA1
        assert out.data[7] == 0xB2

    def test_offset_outside_any_data_record_raises(self) -> None:
        raw = _record(2, 0, RecordType.DATA, b"\x00\x00") + _record(
            0, 0, RecordType.EOF
        )
        with pytest.raises(ValueError, match="not in any data record"):
            patch_image(raw, [ByteChange(offset=0x9999, expect=0, value=1)])

    def test_expect_mismatch_raises(self) -> None:
        # Current byte at offset 0 is 0x00, but we declare expect=0x99.
        raw = _record(2, 0x0000, RecordType.DATA, b"\x00\xFF") + _record(
            0, 0, RecordType.EOF
        )
        with pytest.raises(
            PatchVerificationError,
            match=r"offset 0x0: expected 0x99 but firmware has 0x00",
        ):
            patch_image(raw, [ByteChange(offset=0, expect=0x99, value=0x42)])
