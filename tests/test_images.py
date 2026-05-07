"""Tests for image extraction."""

import struct
from pathlib import Path

import pytest

from thd75_fw.images import _PNG_SIGNATURE, Image, _find_png_end, load

# Minimal valid PNG: 1x1 pixel grayscale
_MINIMAL_PNG = (
    b"\x89PNG\r\n\x1a\n"  # signature
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x00"
    b"\x00\x00\x00:~\x9bU"  # IHDR
    b"\x00\x00\x00\nIDATx"
    b"\x9cc`\x00\x00\x00\x02\x00\x01\xe2!\xbc3"  # IDAT
    b"\x00\x00\x00\x00IEND\xaeB`\x82"  # IEND
)


def _make_image_db(png_count: int) -> bytes:
    """Build a minimal image database with valid PNGs."""
    header = bytearray(0x30)
    header[0:10] = b"1.00.02.00"

    table_size = png_count * 4
    first_png_offset = 0x30 + table_size
    total_size = first_png_offset + png_count * len(_MINIMAL_PNG)

    struct.pack_into("<I", header, 0x20, total_size)
    struct.pack_into("<I", header, 0x24, 1)
    struct.pack_into("<I", header, 0x28, 0x30)

    # Offset table — one entry per PNG
    table = bytearray(table_size)
    for i in range(png_count):
        offset = first_png_offset + i * len(_MINIMAL_PNG)
        struct.pack_into("<I", table, i * 4, offset)

    png_data = _MINIMAL_PNG * png_count

    return bytes(header) + bytes(table) + png_data


class TestLoad:
    """Database-level invariants: image count, header decoding, and
    explicit rejection of malformed inputs (out-of-range offsets,
    wrong table-offset field)."""

    def test_load_returns_one_image_per_offset_table_entry(self) -> None:
        database = load(_make_image_db(3))
        assert len(database.images) == 3

    def test_valid_count_matches_count_of_signature_carrying_images(self) -> None:
        database = load(_make_image_db(5))
        assert database.valid_count == 5

    def test_version_decoded_from_header(self) -> None:
        database = load(_make_image_db(1))
        assert "1.00" in database.version

    def test_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="too small"):
            load(b"\x00" * 10)

    def test_implausible_first_offset_raises(self) -> None:
        # First offset points to 0xDEADBEEF which is way past data end.
        data = bytearray(0x100)
        struct.pack_into("<I", data, 0x28, 0x30)  # table offset OK
        struct.pack_into("<I", data, 0x30, 0xDEADBEEF)  # bad first PNG offset
        with pytest.raises(ValueError, match="Implausible first-PNG offset"):
            load(bytes(data))

    def test_wrong_table_offset_raises(self) -> None:
        data = bytearray(0x100)
        struct.pack_into("<I", data, 0x28, 0x40)  # wrong: expected 0x30
        with pytest.raises(ValueError, match="Unexpected table offset"):
            load(bytes(data))


class TestImage:
    """Image dataclass behavior: PNG signature detection and save."""

    def test_is_valid_png_for_real_signature(self) -> None:
        image = Image(index=0, offset=0, data=_MINIMAL_PNG)
        assert image.is_valid_png

    def test_is_valid_png_false_for_zero_bytes(self) -> None:
        image = Image(index=0, offset=0, data=b"\x00" * 10)
        assert not image.is_valid_png

    def test_save_writes_bytes_verbatim(self, tmp_path: Path) -> None:
        image = Image(index=0, offset=0, data=_MINIMAL_PNG)
        out = tmp_path / "test.png"
        image.save(out)
        assert out.read_bytes() == _MINIMAL_PNG


class TestFindPngEnd:
    """Pin the PNG chunk-walker edge cases. The Wave 1 fix replaced
    a heuristic 'find IEND, trim trailing 0xFF' with a proper chunk
    walk, but the failure modes (no signature / truncated chunk /
    missing IEND) deserve explicit tests."""

    def test_walks_to_iend_for_valid_png(self) -> None:
        end = _find_png_end(_MINIMAL_PNG, 0, len(_MINIMAL_PNG))
        assert end == len(_MINIMAL_PNG)

    def test_invalid_signature_returns_start(self) -> None:
        # A region without a valid PNG signature → return start (zero bytes).
        # Image is then constructed with empty data and is_valid_png=False.
        not_a_png = b"NOT_A_PNG_AT_ALL_PADDING_BYTES_HERE"
        end = _find_png_end(not_a_png, 0, len(not_a_png))
        assert end == 0

    def test_signature_present_but_chunk_truncated(self) -> None:
        # PNG signature is present, but the first chunk's declared length
        # extends past max_end → return max_end (truncated chunk fallback).
        # Build: signature + chunk header claiming 10000 bytes, but only
        # 5 bytes of padding after.
        truncated = _PNG_SIGNATURE + b"\x00\x00\x27\x10IDAT" + b"\x00" * 5
        end = _find_png_end(truncated, 0, len(truncated))
        assert end == len(truncated)

    def test_no_iend_found(self) -> None:
        # Signature + a complete IDAT chunk (length=4, type, 4 data bytes,
        # 4 CRC) but no IEND. Walker should finish the loop and return
        # max_end as a fallback (preserves whatever padding follows).
        idat_chunk = b"\x00\x00\x00\x04IDAT" + b"\x00" * 4 + b"\xCA\xFE\xBA\xBE"
        no_iend = _PNG_SIGNATURE + idat_chunk
        end = _find_png_end(no_iend, 0, len(no_iend))
        assert end == len(no_iend)
