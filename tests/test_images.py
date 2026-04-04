"""Tests for image extraction."""

import struct

from thd75_fw.images import Image, load

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
    # Header (48 bytes)
    header = bytearray(0x30)
    header[0:10] = b"1.00.02.00"

    # Calculate offsets
    table_size = png_count * 4
    first_png_offset = 0x30 + table_size
    total_size = first_png_offset + png_count * len(_MINIMAL_PNG)

    struct.pack_into("<I", header, 0x20, total_size)
    struct.pack_into("<I", header, 0x24, 1)
    struct.pack_into("<I", header, 0x28, 0x30)

    # Offset table
    table = bytearray(table_size)
    for i in range(png_count):
        offset = first_png_offset + i * len(_MINIMAL_PNG)
        struct.pack_into("<I", table, i * 4, offset)

    # PNG data
    png_data = _MINIMAL_PNG * png_count

    return bytes(header) + bytes(table) + png_data


class TestLoad:
    def test_basic_load(self) -> None:
        data = _make_image_db(3)
        db = load(data)
        assert len(db.images) == 3

    def test_valid_pngs(self) -> None:
        data = _make_image_db(5)
        db = load(data)
        assert db.valid_count == 5

    def test_version(self) -> None:
        data = _make_image_db(1)
        db = load(data)
        assert "1.00" in db.version

    def test_too_small_raises(self) -> None:
        try:
            load(b"\x00" * 10)
            raise AssertionError("Should have raised")
        except ValueError:
            pass


class TestImage:
    def test_is_valid_png(self) -> None:
        img = Image(index=0, offset=0, data=_MINIMAL_PNG)
        assert img.is_valid_png

    def test_invalid_png(self) -> None:
        img = Image(index=0, offset=0, data=b"\x00" * 10)
        assert not img.is_valid_png

    def test_save(self, tmp_path: object) -> None:
        from pathlib import Path

        img = Image(index=0, offset=0, data=_MINIMAL_PNG)
        out = Path(str(tmp_path)) / "test.png"
        img.save(out)
        assert out.read_bytes() == _MINIMAL_PNG
