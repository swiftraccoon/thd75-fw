"""Tests for the IMAGE_DATA palette table reader."""

from __future__ import annotations

import pytest

from tests.fixtures.image_data_helpers import build_image_data
from tests.fixtures.png_helpers import PngHeader, build_png
from thd75_fw import images
from thd75_fw.theme.palettes import (
    PALETTE_COUNT,
    load_palette_table,
    pack_palette,
    read_palette,
)

_GRAY_1X1 = PngHeader(width=1, height=1, colour_type=0)


def _palettes() -> list[list[int]]:
    return [[0x0000, 0xFFFF, 0xF81F, 0x0010 * i] for i in range(PALETTE_COUNT)]


class TestPaletteTable:
    def test_reads_all_eighteen_palettes(self) -> None:
        pngs = [build_png(_GRAY_1X1, b"\x00")]
        data = build_image_data(pngs, _palettes())
        table = load_palette_table(data)
        assert len(table.starts) == PALETTE_COUNT
        for index in range(PALETTE_COUNT):
            assert read_palette(data, table, index) == (
                0x0000,
                0xFFFF,
                0xF81F,
                0x0010 * index,
            )
        assert images.load(data).valid_count == 1

    def test_last_palette_ends_where_padding_begins(self) -> None:
        data = build_image_data([build_png(_GRAY_1X1, b"\x00")], _palettes(), padding=8)
        table = load_palette_table(data)
        start, end = table.span(PALETTE_COUNT - 1)
        assert end - start == 8
        assert data[end:] == b"\xff" * 8

    def test_pointer_outside_data_rejected(self) -> None:
        data = bytearray(build_image_data([build_png(_GRAY_1X1, b"\x00")], _palettes()))
        data[0x2C:0x30] = (len(data) + 100).to_bytes(4, "little")
        with pytest.raises(ValueError, match="palette table"):
            _ = load_palette_table(bytes(data))

    def test_descending_offsets_rejected(self) -> None:
        palettes = _palettes()
        data = bytearray(build_image_data([build_png(_GRAY_1X1, b"\x00")], palettes))
        table = load_palette_table(bytes(data))
        first, second = table.starts[0], table.starts[1]
        pointer = int.from_bytes(data[0x2C:0x30], "little")
        data[pointer : pointer + 4] = second.to_bytes(4, "little")
        data[pointer + 4 : pointer + 8] = first.to_bytes(4, "little")
        with pytest.raises(ValueError, match="ascending"):
            _ = load_palette_table(bytes(data))

    def test_pack_palette_is_little_endian(self) -> None:
        assert pack_palette([0x0000, 0xFC60]) == b"\x00\x00\x60\xfc"
