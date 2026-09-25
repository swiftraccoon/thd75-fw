"""Tests for PNG chunk handling and the 8-bit decoder."""

from __future__ import annotations

import struct
import zlib

import pytest

from tests.fixtures.png_helpers import PngHeader, build_png
from thd75_fw.theme.png import (
    Chunk,
    decode_8bit,
    find_chunk,
    is_indexed_8bit,
    iter_chunks,
    palette,
    replace_palette,
)

_PALETTE = [(0, 0, 0), (255, 255, 255), (255, 0, 255), (56, 160, 216)]
_PIXELS = bytes([0, 1, 2, 3, 3, 2, 1, 0, 1, 1, 2, 2])  # 4x3
_INDEXED_4X3 = PngHeader(width=4, height=3, colour_type=3)
_GRAY_4X3 = PngHeader(width=4, height=3, colour_type=0)


class TestChunks:
    def test_iter_chunks_walks_to_iend(self) -> None:
        png = build_png(_INDEXED_4X3, _PIXELS, _PALETTE)
        types = [chunk.type for chunk in iter_chunks(png)]
        assert types == [b"IHDR", b"PLTE", b"IDAT", b"IEND"]

    def test_chunk_offsets_point_at_data_and_crc(self) -> None:
        png = build_png(_INDEXED_4X3, _PIXELS, _PALETTE)
        plte = find_chunk(png, b"PLTE")
        assert isinstance(plte, Chunk)
        assert png[plte.data_offset : plte.data_offset + 3] == b"\x00\x00\x00"
        crc = int.from_bytes(png[plte.crc_offset : plte.crc_offset + 4], "big")
        assert crc == zlib.crc32(b"PLTE" + plte.data) & 0xFFFFFFFF

    def test_bad_signature_rejected(self) -> None:
        with pytest.raises(ValueError, match="signature"):
            _ = list(iter_chunks(b"GIF89a" + bytes(20)))

    def test_truncated_chunk_rejected(self) -> None:
        png = build_png(_INDEXED_4X3, _PIXELS, _PALETTE)
        with pytest.raises(ValueError, match=r"truncated|runs past the end"):
            _ = list(iter_chunks(png[:-6]))
        with pytest.raises(ValueError, match="runs past the end"):
            _ = list(iter_chunks(png[:-14]))

    def test_missing_chunk_rejected(self) -> None:
        png = build_png(_GRAY_4X3, _PIXELS)
        with pytest.raises(ValueError, match="no PLTE chunk"):
            _ = find_chunk(png, b"PLTE")


class TestPalette:
    def test_palette_reads_entries(self) -> None:
        png = build_png(_INDEXED_4X3, _PIXELS, _PALETTE)
        assert palette(png) == tuple(_PALETTE)

    def test_replace_palette_rewrites_entries_and_crc_only(self) -> None:
        png = build_png(_INDEXED_4X3, _PIXELS, _PALETTE)
        new_entries = [(0, 0, 0), (255, 140, 0), (255, 0, 255), (56, 160, 216)]
        out = replace_palette(png, new_entries)
        assert len(out) == len(png)
        assert palette(out) == tuple(new_entries)
        plte = find_chunk(out, b"PLTE")
        crc = int.from_bytes(out[plte.crc_offset : plte.crc_offset + 4], "big")
        assert crc == zlib.crc32(b"PLTE" + plte.data) & 0xFFFFFFFF
        differing = [i for i, (a, b) in enumerate(zip(png, out, strict=True)) if a != b]
        assert min(differing) >= plte.data_offset
        assert max(differing) < plte.crc_offset + 4
        assert decode_8bit(out).pixels == _PIXELS

    def test_replace_palette_entry_count_must_match(self) -> None:
        png = build_png(_INDEXED_4X3, _PIXELS, _PALETTE)
        with pytest.raises(ValueError, match="entries"):
            _ = replace_palette(png, _PALETTE[:2])


class TestDecoder:
    @pytest.mark.parametrize("filter_type", [0, 1, 2, 3, 4])
    def test_decodes_every_filter_type(self, filter_type: int) -> None:
        pixels = bytes(
            (row * 37 + col * 11) & 0x7F for row in range(5) for col in range(7)
        )
        decoded = decode_8bit(
            build_png(
                PngHeader(width=7, height=5, colour_type=0),
                pixels,
                filter_type=filter_type,
            )
        )
        assert (decoded.width, decoded.height, decoded.colour_type) == (7, 5, 0)
        assert decoded.pixels == pixels

    def test_indexed_and_grayscale_classification(self) -> None:
        assert is_indexed_8bit(build_png(_INDEXED_4X3, _PIXELS, _PALETTE))
        assert not is_indexed_8bit(build_png(_GRAY_4X3, _PIXELS))
        assert not is_indexed_8bit(b"not a png")

    def test_unsupported_depth_rejected(self) -> None:
        png = bytearray(build_png(_GRAY_4X3, _PIXELS))
        ihdr = find_chunk(bytes(png), b"IHDR")
        png[ihdr.data_offset + 8] = 16  # bit depth field
        data = bytes(png[ihdr.data_offset : ihdr.data_offset + 13])
        png[ihdr.crc_offset : ihdr.crc_offset + 4] = struct.pack(
            ">I", zlib.crc32(b"IHDR" + data) & 0xFFFFFFFF
        )
        with pytest.raises(ValueError, match="bit depth 8"):
            _ = decode_8bit(bytes(png))
