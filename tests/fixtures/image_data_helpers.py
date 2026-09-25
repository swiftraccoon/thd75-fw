"""Synthetic IMAGE_DATA sections shaped like the V1.03 layout."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

HEADER_SIZE = 0x30
TABLE_OFFSET_FIELD = 0x28
PALETTE_POINTER_FIELD = 0x2C


def build_image_data(
    pngs: Sequence[bytes],
    palettes: Sequence[Sequence[int]],
    padding: int = 64,
) -> bytes:
    """Header, PNG offset table, PNG data, 18-entry palette table, palettes, 0xFF padding."""
    if len(palettes) != 18:
        msg = "the firmware expects exactly 18 palettes"
        raise ValueError(msg)
    header = bytearray(HEADER_SIZE)
    header[0:11] = b"1.00.02.00\x00"  # stock V1.03 header version, NUL-terminated
    struct.pack_into("<I", header, 0x24, 1)
    struct.pack_into("<I", header, TABLE_OFFSET_FIELD, HEADER_SIZE)
    offset_table_size = 4 * len(pngs)
    cursor = HEADER_SIZE + offset_table_size
    offsets: list[int] = []
    body = bytearray()
    for png in pngs:
        offsets.append(cursor + len(body))
        body += png
    palette_table_offset = cursor + len(body)
    struct.pack_into("<I", header, PALETTE_POINTER_FIELD, palette_table_offset)
    palette_data = bytearray()
    palette_offsets: list[int] = []
    palette_base = palette_table_offset + 4 * 18
    for entries in palettes:
        palette_offsets.append(palette_base + len(palette_data))
        palette_data += struct.pack(f"<{len(entries)}H", *entries)
    out = bytearray(header)
    out += struct.pack(f"<{len(pngs)}I", *offsets)
    out += body
    out += struct.pack("<18I", *palette_offsets)
    out += palette_data
    out += b"\xff" * padding
    return bytes(out)
