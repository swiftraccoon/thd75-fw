"""The IMAGE_DATA secondary table: 18 RGB565 display palettes.

Header word 0x2C points at a table of 18 little-endian u32 offsets, each
the start of one palette of u16 RGB565 entries. The firmware loads them
as nine pairs ``{palette[i], palette[i + 9]}`` for the Black and White
schemes. Palette lengths are implicit: each palette ends where the next
begins and the last ends where the section's 0xFF padding begins.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__: list[str] = [
    "PALETTE_COUNT",
    "PALETTE_TABLE_POINTER_OFFSET",
    "PaletteTable",
    "load_palette_table",
    "pack_palette",
    "read_palette",
]

PALETTE_COUNT: int = 18
PALETTE_TABLE_POINTER_OFFSET: int = 0x2C
_PADDING: bytes = b"\xff"


@dataclass(frozen=True, slots=True)
class PaletteTable:
    """Byte spans of the 18 palettes within IMAGE_DATA."""

    starts: tuple[int, ...]
    ends: tuple[int, ...]

    def span(self, index: int) -> tuple[int, int]:
        """``(start, end)`` byte offsets of palette ``index``."""
        return self.starts[index], self.ends[index]


def load_palette_table(image_data: bytes) -> PaletteTable:
    """Locate the 18 palettes.

    Raises:
        ValueError: if the pointer or an offset lies outside the section,
            offsets are not ascending, or a palette has an odd or empty span.

    """
    if len(image_data) < PALETTE_TABLE_POINTER_OFFSET + 4:
        msg = "IMAGE_DATA too small for a palette table pointer"
        raise ValueError(msg)
    pointer = struct.unpack_from("<I", image_data, PALETTE_TABLE_POINTER_OFFSET)[0]
    if pointer + 4 * PALETTE_COUNT > len(image_data):
        msg = f"palette table at 0x{pointer:X} lies outside IMAGE_DATA"
        raise ValueError(msg)
    starts = struct.unpack_from(f"<{PALETTE_COUNT}I", image_data, pointer)
    if starts[0] < pointer + 4 * PALETTE_COUNT:
        msg_0 = "first palette offset lies inside the palette table"
        raise ValueError(msg_0)
    for index in range(1, PALETTE_COUNT):
        if starts[index] < starts[index - 1]:
            msg = f"palette offsets are not ascending at index {index}"
            raise ValueError(msg)
    used = len(image_data.rstrip(_PADDING))
    ends = (*starts[1:], used)
    for index, (start, end) in enumerate(zip(starts, ends, strict=True)):
        if end > len(image_data) or end <= start or (end - start) % 2:
            msg = f"palette {index} has an invalid span 0x{start:X}..0x{end:X}"
            raise ValueError(msg)
    return PaletteTable(starts=tuple(starts), ends=ends)


def read_palette(image_data: bytes, table: PaletteTable, index: int) -> tuple[int, ...]:
    """Return the RGB565 entries of palette ``index``."""
    start, end = table.span(index)
    count = (end - start) // 2
    return tuple(struct.unpack_from(f"<{count}H", image_data, start))


def pack_palette(entries: Sequence[int]) -> bytes:
    """Little-endian u16 bytes of ``entries``."""
    return struct.pack(f"<{len(entries)}H", *entries)
