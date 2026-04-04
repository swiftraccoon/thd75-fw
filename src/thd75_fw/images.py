"""Image extraction from the TH-D75 IMAGE_DATA section.

The image section contains 862 PNG images used for the radio's display.
Images include APRS symbols, status icons, splash screens, menu labels,
and UI elements in various sizes from 1x10 to 240x180 pixels.

File layout::

    0x0000-0x002F  Header (version string, data size, table offsets)
    0x0030-0x0DA7  PNG offset table (862 × 4-byte LE offsets)
    0x0DA8-EOF     PNG image data (concatenated, individually valid PNGs)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

__all__: list[str] = [
    "Image",
    "ImageDatabase",
    "load",
]

_OFFSET_TABLE_START: int = 0x30
_PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True, slots=True)
class Image:
    """A single PNG image from the image database."""

    index: int
    offset: int
    data: bytes

    @property
    def is_valid_png(self) -> bool:
        """Check if the data starts with a valid PNG signature."""
        return self.data[:8] == _PNG_SIGNATURE

    def save(self, path: Path) -> None:
        """Write this image to a file."""
        path.write_bytes(self.data)


@dataclass(frozen=True, slots=True)
class ImageDatabase:
    """Parsed image database."""

    version: str
    images: tuple[Image, ...]

    @property
    def valid_count(self) -> int:
        """Number of images with valid PNG signatures."""
        return sum(1 for img in self.images if img.is_valid_png)


def load(data: bytes) -> ImageDatabase:
    """Parse an image database from raw binary data.

    Args:
        data: Raw bytes of the IMAGE_DATA section.

    Returns:
        An ``ImageDatabase`` with all extracted PNG images.

    Raises:
        ValueError: If the data is too small or the header is invalid.
    """
    if len(data) < _OFFSET_TABLE_START:
        msg = f"Data too small: {len(data)} bytes"
        raise ValueError(msg)

    # Parse header
    version = data[0:11].rstrip(b"\x00\xff").decode("ascii", errors="replace")
    table_offset = struct.unpack_from("<I", data, 0x28)[0]

    if table_offset != _OFFSET_TABLE_START:
        msg = f"Unexpected table offset: 0x{table_offset:X} (expected 0x{_OFFSET_TABLE_START:X})"
        raise ValueError(msg)

    # Read offset table — entries are 4-byte LE offsets to PNG data
    # The first PNG starts right after the table, which tells us the entry count
    first_png_offset = struct.unpack_from("<I", data, _OFFSET_TABLE_START)[0]
    entry_count = (first_png_offset - _OFFSET_TABLE_START) // 4

    offsets: list[int] = []
    for i in range(entry_count):
        off = struct.unpack_from("<I", data, _OFFSET_TABLE_START + i * 4)[0]
        offsets.append(off)

    # Extract images — each PNG runs from its offset to the next offset
    images: list[Image] = []
    for i in range(entry_count):
        start = offsets[i]
        end = offsets[i + 1] if i + 1 < entry_count else len(data)

        # Trim trailing 0xFF padding
        while end > start and data[end - 1] == 0xFF:
            end -= 1

        if start >= len(data):
            break

        # Find actual PNG end by searching for IEND chunk
        png_end = _find_png_end(data, start, end)

        images.append(Image(
            index=i,
            offset=start,
            data=data[start:png_end],
        ))

    return ImageDatabase(
        version=version,
        images=tuple(images),
    )


def _find_png_end(data: bytes, start: int, max_end: int) -> int:
    """Find the end of a PNG image (after IEND chunk).

    PNG files end with the IEND chunk: 4-byte length (0) + 'IEND' + 4-byte CRC.
    """
    iend_marker = b"IEND"
    pos = data.find(iend_marker, start, max_end)
    if pos >= 0:
        return pos + 4 + 4  # IEND tag + CRC32
    return max_end
