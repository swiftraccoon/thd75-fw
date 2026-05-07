"""Image extraction from the TH-D75 IMAGE_DATA section.

The input to ``load()`` is the raw byte content of the IMAGE_DATA section
as written by ``thd75-extract`` — i.e., the post-decryption,
post-Intel-HEX byte-stitched output of the upstream pipeline (see
``thd75_fw.file_cipher`` and ``thd75_fw.intel_hex``).

The image section contains 862 PNG images used for the radio's display.
Images include APRS symbols, status icons, splash screens, menu labels,
and UI elements in various sizes from 1x10 to 240x180 pixels.

File layout::

    0x0000-0x002F  Header (version string, data size, table offsets)
    0x0030-0x0DA7  PNG offset table (862 x 4-byte LE offsets)
    0x0DA8-EOF     PNG image data (concatenated, individually valid PNGs)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__: list[str] = [
    "Image",
    "ImageDatabase",
    "load",
]

_OFFSET_TABLE_START: int = 0x30
_PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"

# Header field locations within IMAGE_DATA (V1.03 layout).
_HEADER_VERSION = slice(0, 11)
_HEADER_TABLE_OFFSET_FIELD = 0x28  # uint32 LE; should equal _OFFSET_TABLE_START
_OFFSET_ENTRY_SIZE = 4             # bytes per offset-table entry


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
        ValueError: If the data is too small, the header is invalid,
            the offset table is implausible, or any image starts
            past the end of data (would-be silent truncation).
    """
    if len(data) < _OFFSET_TABLE_START + _OFFSET_ENTRY_SIZE:
        msg = f"Data too small: {len(data)} bytes"
        raise ValueError(msg)

    # Parse header
    version = data[_HEADER_VERSION].rstrip(b"\x00\xff").decode(
        "ascii", errors="replace"
    )
    table_offset = struct.unpack_from("<I", data, _HEADER_TABLE_OFFSET_FIELD)[0]

    if table_offset != _OFFSET_TABLE_START:
        msg = f"Unexpected table offset: 0x{table_offset:X} (expected 0x{_OFFSET_TABLE_START:X})"
        raise ValueError(msg)

    # Read offset table — the first PNG starts immediately after the table,
    # so its offset tells us the entry count.
    first_png_offset = struct.unpack_from("<I", data, _OFFSET_TABLE_START)[0]
    if first_png_offset <= _OFFSET_TABLE_START or first_png_offset > len(data):
        msg = (
            f"Implausible first-PNG offset 0x{first_png_offset:X} "
            f"(table starts at 0x{_OFFSET_TABLE_START:X}, data ends at 0x{len(data):X})"
        )
        raise ValueError(msg)
    entry_count = (first_png_offset - _OFFSET_TABLE_START) // _OFFSET_ENTRY_SIZE

    offsets: list[int] = []
    for i in range(entry_count):
        offset_pos = _OFFSET_TABLE_START + i * _OFFSET_ENTRY_SIZE
        png_offset = struct.unpack_from("<I", data, offset_pos)[0]
        offsets.append(png_offset)

    # Extract images — each PNG runs from its offset to the next offset
    images: list[Image] = []
    for i in range(entry_count):
        start = offsets[i]
        end = offsets[i + 1] if i + 1 < entry_count else len(data)

        if start >= len(data):
            msg = (
                f"Image {i} starts at offset 0x{start:X} which is past "
                f"end of data (0x{len(data):X})"
            )
            raise ValueError(msg)
        if start >= end:
            msg = f"Image {i} has invalid range: start=0x{start:X}, end=0x{end:X}"
            raise ValueError(msg)

        # Find proper PNG end by walking chunks. This is exact (not heuristic),
        # so no trailing-padding trim is needed — the chunk walk stops at IEND
        # and any 0xFF padding between this PNG and the next is correctly excluded.
        png_end = _find_png_end(data, start, min(end, len(data)))

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
    """Find the end of a PNG image by walking chunks until IEND.

    Each PNG chunk has the format::

        length (4 bytes, big-endian) | type (4 bytes) | data (length bytes) | CRC (4 bytes)

    Returns the offset just past the IEND chunk's CRC, or ``start`` if the
    PNG signature is invalid, or ``max_end`` if a chunk extends past the
    boundary (truncated/corrupt PNG).
    """
    if max_end - start < 8 or data[start : start + 8] != _PNG_SIGNATURE:
        return start  # No valid PNG signature

    pos = start + 8  # Skip signature
    while pos + 12 <= max_end:  # 8-byte chunk header + at least 4-byte CRC
        chunk_len = int.from_bytes(data[pos : pos + 4], "big")
        chunk_type = data[pos + 4 : pos + 8]
        chunk_end = pos + 8 + chunk_len + 4  # header + data + CRC
        if chunk_end > max_end:
            return max_end  # Truncated chunk
        if chunk_type == b"IEND":
            return chunk_end
        pos = chunk_end
    return max_end
