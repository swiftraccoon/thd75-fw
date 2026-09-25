"""Synthetic 8-bit PNG builder for theme tests (independent of the decoder)."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from thd75_fw.theme.colour import RGB

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True, slots=True, kw_only=True)
class PngHeader:
    """The IHDR fields a synthetic PNG varies.

    :func:`build_png` fixes the rest: bit depth 8, deflate compression, filter
    method 0 and no interlace.

    Attributes:
        width: Image width in pixels.
        height: Image height in pixels.
        colour_type: IHDR colour type: 0 for grayscale, 3 for indexed.

    """

    width: int
    height: int
    colour_type: int


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _paeth(left: int, up: int, up_left: int) -> int:
    estimate = left + up - up_left
    distance_left = abs(estimate - left)
    distance_up = abs(estimate - up)
    distance_up_left = abs(estimate - up_left)
    if distance_left <= distance_up and distance_left <= distance_up_left:
        return left
    return up if distance_up <= distance_up_left else up_left


def _filter_line(filter_type: int, line: bytes, previous: bytes) -> bytes:
    out = bytearray(len(line))
    for index, raw in enumerate(line):
        left = line[index - 1] if index else 0
        up = previous[index]
        up_left = previous[index - 1] if index else 0
        if filter_type == 0:
            predictor = 0
        elif filter_type == 1:
            predictor = left
        elif filter_type == 2:
            predictor = up
        elif filter_type == 3:
            predictor = (left + up) >> 1
        elif filter_type == 4:
            predictor = _paeth(left, up, up_left)
        else:
            msg = f"unsupported filter {filter_type}"
            raise ValueError(msg)
        out[index] = (raw - predictor) & 0xFF
    return bytes(out)


def build_png(
    header: PngHeader,
    pixels: bytes,
    palette: Sequence[RGB] | None = None,
    filter_type: int = 0,
) -> bytes:
    """Encode one-byte-per-pixel data as a non-interlaced 8-bit PNG.

    Args:
        header: Dimensions and colour type written to IHDR.
        pixels: ``width * height`` pixel bytes, row by row.
        palette: PLTE entries, or ``None`` to write no PLTE chunk.
        filter_type: Scanline filter applied to every row, 0..4.

    Returns:
        The complete PNG file.

    Raises:
        ValueError: If ``pixels`` does not hold ``width * height`` bytes, or
            ``filter_type`` is not 0..4.

    """
    width, height = header.width, header.height
    if len(pixels) != width * height:
        msg = "pixel count does not match dimensions"
        raise ValueError(msg)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, header.colour_type, 0, 0, 0)
    raw = bytearray()
    previous = bytes(width)
    for row in range(height):
        line = pixels[row * width : (row + 1) * width]
        raw.append(filter_type)
        raw += _filter_line(filter_type, line, previous)
        previous = line
    chunks = [_chunk(b"IHDR", ihdr)]
    if palette is not None:
        chunks.append(_chunk(b"PLTE", bytes(c for entry in palette for c in entry)))
    chunks.append(_chunk(b"IDAT", zlib.compress(bytes(raw))))
    chunks.append(_chunk(b"IEND", b""))
    return PNG_SIGNATURE + b"".join(chunks)
