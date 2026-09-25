"""Minimal PNG handling for the image database: chunks, PLTE edits, 8-bit decoding.

The firmware's images are non-interlaced 8-bit PNGs, either grayscale
(colour type 0, whose pixel values are palette indices for the display
palettes) or indexed (colour type 3, whose PLTE holds the colours). This
module edits PLTE chunks in place and decodes pixel data for twin
detection. It needs nothing beyond ``zlib``.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from .colour import RGB

__all__: list[str] = [
    "PNG_SIGNATURE",
    "Chunk",
    "Decoded",
    "decode_8bit",
    "find_chunk",
    "is_indexed_8bit",
    "iter_chunks",
    "palette",
    "replace_palette",
]

PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"
_IHDR_LENGTH: int = 13
_GRAYSCALE: int = 0
_INDEXED: int = 3
_BIT_DEPTH: Final[int] = 8
"""The only IHDR bit depth this module handles."""
_PLTE_COMPONENT_MAX: Final[int] = 0xFF
"""Largest value of one PLTE colour component (one byte)."""

# PNG scanline filter types: the byte that starts every row of pixel data.
_FILTER_NONE: Final[int] = 0
_FILTER_SUB: Final[int] = 1
_FILTER_UP: Final[int] = 2
_FILTER_AVERAGE: Final[int] = 3
_FILTER_PAETH: Final[int] = 4


@dataclass(frozen=True, slots=True)
class Chunk:
    """One PNG chunk located within its file.

    ``offset`` is the position of the 4-byte length field; ``data_offset``
    and ``crc_offset`` locate the payload and the CRC-32 that follows it.
    """

    offset: int
    type: bytes
    data: bytes

    @property
    def data_offset(self) -> int:
        """Position of the payload, after the 4-byte length and 4-byte type."""
        return self.offset + 8

    @property
    def crc_offset(self) -> int:
        """Position of the CRC-32 that follows the payload."""
        return self.offset + 8 + len(self.data)


def iter_chunks(png: bytes) -> Iterator[Chunk]:
    """Yield every chunk in order, stopping after IEND.

    Raises:
        ValueError: on a bad signature or a chunk that runs past the end.

    """
    if png[:8] != PNG_SIGNATURE:
        msg = "not a PNG: bad signature"
        raise ValueError(msg)
    position = 8
    while True:
        if position + 12 > len(png):
            msg = f"truncated chunk header at offset {position}"
            raise ValueError(msg)
        length = int.from_bytes(png[position : position + 4], "big")
        chunk_type = png[position + 4 : position + 8]
        end = position + 12 + length
        if end > len(png):
            msg = f"chunk {chunk_type!r} at offset {position} runs past the end"
            raise ValueError(msg)
        yield Chunk(
            offset=position,
            type=chunk_type,
            data=png[position + 8 : position + 8 + length],
        )
        if chunk_type == b"IEND":
            return
        position = end


def find_chunk(png: bytes, chunk_type: bytes) -> Chunk:
    """Return the first chunk of ``chunk_type``.

    Raises:
        ValueError: if the PNG has no such chunk.

    """
    for chunk in iter_chunks(png):
        if chunk.type == chunk_type:
            return chunk
    msg = f"no {chunk_type.decode('ascii', errors='replace')} chunk"
    raise ValueError(msg)


def palette(png: bytes) -> tuple[RGB, ...]:
    """Return the PLTE entries as 8-bit RGB triples."""
    data = find_chunk(png, b"PLTE").data
    if len(data) % 3:
        msg = f"PLTE length {len(data)} is not a multiple of 3"
        raise ValueError(msg)
    return tuple((data[i], data[i + 1], data[i + 2]) for i in range(0, len(data), 3))


def replace_palette(png: bytes, entries: Sequence[RGB]) -> bytes:
    """Return ``png`` with its PLTE entries replaced and the chunk CRC recomputed.

    The entry count must match the existing chunk so the file keeps its size.
    """
    plte = find_chunk(png, b"PLTE")
    if len(entries) * 3 != len(plte.data):
        msg = f"PLTE holds {len(plte.data) // 3} entries, got {len(entries)}"
        raise ValueError(msg)
    for entry in entries:
        for component in entry:
            if not 0 <= component <= _PLTE_COMPONENT_MAX:
                msg = f"palette component out of range: {entry!r}"
                raise ValueError(msg)
    data = bytes(component for entry in entries for component in entry)
    crc = zlib.crc32(b"PLTE" + data) & 0xFFFFFFFF
    out = bytearray(png)
    out[plte.data_offset : plte.data_offset + len(data)] = data
    out[plte.crc_offset : plte.crc_offset + 4] = struct.pack(">I", crc)
    return bytes(out)


@dataclass(frozen=True, slots=True)
class Decoded:
    """Decoded 8-bit image: one byte per pixel, rows top to bottom."""

    width: int
    height: int
    colour_type: int
    pixels: bytes


def _paeth(left: int, up: int, up_left: int) -> int:
    estimate = left + up - up_left
    distance_left = abs(estimate - left)
    distance_up = abs(estimate - up)
    distance_up_left = abs(estimate - up_left)
    if distance_left <= distance_up and distance_left <= distance_up_left:
        return left
    return up if distance_up <= distance_up_left else up_left


def _unfilter(filter_type: int, line: bytearray, previous: bytearray) -> None:
    if filter_type == _FILTER_NONE:
        return
    if filter_type not in (_FILTER_SUB, _FILTER_UP, _FILTER_AVERAGE, _FILTER_PAETH):
        msg = f"unsupported PNG filter type {filter_type}"
        raise ValueError(msg)
    for index in range(len(line)):
        left = line[index - 1] if index else 0
        up = previous[index]
        up_left = previous[index - 1] if index else 0
        if filter_type == _FILTER_SUB:
            predictor = left
        elif filter_type == _FILTER_UP:
            predictor = up
        elif filter_type == _FILTER_AVERAGE:
            predictor = (left + up) >> 1
        else:
            predictor = _paeth(left, up, up_left)
        line[index] = (line[index] + predictor) & 0xFF


def decode_8bit(png: bytes) -> Decoded:
    """Decode a non-interlaced 8-bit grayscale or indexed PNG.

    Raises:
        ValueError: for any other depth, colour type, interlacing, or a
            malformed stream.

    """
    chunks = list(iter_chunks(png))
    if not chunks or chunks[0].type != b"IHDR" or len(chunks[0].data) != _IHDR_LENGTH:
        msg = "PNG does not start with a valid IHDR chunk"
        raise ValueError(msg)
    (
        width,
        height,
        bit_depth,
        colour_type,
        compression,
        filter_method,
        interlace,
    ) = struct.unpack(">IIBBBBB", chunks[0].data)
    if bit_depth != _BIT_DEPTH:
        msg = f"only bit depth 8 is supported, got {bit_depth}"
        raise ValueError(msg)
    if colour_type not in (_GRAYSCALE, _INDEXED):
        msg = (
            "only grayscale or indexed PNGs are supported, "
            f"got colour type {colour_type}"
        )
        raise ValueError(msg)
    if compression != 0 or filter_method != 0 or interlace != 0:
        msg_0 = "unsupported compression, filter method or interlacing"
        raise ValueError(msg_0)
    raw = zlib.decompress(
        b"".join(chunk.data for chunk in chunks if chunk.type == b"IDAT")
    )
    if len(raw) != height * (width + 1):
        msg = f"IDAT decodes to {len(raw)} bytes, expected {height * (width + 1)}"
        raise ValueError(msg)
    pixels = bytearray()
    previous = bytearray(width)
    position = 0
    for _ in range(height):
        filter_type = raw[position]
        position += 1
        line = bytearray(raw[position : position + width])
        position += width
        _unfilter(filter_type, line, previous)
        pixels += line
        previous = line
    return Decoded(
        width=width, height=height, colour_type=colour_type, pixels=bytes(pixels)
    )


def is_indexed_8bit(png: bytes) -> bool:
    """Return True for a PNG whose IHDR says 8-bit indexed colour (type 3)."""
    if png[:8] != PNG_SIGNATURE or len(png) < 8 + 8 + _IHDR_LENGTH:
        return False
    if png[12:16] != b"IHDR":
        return False
    bit_depth = png[24]
    colour_type = png[25]
    return bit_depth == _BIT_DEPTH and colour_type == _INDEXED
