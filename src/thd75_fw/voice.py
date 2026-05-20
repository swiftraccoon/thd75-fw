"""Voice prompt extraction from the TH-D75 DATA_0160 section.

The input to ``load()`` is the raw byte content of the DATA_0160 section
as written by ``thd75-extract`` — i.e., the post-decryption,
post-Intel-HEX byte-stitched output of the upstream pipeline (see
``thd75_fw.file_cipher`` and ``thd75_fw.intel_hex``).

The voice prompt database contains 749 indexed segments of signed 8-bit
linear PCM audio at 8 kHz mono. Three language groups (V1.03 layout):

  - English:  indices 0-326 (327 segments, ~131s)
  - Japanese: indices 327-682 (356 segments, ~131s)
  - Chinese:  indices 683-748 (66 segments, ~22s)

The first 36 entries are organized as 12 triplets (EN, JP, ZH) of concept
prompts. After that, digits/letters use 10-step spacing.

File layout::

    0x0000-0x003F  Header (model ID, engine version, entry count)
    0x0040-0x0BF3  Index table (749 x 4-byte LE cumulative offsets)
    0x0BF4-0x0BF7  End marker (total indexed audio size)
    0x0BF8-EOF     Audio data (8-bit signed PCM, 8 kHz mono)
"""

from __future__ import annotations

import struct
import wave
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from pathlib import Path

__all__: list[str] = [
    "Language",
    "Prompt",
    "PromptDatabase",
    "classify_language",
    "load",
]

SAMPLE_RATE: int = 8000

# V1.03 DATA_0160 layout constants — private because they're tied to
# this specific firmware version. External callers go through ``load()``
# rather than reaching for these directly.
_INDEX_TABLE_OFFSET: int = 0x40
_AUDIO_BASE: int = 0x0BF8
_HEADER_MODEL_ID = slice(0, 7)
_HEADER_ENGINE_VERSION = slice(7, 24)
_HEADER_ENTRY_COUNT_OFFSET = 0x20  # uint32 LE
_INDEX_ENTRY_SIZE = 4              # bytes per cumulative-offset entry

Language = Literal["en", "ja", "zh"]
"""Three-letter language code recognized by this module."""

# Default V1.03 firmware language layout. If you need to handle a
# different firmware version, classify indices yourself and pass the
# results to ``Prompt(language=...)``; this helper exists for the
# documented V1.03 case which covers the only firmware currently shipped.
_EN_MAX_INDEX: int = 326
_JA_MAX_INDEX: int = 682


def classify_language(index: int) -> Language:
    """Classify a prompt index by language for V1.03's layout.

    Returns ``"en"`` for indices 0-326, ``"ja"`` for 327-682, ``"zh"``
    for 683 or higher. No upper bound is enforced — indices past 748
    (V1.03's last valid prompt) still classify as ``"zh"`` rather than
    raising; the loader catches out-of-range indices upstream.
    """
    if index <= _EN_MAX_INDEX:
        return "en"
    if index <= _JA_MAX_INDEX:
        return "ja"
    return "zh"


@dataclass(frozen=True, slots=True)
class Prompt:
    """A single voice prompt segment."""

    index: int
    offset: int
    size: int
    data: bytes
    language: Language

    @property
    def duration_ms(self) -> int:
        """Duration in milliseconds at 8 kHz."""
        return (self.size * 1000) // SAMPLE_RATE

    def to_wav(self, path: Path) -> None:
        """Write this prompt as a WAV file (8-bit unsigned PCM, 8 kHz mono).

        WAV uses unsigned 8-bit samples, so we convert from signed by
        flipping the sign bit (equivalent to adding 128 modulo 256).
        """
        unsigned_samples = bytes(sample ^ 0x80 for sample in self.data)
        with wave.open(str(path), "wb") as wave_file:
            wave_file.setnchannels(1)
            wave_file.setsampwidth(1)
            wave_file.setframerate(SAMPLE_RATE)
            wave_file.writeframes(unsigned_samples)


@dataclass(frozen=True, slots=True)
class PromptDatabase:
    """Parsed voice prompt database."""

    model_id: str
    engine_version: str
    prompts: tuple[Prompt, ...]

    @property
    def total_duration_ms(self) -> int:
        """Total audio duration across all prompts."""
        return sum(p.duration_ms for p in self.prompts)

    def by_language(self, language: Language) -> tuple[Prompt, ...]:
        """Filter prompts by language code."""
        return tuple(prompt for prompt in self.prompts if prompt.language == language)


def load(data: bytes) -> PromptDatabase:
    """Parse a voice prompt database from raw binary data.

    Args:
        data: Raw bytes of the DATA_0160 section.

    Returns:
        A ``PromptDatabase`` with all indexed prompts.

    Raises:
        ValueError: If the data is too small, the header is invalid,
            the index table doesn't fit, or any prompt's audio range
            exceeds the available data (would-be silent truncation).
    """
    if len(data) < _AUDIO_BASE:
        msg = f"Data too small: {len(data)} bytes (need at least {_AUDIO_BASE})"
        raise ValueError(msg)

    # Parse header
    model_id = data[_HEADER_MODEL_ID].rstrip(b"\x00\xff ").decode(
        "ascii", errors="replace"
    )
    engine_version = data[_HEADER_ENGINE_VERSION].rstrip(b"\x00\xff").decode(
        "ascii", errors="replace"
    )
    entry_count = struct.unpack_from("<I", data, _HEADER_ENTRY_COUNT_OFFSET)[0]

    if entry_count == 0 or entry_count > 10000:
        msg = f"Invalid entry count: {entry_count}"
        raise ValueError(msg)

    table_end = _INDEX_TABLE_OFFSET + entry_count * _INDEX_ENTRY_SIZE
    if table_end > len(data):
        msg = (
            f"Index table for {entry_count} entries needs {table_end} bytes, "
            f"have {len(data)}"
        )
        raise ValueError(msg)
    if table_end > _AUDIO_BASE:
        # Header is lying about the entry count: the table would overflow
        # past the documented audio-data start and silently shadow the
        # first audio bytes with index-table entries.
        msg = (
            f"Index table for {entry_count} entries ends at 0x{table_end:X}, "
            f"overlapping the audio data region (starts at 0x{_AUDIO_BASE:X})"
        )
        raise ValueError(msg)

    # Parse index table — entries are cumulative end-offsets relative to _AUDIO_BASE
    offsets: list[int] = []
    for i in range(entry_count):
        offset_pos = _INDEX_TABLE_OFFSET + i * _INDEX_ENTRY_SIZE
        cumulative_end = struct.unpack_from("<I", data, offset_pos)[0]
        offsets.append(cumulative_end)

    # Build prompts
    prompts: list[Prompt] = []
    for i in range(entry_count):
        start = 0 if i == 0 else offsets[i - 1]
        end = offsets[i]
        # Cumulative offsets must monotonically nondecrease — a
        # decreasing offset would silently produce a negative-size
        # prompt with empty data and negative duration. Refuse loudly.
        if end < start:
            msg = (
                f"Prompt {i} has cumulative end 0x{end:X} earlier than "
                f"previous prompt's end 0x{start:X} — index table is "
                f"non-monotonic and the database is corrupt"
            )
            raise ValueError(msg)
        abs_start = _AUDIO_BASE + start
        abs_end = _AUDIO_BASE + end

        if abs_end > len(data):
            msg = (
                f"Prompt {i} extends to offset {abs_end} but data ends at "
                f"{len(data)} (header claims {entry_count} prompts)"
            )
            raise ValueError(msg)

        prompts.append(Prompt(
            index=i,
            offset=abs_start,
            size=end - start,
            data=data[abs_start:abs_end],
            language=classify_language(index=i),
        ))

    return PromptDatabase(
        model_id=model_id,
        engine_version=engine_version,
        prompts=tuple(prompts),
    )
