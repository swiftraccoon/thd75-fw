"""Voice prompt extraction from the TH-D75 DATA_0160 section.

The voice prompt database contains 749 indexed segments of signed 8-bit
linear PCM audio at 8 kHz mono. Three language groups:

  - English:  indices 0-326 (327 segments, ~131s)
  - Japanese: indices 327-682 (356 segments, ~131s)
  - Chinese:  indices 683-748 (66 segments, ~22s)

The first 36 entries are organized as 12 triplets (EN, JP, ZH) of concept
prompts. After that, digits/letters use 10-step spacing.

File layout::

    0x0000-0x003F  Header (model ID, engine version, entry count)
    0x0040-0x0BF3  Index table (749 × 4-byte LE cumulative offsets)
    0x0BF4-0x0BF7  End marker (total indexed audio size)
    0x0BF8-EOF     Audio data (8-bit signed PCM, 8 kHz mono)
"""

from __future__ import annotations

import struct
import wave
from dataclasses import dataclass
from pathlib import Path

__all__: list[str] = [
    "AUDIO_BASE",
    "INDEX_TABLE_OFFSET",
    "Prompt",
    "PromptDatabase",
    "load",
]

INDEX_TABLE_OFFSET: int = 0x40
AUDIO_BASE: int = 0x0BF8
SAMPLE_RATE: int = 8000


@dataclass(frozen=True, slots=True)
class Prompt:
    """A single voice prompt segment."""

    index: int
    offset: int
    size: int
    data: bytes

    @property
    def duration_ms(self) -> int:
        """Duration in milliseconds at 8 kHz."""
        return (self.size * 1000) // SAMPLE_RATE

    @property
    def language(self) -> str:
        """Estimated language group."""
        if self.index <= 326:
            return "en"
        if self.index <= 682:
            return "ja"
        return "zh"

    def to_wav(self, path: Path) -> None:
        """Write this prompt as a WAV file (8-bit unsigned PCM, 8 kHz mono).

        WAV uses unsigned 8-bit samples, so we convert from signed by
        adding 128 to each byte.
        """
        unsigned = bytes((b + 128) & 0xFF for b in self.data)
        with wave.open(str(path), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(1)
            wf.setframerate(SAMPLE_RATE)
            wf.writeframes(unsigned)


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

    def by_language(self, lang: str) -> tuple[Prompt, ...]:
        """Filter prompts by language code ('en', 'ja', 'zh')."""
        return tuple(p for p in self.prompts if p.language == lang)


def load(data: bytes) -> PromptDatabase:
    """Parse a voice prompt database from raw binary data.

    Args:
        data: Raw bytes of the DATA_0160 section.

    Returns:
        A ``PromptDatabase`` with all indexed prompts.

    Raises:
        ValueError: If the data is too small or the header is invalid.
    """
    if len(data) < AUDIO_BASE:
        msg = f"Data too small: {len(data)} bytes (need at least {AUDIO_BASE})"
        raise ValueError(msg)

    # Parse header
    model_id = data[0:7].rstrip(b"\x00\xff ").decode("ascii", errors="replace")
    engine_ver = data[7:24].rstrip(b"\x00\xff").decode("ascii", errors="replace")
    entry_count = struct.unpack_from("<I", data, 0x20)[0]

    if entry_count == 0 or entry_count > 10000:
        msg = f"Invalid entry count: {entry_count}"
        raise ValueError(msg)

    # Parse index table (cumulative end-offsets relative to AUDIO_BASE)
    offsets: list[int] = []
    for i in range(entry_count):
        off = struct.unpack_from("<I", data, INDEX_TABLE_OFFSET + i * 4)[0]
        offsets.append(off)

    # Build prompts
    prompts: list[Prompt] = []
    for i in range(entry_count):
        start = 0 if i == 0 else offsets[i - 1]
        end = offsets[i]
        abs_start = AUDIO_BASE + start
        abs_end = AUDIO_BASE + end

        if abs_end > len(data):
            break

        prompts.append(Prompt(
            index=i,
            offset=abs_start,
            size=end - start,
            data=data[abs_start:abs_end],
        ))

    return PromptDatabase(
        model_id=model_id,
        engine_version=engine_ver,
        prompts=tuple(prompts),
    )
