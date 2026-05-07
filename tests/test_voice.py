"""Tests for voice prompt extraction."""

import struct
import wave
from pathlib import Path

import pytest

from thd75_fw.voice import (
    _AUDIO_BASE,
    _INDEX_TABLE_OFFSET,
    SAMPLE_RATE,
    Prompt,
    classify_language,
    load,
)


def _make_db(entry_count: int, segment_sizes: list[int]) -> bytes:
    """Build a minimal voice prompt database binary."""
    header = bytearray(_AUDIO_BASE)
    header[0:5] = b"E5210"
    header[7:23] = b"VTE0816SQ1.00.00"
    struct.pack_into("<I", header, 0x20, entry_count)

    # Index table (cumulative end-offsets relative to _AUDIO_BASE)
    cumulative = 0
    for i, size in enumerate(segment_sizes):
        cumulative += size
        struct.pack_into("<I", header, _INDEX_TABLE_OFFSET + i * 4, cumulative)

    # Audio data — one fill byte per segment
    audio = bytearray()
    for size in segment_sizes:
        audio.extend(b"\x10" * size)

    return bytes(header) + bytes(audio)


class TestLoad:
    """Database-level invariants: prompt count, header decoding, and
    explicit rejection of malformed inputs that would otherwise produce
    silently-wrong output."""

    def test_load_returns_one_prompt_per_index_table_entry(self) -> None:
        sizes = [100, 200, 150]
        database = load(_make_db(3, sizes))
        assert len(database.prompts) == 3
        assert [prompt.size for prompt in database.prompts] == sizes

    def test_model_id_decoded_from_header(self) -> None:
        database = load(_make_db(1, [50]))
        assert "5210" in database.model_id

    def test_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="too small"):
            load(b"\x00" * 10)

    def test_truncated_data_raises(self) -> None:
        # Header claims 3 prompts ending at audio offset 600, but we
        # truncate the data so the last prompt would extend past EOF.
        # The old implementation silently dropped the offending prompt.
        full = _make_db(3, [100, 200, 300])
        # Cut off the last 50 bytes of audio.
        truncated = full[:-50]
        with pytest.raises(ValueError, match="extends to offset"):
            load(truncated)

    def test_invalid_entry_count_raises(self) -> None:
        # Build a header with an absurd entry count.
        data = bytearray(_AUDIO_BASE)
        struct.pack_into("<I", data, 0x20, 99999)
        with pytest.raises(ValueError, match="entry count"):
            load(bytes(data))


class TestClassifyLanguage:
    """V1.03 prompt-index → language-code mapping at the documented
    en/ja/zh boundaries."""

    def test_english_range(self) -> None:
        assert classify_language(0) == "en"
        assert classify_language(326) == "en"

    def test_japanese_range(self) -> None:
        assert classify_language(327) == "ja"
        assert classify_language(682) == "ja"

    def test_chinese_range(self) -> None:
        assert classify_language(683) == "zh"
        assert classify_language(748) == "zh"


class TestPrompt:
    """Prompt dataclass behavior: derived properties and to_wav output
    format."""

    def test_duration(self) -> None:
        prompt = Prompt(
            index=0,
            offset=0,
            size=SAMPLE_RATE,
            data=b"\x00" * SAMPLE_RATE,
            language="en",
        )
        assert prompt.duration_ms == 1000

    def test_to_wav_writes_well_formed_wav(self, tmp_path: Path) -> None:
        prompt = Prompt(
            index=0, offset=0, size=100, data=b"\x00" * 100, language="en",
        )
        wav_path = tmp_path / "test.wav"
        prompt.to_wav(wav_path)
        assert wav_path.exists()
        # Verify it's a real WAV with the expected shape, not just any bytes.
        with wave.open(str(wav_path), "rb") as wave_file:
            assert wave_file.getnchannels() == 1
            assert wave_file.getsampwidth() == 1
            assert wave_file.getframerate() == SAMPLE_RATE
            assert wave_file.getnframes() == 100
