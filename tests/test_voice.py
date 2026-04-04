"""Tests for voice prompt extraction."""

import struct

from thd75_fw.voice import (
    AUDIO_BASE,
    INDEX_TABLE_OFFSET,
    SAMPLE_RATE,
    Prompt,
    load,
)


def _make_db(entry_count: int, segment_sizes: list[int]) -> bytes:
    """Build a minimal voice prompt database binary."""
    # Header
    header = bytearray(AUDIO_BASE)
    header[0:5] = b"E5210"
    header[7:23] = b"VTE0816SQ1.00.00"
    struct.pack_into("<I", header, 0x20, entry_count)

    # Index table (cumulative offsets)
    cumulative = 0
    for i, size in enumerate(segment_sizes):
        cumulative += size
        struct.pack_into("<I", header, INDEX_TABLE_OFFSET + i * 4, cumulative)

    # Audio data — one fill byte per segment
    audio = bytearray()
    for size in segment_sizes:
        audio.extend(b"\x10" * size)

    return bytes(header) + bytes(audio)


class TestLoad:
    def test_basic_load(self) -> None:
        sizes = [100, 200, 150]
        data = _make_db(3, sizes)
        db = load(data)
        assert len(db.prompts) == 3
        assert db.prompts[0].size == 100
        assert db.prompts[1].size == 200
        assert db.prompts[2].size == 150

    def test_model_id(self) -> None:
        data = _make_db(1, [50])
        db = load(data)
        assert "5210" in db.model_id

    def test_too_small_raises(self) -> None:
        try:
            load(b"\x00" * 10)
            raise AssertionError("Should have raised")
        except ValueError:
            pass


class TestPrompt:
    def test_duration(self) -> None:
        p = Prompt(index=0, offset=0, size=SAMPLE_RATE, data=b"\x00" * SAMPLE_RATE)
        assert p.duration_ms == 1000

    def test_language_en(self) -> None:
        assert Prompt(index=0, offset=0, size=0, data=b"").language == "en"
        assert Prompt(index=326, offset=0, size=0, data=b"").language == "en"

    def test_language_ja(self) -> None:
        assert Prompt(index=327, offset=0, size=0, data=b"").language == "ja"
        assert Prompt(index=682, offset=0, size=0, data=b"").language == "ja"

    def test_language_zh(self) -> None:
        assert Prompt(index=683, offset=0, size=0, data=b"").language == "zh"
        assert Prompt(index=748, offset=0, size=0, data=b"").language == "zh"

    def test_to_wav(self, tmp_path: object) -> None:
        from pathlib import Path

        p = Prompt(index=0, offset=0, size=100, data=b"\x00" * 100)
        wav_path = Path(str(tmp_path)) / "test.wav"
        p.to_wav(wav_path)
        assert wav_path.exists()
        assert wav_path.stat().st_size > 44  # WAV header + data
