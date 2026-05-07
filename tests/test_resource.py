"""Tests for PE resource extraction."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from thd75_fw import resource

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.monkeypatch import MonkeyPatch


def _synthetic_resource_bytes(num_data_lines: int = 200) -> bytes:
    """Build a small byte stream containing a $-prefixed hex region.

    The real updater's resource is ~42 MB; we lower _MIN_RESOURCE_SIZE
    for tests so we can exercise the scanner without huge fixtures.
    """
    region = b"$AABBCC\r\n" + b"DCCDDEEFF\r\n" * num_data_lines
    return b"\x00\x00\x00" + b"some binary header bytes\xFF" * 5 + region + b"\x00\x00trailing-binary"


class TestLoad:
    """The two paths through ``resource.load``: ILSpy fast-path
    (sibling .txt file) and PE byte-scanner fallback. Both must
    surface missing-file errors with proper ``.filename``."""

    def test_load_missing_file_raises_with_filename(self, tmp_path: Path) -> None:
        # The CLI relies on .filename being set so it can produce
        # `error: file not found: <path>` instead of a stack trace.
        missing = tmp_path / "nonexistent.exe"
        with pytest.raises(FileNotFoundError) as exc_info:
            resource.load(missing)
        assert exc_info.value.filename == str(missing)

    def test_load_finds_synthetic_resource(
        self, tmp_path: Path, monkeypatch: MonkeyPatch,
    ) -> None:
        # Lower the size threshold so a small synthetic fixture qualifies.
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        fake_exe = tmp_path / "fake.exe"
        fake_exe.write_bytes(_synthetic_resource_bytes())
        text = resource.load(fake_exe)
        assert text.startswith("$AABBCC")
        assert "DCCDDEEFF" in text

    def test_no_resource_in_pe_raises(
        self, tmp_path: Path, monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        # No $-marker anywhere; scanner can't find a resource.
        fake_exe = tmp_path / "fake.exe"
        fake_exe.write_bytes(b"\x00" * 200 + b"junk binary content " * 20)
        with pytest.raises(ValueError, match="not found"):
            resource.load(fake_exe)

    def test_resource_too_small_rejected(
        self, tmp_path: Path, monkeypatch: MonkeyPatch,
    ) -> None:
        # With default _MIN_RESOURCE_SIZE = 1 MB, a small file can't qualify.
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 10_000)
        fake_exe = tmp_path / "tiny.exe"
        fake_exe.write_bytes(_synthetic_resource_bytes(num_data_lines=5))
        with pytest.raises(ValueError, match="not found"):
            resource.load(fake_exe)

    def test_ilspy_sibling_takes_precedence_over_pe_scan(
        self, tmp_path: Path, monkeypatch: MonkeyPatch,
    ) -> None:
        """Fast path: if ``THD75_Updater_E.Resources.TH-D75_Firm_E.txt``
        sits next to the .exe (e.g., produced by ``ilspycmd``), prefer
        it over byte-scanning the PE.

        Verified against real V1.03 firmware: byte-scanner output and
        ILSpy fast-path output are SHA-256 identical for all 7 sections.
        This test pins the dispatch logic so a refactor can't silently
        regress to always byte-scanning.
        """
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)

        # The .exe contains a byte-scannable region with one sentinel.
        fake_exe = tmp_path / "fake.exe"
        fake_exe.write_bytes(_synthetic_resource_bytes())

        # The sibling .txt has a clearly different sentinel. Use \n
        # rather than \r\n so it round-trips through read_text's
        # universal-newline translation cleanly.
        sibling = tmp_path / "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
        sibling_text = "$FAST_PATH_SENTINEL\nDDEADBEEF\n"
        sibling.write_text(sibling_text, encoding="utf-8")

        text = resource.load(fake_exe)

        # If we reached this assertion via the byte scanner, we'd see
        # "$AABBCC..." from _synthetic_resource_bytes. The fast path
        # returns the sibling .txt's content.
        assert "FAST_PATH_SENTINEL" in text
        assert "AABBCC" not in text  # byte-scanner content not present
