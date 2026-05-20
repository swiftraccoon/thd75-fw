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
    """``resource.load`` reads its argument's PE bytes and scans for
    the embedded firmware resource. A previous version preferred a
    sibling ILSpy-extracted text file when one existed next to the
    requested ``.exe`` — that was removed in v0.2.0 because it was a
    silent firmware-version footgun (a stale sibling from a prior
    session would override the requested updater). Pre-extracted
    resources are now passed explicitly via ``--resource``."""

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

    def test_sibling_ilspy_file_is_ignored(
        self, tmp_path: Path, monkeypatch: MonkeyPatch,
    ) -> None:
        """``resource.load`` MUST ignore a sibling ILSpy-extracted file
        even when one is present — silently swapping the .exe's
        embedded resource for a sibling text file's content is a
        firmware-version footgun (the sibling could be from a prior
        extraction of a different updater version).

        This test pins the v0.2.0 contract: a sibling file does not
        affect ``load(exe_path)``. Callers who want to use a
        pre-extracted resource should pass it explicitly through the
        CLI's ``--resource`` flag (which routes around ``resource.load``
        entirely — see cli.py's ``_run_extract`` / ``_run_patch``).
        """
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)

        # The .exe contains a byte-scannable region with one sentinel.
        fake_exe = tmp_path / "fake.exe"
        fake_exe.write_bytes(_synthetic_resource_bytes())

        # Put a sibling ILSpy-extracted .txt next to the .exe with a
        # clearly different sentinel.
        sibling = tmp_path / "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
        sibling.write_text(
            "$STALE_SIBLING_SENTINEL\nDDEADBEEF\n", encoding="utf-8",
        )

        text = resource.load(fake_exe)

        # The .exe's actual content must come through; the sibling
        # must not have shadowed it.
        assert "AABBCC" in text
        assert "STALE_SIBLING_SENTINEL" not in text


class TestExtract:
    """``extract`` pulls the resource text straight from .exe bytes
    (no Path, no sibling-file fast path) — the form the repacker needs."""

    def test_extracts_synthetic_resource(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        text = resource.extract(_synthetic_resource_bytes())
        assert text.startswith("$AABBCC")
        assert "DCCDDEEFF" in text

    def test_no_resource_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        with pytest.raises(ValueError, match="not found"):
            resource.extract(b"\x00" * 200 + b"no markers here " * 20)


class TestReplace:
    """``replace`` overwrites the embedded resource in place; the splice
    requires a same-length replacement so no other PE offset moves."""

    def test_replaces_resource_in_place(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        exe = _synthetic_resource_bytes()
        original = resource.extract(exe)
        # A same-length edit: swap one 6-char hex run for another.
        new_resource = original.replace("AABBCC", "DDEEFF", 1)
        patched = resource.replace(exe, new_resource)
        assert len(patched) == len(exe)
        assert resource.extract(patched) == new_resource
        # The binary surrounding the resource is untouched.
        assert patched[:10] == exe[:10]
        assert patched[-10:] == exe[-10:]

    def test_length_mismatch_rejected(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        exe = _synthetic_resource_bytes()
        original = resource.extract(exe)
        with pytest.raises(ValueError, match="exact length match"):
            resource.replace(exe, original + "EXTRA")

    def test_no_resource_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        with pytest.raises(ValueError, match="not found"):
            resource.replace(b"\x00" * 300, "$AABBCC\r\n")
