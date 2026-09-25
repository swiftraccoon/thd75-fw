"""Tests for the thd75-theme command."""

from __future__ import annotations

import struct
import sys
from typing import TYPE_CHECKING

import pytest

from tests.fixtures.image_data_helpers import build_image_data
from tests.fixtures.png_helpers import PngHeader, build_png
from thd75_fw import cli
from thd75_fw.cli import main_theme
from thd75_fw.patch import parse_patch
from thd75_fw.theme.build import (
    LABEL_OFFSET,
    TEXT_PALETTE_BLACK_OFFSET,
    TEXT_PALETTE_WHITE_OFFSET,
    V103_TEXT_PALETTE_BLACK,
)

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch

_STOCK_WHITE_TEXT = (
    0x0000,
    0xFFFF,
    0xF800,
    0xFFFF,
    0x3314,
    0xC618,
    0x52AA,
    0xB69F,
    0xC78C,
    0x0000,
)
_PIXELS = bytes([0, 1, 2, 3, 3, 2, 1, 0, 1, 1, 2, 2])
_INDEXED_4X3 = PngHeader(width=4, height=3, colour_type=3)


def _write_sections(tmp_path: Path) -> tuple[Path, Path]:
    firmware = bytearray(b"\xff" * 0x160000)
    struct.pack_into(
        "<10H", firmware, TEXT_PALETTE_BLACK_OFFSET, *V103_TEXT_PALETTE_BLACK
    )
    struct.pack_into("<10H", firmware, TEXT_PALETTE_WHITE_OFFSET, *_STOCK_WHITE_TEXT)
    firmware[LABEL_OFFSET : LABEL_OFFSET + 6] = b"White\x00"
    struct.pack_into("<HH", firmware, 0x15F100, 0, 1)
    palettes = [[0x0000, 0xFFFF, 0xF81F, 0x07E0] for _ in range(18)]
    palettes[12] = [0x0000, 0xFFFF, 0xF81F, 0xFFFF]
    image_data = build_image_data(
        [
            build_png(
                _INDEXED_4X3,
                _PIXELS,
                [(0, 0, 0), (255, 255, 255), (255, 0, 255), (1, 2, 3)],
            ),
            build_png(
                _INDEXED_4X3,
                _PIXELS,
                [(255, 255, 255), (0, 0, 0), (255, 0, 255), (1, 2, 3)],
            ),
        ],
        palettes,
    )
    firmware_path = tmp_path / "FIRMWARE.bin"
    image_path = tmp_path / "IMAGE_DATA.bin"
    _ = firmware_path.write_bytes(bytes(firmware))
    _ = image_path.write_bytes(image_data)
    return firmware_path, image_path


class TestParseRgb:
    def test_parses_three_components(self) -> None:
        assert cli._parse_rgb("255,140,0") == (255, 140, 0)
        assert cli._parse_rgb(" 1, 2 ,3 ") == (1, 2, 3)

    @pytest.mark.parametrize("text", ["255,140", "256,0,0", "a,b,c", "1,2,3,4"])
    def test_rejects_malformed(self, text: str) -> None:
        with pytest.raises(ValueError, match="R,G,B"):
            _ = cli._parse_rgb(text)


class TestMainTheme:
    def test_writes_patch_from_sections(
        self, monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
    ) -> None:
        firmware_path, image_path = _write_sections(tmp_path)
        out = tmp_path / "theme.toml"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-theme",
                str(out),
                "--firmware",
                str(firmware_path),
                "--image-data",
                str(image_path),
                "--name",
                "test-theme",
            ],
        )
        main_theme()
        parsed = parse_patch(out.read_text(encoding="utf-8"))
        assert parsed.name == "test-theme"
        assert parsed.touched_sections == ("FIRMWARE", "IMAGE_DATA")
        err = capsys.readouterr().err
        assert "twin groups: 1, recoloured: 1" in err
        assert "IMAGE_DATA byte changes:" in err

    def test_requires_one_input_mode(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-theme", str(tmp_path / "x.toml")])
        with pytest.raises(SystemExit) as excinfo:
            main_theme()
        assert excinfo.value.code == 2

    def test_bad_rgb_exits_with_usage_error(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        firmware_path, image_path = _write_sections(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-theme",
                str(tmp_path / "x.toml"),
                "--firmware",
                str(firmware_path),
                "--image-data",
                str(image_path),
                "--rgb",
                "300,0,0",
            ],
        )
        with pytest.raises(SystemExit) as excinfo:
            main_theme()
        assert excinfo.value.code == 2

    def test_theme_error_exits_one(
        self, monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
    ) -> None:
        firmware_path, image_path = _write_sections(tmp_path)
        broken = bytearray(firmware_path.read_bytes())
        broken[LABEL_OFFSET] = ord("B")
        _ = firmware_path.write_bytes(bytes(broken))
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-theme",
                str(tmp_path / "x.toml"),
                "--firmware",
                str(firmware_path),
                "--image-data",
                str(image_path),
            ],
        )
        with pytest.raises(SystemExit) as excinfo:
            main_theme()
        assert excinfo.value.code == 1
        assert "'White'" in capsys.readouterr().err
