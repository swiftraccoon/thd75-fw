"""Tests for theme construction from synthetic FIRMWARE and IMAGE_DATA sections."""

from __future__ import annotations

import hashlib
import struct

import pytest

from tests.fixtures.image_data_helpers import build_image_data
from tests.fixtures.png_helpers import PngHeader, build_png
from thd75_fw import images
from thd75_fw.patch import parse_patch
from thd75_fw.theme.build import (
    LABEL_OFFSET,
    TEXT_PALETTE_BLACK_OFFSET,
    TEXT_PALETTE_WHITE_OFFSET,
    V103_TEXT_PALETTE_BLACK,
    ThemeError,
    ThemeOptions,
    build_theme,
)
from thd75_fw.theme.colour import DEEP_ORANGE
from thd75_fw.theme.palettes import load_palette_table, read_palette
from thd75_fw.theme.png import decode_8bit, palette
from thd75_fw.theme.twins import Role

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
_GRAY_4X3 = PngHeader(width=4, height=3, colour_type=0)
_BLACK_PLTE = [(0, 0, 0), (255, 255, 255), (255, 0, 255), (56, 160, 216)]
_WHITE_PLTE = [(255, 255, 255), (0, 0, 0), (255, 0, 255), (24, 117, 197)]


def _firmware(evidence_at: int | None = 0x15F100) -> bytes:
    data = bytearray(b"\xff" * 0x160000)  # 0xFF fill: no accidental image indices
    struct.pack_into("<10H", data, TEXT_PALETTE_BLACK_OFFSET, *V103_TEXT_PALETTE_BLACK)
    struct.pack_into("<10H", data, TEXT_PALETTE_WHITE_OFFSET, *_STOCK_WHITE_TEXT)
    data[LABEL_OFFSET : LABEL_OFFSET + 6] = b"White\x00"
    if evidence_at is not None:
        struct.pack_into("<HH", data, evidence_at, 0, 1)  # pair table: 0 Black, 1 White
    return bytes(data)


def _palettes() -> list[list[int]]:
    small_black = [0x0000, 0xFFFF, 0xF81F, 0x3D1B]
    small_white = [0x0000, 0xFFFF, 0xF81F, 0x1BB8]
    background_black = [0x0000, 0xFFFF, 0xF81F] + [0x8410] * 25 + [0x0000, 0x2104]
    background_white = [0x0000, 0xFFFF, 0xF81F] + [0x8410] * 25 + [0xFFFF, 0x2104]
    digits_black = [0x0000, 0xFFFF, 0xF81F, 0x8410]
    digits_white = [0xFFFF, 0x0000, 0xF81F, 0x8410]
    identical = [0x0000, 0xFFFF, 0xF81F, 0x07E0]
    palettes = [list(identical) for _ in range(18)]
    palettes[0], palettes[9] = small_black, small_white
    palettes[3], palettes[12] = background_black, background_white
    palettes[7], palettes[16] = digits_black, digits_white
    return palettes


def _image_data() -> bytes:
    pngs = [
        build_png(_INDEXED_4X3, _PIXELS, _BLACK_PLTE),
        build_png(_INDEXED_4X3, _PIXELS, _WHITE_PLTE),
        build_png(_GRAY_4X3, bytes([28] * 12)),
    ]
    return build_image_data(pngs, _palettes())


class TestBuildTheme:
    def test_firmware_runs(self) -> None:
        build = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        firmware_runs = [run for run in build.runs if run.section == "FIRMWARE"]
        assert [run.offset for run in firmware_runs] == [
            LABEL_OFFSET,
            TEXT_PALETTE_BLACK_OFFSET,
        ]
        label, text = firmware_runs
        assert label.expect[:6] == b"White\x00"
        assert label.value[:6] == b"Orange"
        assert label.value[6:] == label.expect[6:]
        assert text.expect[:20] == text.value[:20]
        assert text.value[20:] == bytes.fromhex(
            "60FC 0000 00F8 60FC 9F86 6051 60FC 1433 895C 0000"
        )

    def test_palette_rules(self) -> None:
        build = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        patched = build.patched_image_data
        table = load_palette_table(patched)
        assert read_palette(patched, table, 9) == (0x0000, 0xFC60, 0xF81F, 0x3D1B)
        assert read_palette(patched, table, 12)[28] == 0x0000
        assert read_palette(patched, table, 12)[1] == 0xFC60
        assert read_palette(patched, table, 16) == (0x0000, 0xFC60, 0xF81F, 0x8240)
        assert read_palette(patched, table, 13) == (0x0000, 0xFFFF, 0xF81F, 0x07E0)
        # Identical pairs in the source lists still recolour their white entry.
        assert set(build.report.palettes_changed) == {9, 10, 11, 12, 14, 16, 17}

    def test_white_twin_takes_the_black_palette_recoloured(self) -> None:
        build = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        patched = images.load(build.patched_image_data).images
        assert palette(patched[0].data) == tuple(_BLACK_PLTE)
        assert palette(patched[1].data) == (
            (0, 0, 0),
            (255, 140, 0),
            (255, 0, 255),
            (56, 160, 216),
        )
        assert decode_8bit(patched[1].data).pixels == _PIXELS
        assert build.report.twins_recoloured == 1
        assert build.report.twin_groups == 1

    def test_patch_round_trips_through_toml(self) -> None:
        build = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        parsed = parse_patch(build.toml)
        assert parsed == build.patch
        assert parsed.touched_sections == ("FIRMWARE", "IMAGE_DATA")
        assert parsed.source_sha256 is None
        assert parsed.result_sha256 is None
        (pins,) = parsed.section_hashes
        assert pins.section == "IMAGE_DATA"
        assert pins.source_sha256 == hashlib.sha256(_image_data()).hexdigest()
        assert (
            pins.result_sha256 == hashlib.sha256(build.patched_image_data).hexdigest()
        )
        assert pins.version == "1.00.02.01"
        assert 'version = "1.00.02.01"' in build.toml
        assert parsed.change_count == sum(run.changed() for run in build.runs)
        assert parsed.name == "orange-on-black"
        assert "1 white-scheme icon twin" in parsed.description

    def test_image_data_header_version_is_bumped(self) -> None:
        build = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        version_run = next(
            run for run in build.runs if run.section == "IMAGE_DATA" and run.offset == 0
        )
        assert version_run.expect == b"1.00.02.00"
        assert version_run.value == b"1.00.02.01"
        assert build.patched_image_data[:11] == b"1.00.02.01\x00"
        assert build.report.image_version_bumped is True

    def test_unexpected_header_version_is_rejected(self) -> None:
        image_data = bytearray(_image_data())
        image_data[0:10] = b"1.00.02.01"
        with pytest.raises(ThemeError, match="header version"):
            _ = build_theme(_firmware(), bytes(image_data), DEEP_ORANGE)

    def test_build_is_deterministic(self) -> None:
        first = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        second = build_theme(_firmware(), _image_data(), DEEP_ORANGE)
        assert first.toml == second.toml

    def test_missing_text_palette_is_rejected(self) -> None:
        firmware = bytearray(_firmware())
        firmware[TEXT_PALETTE_BLACK_OFFSET] ^= 0x01
        with pytest.raises(ThemeError, match="Black text palette"):
            _ = build_theme(bytes(firmware), _image_data(), DEEP_ORANGE)

    def test_missing_label_is_rejected(self) -> None:
        firmware = bytearray(_firmware())
        firmware[LABEL_OFFSET : LABEL_OFFSET + 5] = b"Black"
        with pytest.raises(ThemeError, match="'White'"):
            _ = build_theme(bytes(firmware), _image_data(), DEEP_ORANGE)

    def test_unresolved_twins_fail_closed(self) -> None:
        with pytest.raises(ThemeError, match="ambiguous"):
            _ = build_theme(
                _firmware(evidence_at=None),
                _image_data(),
                DEEP_ORANGE,
                ThemeOptions(overrides={}),
            )

    def test_override_reports_the_twin(self) -> None:
        build = build_theme(
            _firmware(evidence_at=None),
            _image_data(),
            DEEP_ORANGE,
            ThemeOptions(overrides={1: Role.WHITE}),
        )
        assert build.report.twins_from_overrides == (1,)
