"""Slow end-to-end checks of the orange-on-black theme against the real V1.03 updater."""

from __future__ import annotations

import hashlib
import importlib.resources
from pathlib import Path

import pytest

from thd75_fw import cli, images, kex, resource
from thd75_fw.patch import load_patch
from thd75_fw.theme import DEEP_ORANGE, build_theme
from thd75_fw.theme.png import decode_8bit, is_indexed_8bit

_REAL_EXE = (
    Path(__file__).resolve().parent.parent
    / "ref"
    / "TH-D75_V103_E"
    / "TH-D75_V103_e.exe"
)

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not _REAL_EXE.is_file(), reason="real updater .exe absent (ref/ is gitignored)"
    ),
]


@pytest.fixture(scope="module")
def stock_resource() -> str:
    return resource.extract(_REAL_EXE.read_bytes())


@pytest.fixture(scope="module")
def stock_sections(stock_resource: str) -> tuple[bytes, bytes]:
    model = kex.parse_resource(stock_resource)
    return kex.section_image(model, "FIRMWARE"), kex.section_image(model, "IMAGE_DATA")


def test_catalog_entry_is_the_generator_output(
    stock_sections: tuple[bytes, bytes],
) -> None:
    firmware, image_data = stock_sections
    build = build_theme(firmware, image_data, DEEP_ORANGE)
    committed = (
        importlib.resources.files("thd75_fw") / "patches" / "orange-on-black.toml"
    ).read_text(encoding="utf-8")
    assert build.toml == committed
    assert build.report.twin_groups == 105
    assert build.report.twins_recoloured == 127
    assert set(build.report.palettes_changed) == {9, 10, 11, 12, 14, 16, 17}


def test_theme_applies_to_stock_and_pins_image_data(stock_resource: str) -> None:
    entry = load_patch("orange-on-black")
    rendered = kex.patch_kex_stack(stock_resource, [entry])
    model = kex.parse_kex_bytes(rendered)
    (pins,) = entry.section_hashes
    image_data = kex.section_image(model, "IMAGE_DATA")
    assert hashlib.sha256(image_data).hexdigest() == pins.result_sha256
    assert image_data[:11] == b"1.00.02.01\x00"
    assert b'$VA="1.00.02.01"' in model.blocks[1].metadata
    firmware = kex.section_image(model, "FIRMWARE")
    assert firmware[0x8798:0x879F] == b"Orange\x00"
    assert firmware[0x15FB10:0x15FB24] == bytes.fromhex(
        "60FC 0000 00F8 60FC 9F86 6051 60FC 1433 895C 0000"
    )


_FAMILY_CHAIN = (
    "normal-gm-nor-read",
    "normal-gm-nor-read-usb-recover",
    "normal-gm-nor-read-usb-recover-azimuth",
)


def test_theme_stacks_on_a_normal_gm_family_firmware(
    stock_resource: str, stock_sections: tuple[bytes, bytes]
) -> None:
    """The Azimuth chain plus the theme renders the admitted composite KEX."""
    stages = [load_patch(name) for name in (*_FAMILY_CHAIN, "orange-on-black")]
    rendered = kex.patch_kex_stack(stock_resource, stages)
    assert (
        hashlib.sha256(rendered).hexdigest()
        == cli._AZIMUTH_ORANGE_ON_BLACK_PLAINTEXT_KEX_SHA256
    )
    model = kex.parse_kex_bytes(rendered)
    firmware = kex.section_image(model, "FIRMWARE")
    stock_firmware, _ = stock_sections
    assert firmware != stock_firmware
    assert firmware[0x8798:0x879F] == b"Orange\x00"
    assert firmware[0x15FB10:0x15FB24] == bytes.fromhex(
        "60FC 0000 00F8 60FC 9F86 6051 60FC 1433 895C 0000"
    )


def test_every_touched_png_still_decodes_to_the_same_pixels(
    stock_resource: str, stock_sections: tuple[bytes, bytes]
) -> None:
    _, stock_image_data = stock_sections
    rendered = kex.patch_kex_stack(stock_resource, [load_patch("orange-on-black")])
    patched_image_data = kex.section_image(kex.parse_kex_bytes(rendered), "IMAGE_DATA")
    before = images.load(stock_image_data).images
    after = images.load(patched_image_data).images
    touched = 0
    for old, new in zip(before, after, strict=True):
        if old.data == new.data or not is_indexed_8bit(old.data):
            continue
        touched += 1
        assert decode_8bit(old.data).pixels == decode_8bit(new.data).pixels
    assert touched == 127
