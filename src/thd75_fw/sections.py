"""Firmware section definitions for the Kenwood TH-D75.

Each section maps to a specific NOR flash region on the radio's
TI OMAP-L138 SoC. The section layout is defined by the DataBlockInfo
metadata embedded in the .NET firmware updater.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NewType

__all__: list[str] = [
    "FLASH_BASE",
    "SECTIONS",
    "FlashAddress",
    "SectionInfo",
    "lookup_by_address",
    "lookup_by_name",
    "name_for_address",
]


FlashAddress = NewType("FlashAddress", int)
"""A flash-relative address (offset from the SoC's NOR flash base).

This is the ``SectionInfo.flash_address`` form, the form used in
filenames produced by ``thd75-extract`` (e.g.,
``FIRMWARE_0x00200000.bin``), and the form returned by
``cli._extract_flash_address``. Distinct from a *physical* address
(which adds ``FLASH_BASE``) and from a DDR address (``0xC0xxxxxx``).
"""


# Base physical address of the OMAP-L138's external NOR flash region.
# The updater stores section start addresses ($SA= metadata) as physical
# addresses including this offset; subtracting it gives the flash-relative
# offset used as a section's filename and as SectionInfo.flash_address.
# (Not to be confused with DDR base 0xC0000000, where the runtime image
# lives after the bootloader copies it from flash.)
FLASH_BASE: FlashAddress = FlashAddress(0x6000_0000)


@dataclass(frozen=True, slots=True)
class SectionInfo:
    """Immutable metadata for a single firmware section."""

    name: str
    flash_address: FlashAddress
    expected_size: int
    description: str

    @property
    def filename(self) -> str:
        """Standard output filename: ``<name>_0x<address>.bin``."""
        return f"{self.name}_0x{self.flash_address:08X}.bin"


SECTIONS: tuple[SectionInfo, ...] = (
    SectionInfo(
        name="FIRMWARE",
        flash_address=FlashAddress(0x0020_0000),
        expected_size=2_621_440,
        description="ARM926EJ-S executable code and embedded data",
    ),
    SectionInfo(
        name="IMAGE_DATA",
        flash_address=FlashAddress(0x0060_0000),
        expected_size=393_216,
        description="862 PNG images with RGB565 color palettes",
    ),
    SectionInfo(
        name="DATA_00E0",
        flash_address=FlashAddress(0x00E0_0000),
        expected_size=1_048_576,
        description="TI C6748 AMBE2+ DSP firmware",
    ),
    SectionInfo(
        name="DATA_0160",
        flash_address=FlashAddress(0x0160_0000),
        expected_size=10_485_760,
        description="Voice prompt database (8-bit PCM, 8 kHz, 3 languages)",
    ),
    SectionInfo(
        name="FONT_DATA",
        flash_address=FlashAddress(0x0150_0000),
        expected_size=786_432,
        description="Shift-JIS display fonts (16x16 and 24x24, 1-bit mono)",
    ),
    SectionInfo(
        name="CHECKBYTES",
        flash_address=FlashAddress(0x0020_0062),
        expected_size=2,
        description="Bootloader integrity checksum (0xB01D in V1.03)",
    ),
    SectionInfo(
        name="FINAL_ZZZ",
        flash_address=FlashAddress(0x0020_0040),
        expected_size=32,
        description="Build marker written last to confirm update completion",
    ),
)

_BY_ADDRESS: dict[FlashAddress, SectionInfo] = {
    section.flash_address: section for section in SECTIONS
}
_BY_NAME: dict[str, SectionInfo] = {section.name: section for section in SECTIONS}


def lookup_by_address(address: FlashAddress) -> SectionInfo | None:
    """Return section info for a flash address, or ``None``."""
    return _BY_ADDRESS.get(address)


def lookup_by_name(name: str) -> SectionInfo | None:
    """Return section info for a section name, or ``None``."""
    return _BY_NAME.get(name)


def name_for_address(address: FlashAddress) -> str:
    """Return the human-readable name for a flash address.

    Returns the section's ``name`` if known, or a synthesized
    ``UNKNOWN_<hex>`` label otherwise. Callers that need to distinguish
    known from unknown should use ``lookup_by_address`` instead, which
    returns ``None`` for unknown addresses.
    """
    info = _BY_ADDRESS.get(address)
    return info.name if info else f"UNKNOWN_{address:08X}"
