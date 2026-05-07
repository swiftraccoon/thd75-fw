"""Tests for section metadata."""

from __future__ import annotations

from thd75_fw.sections import (
    SECTIONS,
    FlashAddress,
    SectionInfo,
    lookup_by_address,
    lookup_by_name,
    name_for_address,
)


class TestSECTIONS:
    """Invariants on the SECTIONS tuple itself."""

    def test_seven_sections_defined(self) -> None:
        assert len(SECTIONS) == 7

    def test_all_addresses_unique(self) -> None:
        addresses = [section.flash_address for section in SECTIONS]
        assert len(set(addresses)) == len(addresses)

    def test_all_names_unique(self) -> None:
        names = [section.name for section in SECTIONS]
        assert len(set(names)) == len(names)


class TestSectionInfoFilename:
    """The ``filename`` property is the contract the CLI relies on."""

    def test_filename_format(self) -> None:
        info = SectionInfo(
            name="FOO",
            flash_address=FlashAddress(0x01234567),
            expected_size=100,
            description="test",
        )
        assert info.filename == "FOO_0x01234567.bin"

    def test_real_section_filename(self) -> None:
        firmware = lookup_by_name("FIRMWARE")
        assert firmware is not None
        assert firmware.filename == "FIRMWARE_0x00200000.bin"


class TestLookups:
    """``lookup_by_address`` and ``lookup_by_name`` return Optional types
    so callers can distinguish known sections from unknown addresses."""

    def test_lookup_by_address_known(self) -> None:
        info = lookup_by_address(FlashAddress(0x00200000))
        assert info is not None
        assert info.name == "FIRMWARE"

    def test_lookup_by_address_unknown_returns_none(self) -> None:
        assert lookup_by_address(FlashAddress(0xDEADBEEF)) is None

    def test_lookup_by_name_known(self) -> None:
        info = lookup_by_name("DATA_0160")
        assert info is not None
        assert info.flash_address == FlashAddress(0x01600000)

    def test_lookup_by_name_unknown_returns_none(self) -> None:
        assert lookup_by_name("NOT_A_REAL_SECTION") is None


class TestNameForAddress:
    """``name_for_address`` always returns a string; unknown addresses
    get a synthesized ``UNKNOWN_<hex>`` form distinguishable from real
    section names."""

    def test_known_returns_name(self) -> None:
        assert name_for_address(FlashAddress(0x01600000)) == "DATA_0160"

    def test_unknown_returns_unknown_format(self) -> None:
        assert (
            name_for_address(FlashAddress(0xDEADBEEF))
            == "UNKNOWN_DEADBEEF"
        )
