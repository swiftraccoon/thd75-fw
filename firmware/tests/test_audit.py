"""Regression tests for the target payload's post-build safety audit."""

from __future__ import annotations

import struct
import unittest

import audit


def _metadata(text: bytes) -> bytes:
    """Build a stock-style 32-byte NUL/erased-padded metadata field."""
    return text + b"\x00" + b"\xff" * (31 - len(text))


def _valid_image() -> bytearray:
    """Construct the smallest byte image satisfying the D75 boot contract."""
    image = bytearray(b"\xff" * (audit.TEXT_OFFSET + 4))
    image[:0x20] = audit.VECTOR_OPCODE * 8
    image[0x20:0x40] = struct.pack(
        "<8I",
        *([audit.DDR_START + audit.TEXT_OFFSET] * 8),
    )
    image[audit.FINALIZATION_OFFSET : audit.VERSION_OFFSET] = (
        audit.FINAL_ZZZ_D75 + b"\xff\xff" + audit.CHECKBYTES_D75_V103 + b"\xff" * 28
    )
    image[audit.VERSION_OFFSET : audit.VERSION_OFFSET + 0x20] = _metadata(b"test")
    image[audit.VERSION_OFFSET + 0x20 : audit.PRIMARY_DESCRIPTOR_OFFSET] = _metadata(
        b"V0.0.0"
    )
    primary_descriptor = struct.pack("<8I", *audit.EXPECTED_PRIMARY_DESCRIPTOR)
    secondary_descriptor = struct.pack("<8I", *audit.EXPECTED_SECONDARY_DESCRIPTOR)
    image[
        audit.PRIMARY_DESCRIPTOR_OFFSET : audit.PRIMARY_DESCRIPTOR_OFFSET
        + audit.DESCRIPTOR_SIZE
    ] = primary_descriptor
    image[
        audit.SECONDARY_DESCRIPTOR_OFFSET : audit.SECONDARY_DESCRIPTOR_OFFSET
        + audit.DESCRIPTOR_SIZE
    ] = secondary_descriptor
    image[audit.TEXT_OFFSET :] = b"\x00\x00\x00\xea"
    return image


class BinaryLayoutTests(unittest.TestCase):
    """Exercise every byte range whose regression could prevent boot."""

    def test_valid_image_passes(self) -> None:
        """A stock-shaped minimal payload has no audit findings."""
        assert audit.audit_binary_layout(bytes(_valid_image())) == []

    def test_rejects_non_erased_header_gap(self) -> None:
        """Catch lld's historical 00 00 00 FF fill regression."""
        image = _valid_image()
        image[0x100] = 0
        assert any(
            "padding" in finding for finding in audit.audit_binary_layout(bytes(image))
        )

    def test_rejects_missing_checkbytes(self) -> None:
        """CHECKBYTES must remain B0 1D at image offset 0x62."""
        image = _valid_image()
        image[0x62:0x64] = b"\xff\xff"
        assert any(
            "CHECKBYTES" in finding
            for finding in audit.audit_binary_layout(bytes(image))
        )

    def test_rejects_descriptor_disagreement(self) -> None:
        """Both stock D75 descriptor slots must remain independently valid."""
        image = _valid_image()
        image[audit.SECONDARY_DESCRIPTOR_OFFSET] ^= 1
        assert any(
            "secondary descriptor" in finding
            for finding in audit.audit_binary_layout(bytes(image))
        )

    def test_rejects_handler_outside_loaded_image(self) -> None:
        """Vectors must stay inside the candidate descriptor copy span."""
        image = _valid_image()
        struct.pack_into("<I", image, 0x20, audit.DDR_END)
        assert any(
            "vector 0 handler" in finding
            for finding in audit.audit_binary_layout(bytes(image))
        )

    def test_rejects_image_beyond_stock_update_envelope(self) -> None:
        """The 3 MiB copy field must not widen the 2.5 MiB write envelope."""
        image = _valid_image()
        envelope_length = audit.STOCK_UPDATE_ENVELOPE_END - audit.FLASH_SLOT_START
        image.extend(b"\xff" * (envelope_length + 1 - len(image)))
        assert any(
            "2.5 MiB V1.03 FIRMWARE" in finding
            for finding in audit.audit_binary_layout(bytes(image))
        )


class ElfLayoutTests(unittest.TestCase):
    """Cover ELF entry and section placement rules."""

    def test_expected_sections_pass(self) -> None:
        """The header and text at their fixed DDR offsets are accepted."""
        sections = [
            audit.Section(
                ".firmware_header", audit.HEADER_SIZE, audit.DDR_START, "TEXT"
            ),
            audit.Section(".text", 4, audit.DDR_START + audit.TEXT_OFFSET, "TEXT"),
        ]
        assert audit.audit_sections(sections) == []

    def test_bss_does_not_inflate_flat_binary_size(self) -> None:
        """NOLOAD BSS occupies DDR but is absent from objcopy output."""
        sections = [
            audit.Section(
                ".firmware_header", audit.HEADER_SIZE, audit.DDR_START, "TEXT"
            ),
            audit.Section(".text", 4, audit.DDR_START + audit.TEXT_OFFSET, "TEXT"),
            audit.Section(
                ".bss", 0x100, audit.DDR_START + audit.TEXT_OFFSET + 4, "BSS"
            ),
        ]
        assert (
            audit.audit_binary_size_vs_sections(bytes(_valid_image()), sections) == []
        )

    def test_wrong_text_offset_fails(self) -> None:
        """Catch a location-counter assignment ignored by the linker."""
        sections = [
            audit.Section(".firmware_header", 0xE0, audit.DDR_START, "TEXT"),
            audit.Section(".text", 4, audit.DDR_START + 0xE0, "TEXT"),
        ]
        findings = audit.audit_sections(sections)
        assert any("exactly 0x200" in finding for finding in findings)
        assert any(".text must start" in finding for finding in findings)

    def test_entry_parser_and_audit(self) -> None:
        """The ELF entry must point at the vector table, not `_reset`."""
        parsed = audit.parse_start_address("start address: 0xc0000000\n")
        assert parsed == audit.DDR_START
        assert audit.audit_start_address(parsed) == []
        assert audit.audit_start_address(audit.DDR_START + 512)

    def test_decimal_nor_immediate_is_inventoried(self) -> None:
        """ARM constants printed in decimal must not bypass the NOR audit."""
        disassembly = "mov r5, #1610612736\n"  # 0x60000000
        assert audit.collect_nor_addresses(disassembly) == {audit.NOR_START}


if __name__ == "__main__":
    _ = unittest.main()
