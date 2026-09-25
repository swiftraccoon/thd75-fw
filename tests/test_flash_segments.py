"""Tests for thd75_fw.flash.segments."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from thd75_fw import kex
from thd75_fw.flash.segments import (
    CHECKBYTES_D75_V103,
    CHECKBYTES_OFFSET,
    CHECKBYTES_SETUP_CHECKSUM_D75_V103,
    D75_V103_MAIN_ERASE_CHECK_LENGTH,
    FINAL_ZZZ_D75_V103,
    FINAL_ZZZ_SETUP_CHECKSUM_D75_V103,
    FINALIZATION_LENGTH,
    FINALIZATION_OFFSET,
    MAIN_FIRMWARE_REGION_END,
    MAIN_FIRMWARE_REGION_START,
    NOR_CPU_WINDOW_END,
    NOR_CPU_WINDOW_START,
    NOR_RELATIVE_WINDOW_END,
    STOCK_TARGET_TYPE_MASK_D75_V103,
    ZZZ_MARKER_OFFSET,
    BootloaderRegionError,
    FlatImageOptions,
    SegmentDescriptor,
    _parse_quoted_hex_u64,
    split_for_safe_zzz_flash,
    validate_main_firmware_region,
    validate_non_bootloader_nor_region,
)
from thd75_fw.kex import KexBlock, firmware_checksum


def _sample() -> SegmentDescriptor:
    return SegmentDescriptor(
        flash_start_addr=0x00200000,
        data_length=0x280000,
        erase_length=0x280000,
        target_type_mask=0xFFFFFFFF_FFFFFFFF,
        erase_wait_seconds=5,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x3343,
        checksum_start_offset=0,
        checksum_length=0x280000,
        checksum_wait_seconds=10,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )


class TestSegmentDescriptor:
    def test_construction(self) -> None:
        d = _sample()
        assert d.flash_start_addr == 0x00200000
        assert d.expected_after_checksum == 0x3343

    def test_frozen(self) -> None:
        d = _sample()
        field_name = "data_length"
        with pytest.raises(AttributeError):
            setattr(d, field_name, 0)

    def test_to_wire_has_expected_length(self) -> None:
        d = _sample()
        wire = d.to_wire()
        # 4+4+4+4(pad)+8+4+2+2+4+4+4+4+4 = 52 fixed + version_check_bytes
        assert len(wire) == 52 + len(d.version_check_bytes)

    def test_to_wire_field_layout(self) -> None:
        d = _sample()
        wire = d.to_wire()
        # First 4 bytes: flash_start_addr LE
        assert wire[0:4] == (0x00200000).to_bytes(4, "little")
        # Next 4: data_length LE
        assert wire[4:8] == (0x280000).to_bytes(4, "little")
        # bytes 12..16 are the padding u32 (all zero)
        assert wire[12:16] == b"\x00\x00\x00\x00"


class TestRangeValidation:
    def test_rejects_oversized_u32_field(self) -> None:
        with pytest.raises(ValueError, match="flash_start_addr"):
            _ = SegmentDescriptor(
                flash_start_addr=0x1_0000_0000,
                data_length=0,
                erase_length=0,
                target_type_mask=0,
                erase_wait_seconds=0,
                expected_before_checksum=0,
                expected_after_checksum=0,
                checksum_start_offset=0,
                checksum_length=0,
                checksum_wait_seconds=0,
                version_start_offset=0,
                version_length=0,
                version_check_bytes=b"",
            )

    def test_rejects_oversized_u16_checksum(self) -> None:
        with pytest.raises(ValueError, match="expected_after_checksum"):
            _ = SegmentDescriptor(
                flash_start_addr=0,
                data_length=0,
                erase_length=0,
                target_type_mask=0,
                erase_wait_seconds=0,
                expected_before_checksum=0,
                expected_after_checksum=0x10000,
                checksum_start_offset=0,
                checksum_length=0,
                checksum_wait_seconds=0,
                version_start_offset=0,
                version_length=0,
                version_check_bytes=b"",
            )


class TestFromKexBlock:
    """Adapter parses $-tagged metadata into SegmentDescriptor fields."""

    def test_parses_minimal_block(self) -> None:
        metadata = (
            b"$SA=0x00200000",
            b"$DL=0x00000010",
            b"$EL=0x00000010",
            b"$TT=0x00000000FFFFFFFF",
            b"$ET=5",
            b"$CB=0xFFFF",
            b"$CA=0x3343",
            b"$CS=0x0",
            b"$CL=0x10",
            b"$CT=10",
            b"$VS=0",
            b"$VL=0",
            b"$VA=",
        )
        block = KexBlock(metadata=metadata, records=b"")
        descriptor = SegmentDescriptor.from_kex_block(block)
        assert descriptor.flash_start_addr == 0x00200000
        assert descriptor.data_length == 0x10
        assert descriptor.expected_after_checksum == 0x3343
        assert descriptor.erase_wait_seconds == 5
        assert descriptor.version_check_bytes == b""

    def test_handles_va_payload(self) -> None:
        metadata = (
            b"$SA=0x0",
            b"$DL=0x10",
            b"$EL=0x10",
            b"$TT=0x1",
            b"$ET=1",
            b"$CB=0x0",
            b"$CA=0x1234",
            b"$CS=0",
            b"$CL=0",
            b"$CT=1",
            b"$VS=0",
            b"$VL=4",
            b"$VA=ABCD",
        )
        descriptor = SegmentDescriptor.from_kex_block(
            KexBlock(metadata=metadata, records=b""),
        )
        assert descriptor.version_check_bytes == b"ABCD"

    def test_strips_va_quotes_like_vendor_parser(self) -> None:
        metadata = (
            b"$SA=0x0",
            b"$DL=0x10",
            b"$EL=0x10",
            b"$TT=0x1",
            b"$ET=1",
            b"$CB=0x0",
            b"$CA=0x1234",
            b"$CS=0",
            b"$CL=0",
            b"$CT=1",
            b"$VS=0",
            b"$VL=15",
            b'$VA="V1.03.000      "',
        )
        descriptor = SegmentDescriptor.from_kex_block(
            KexBlock(metadata=metadata, records=b""),
        )

        assert descriptor.version_check_bytes == b"V1.03.000      "
        assert len(descriptor.to_wire()) == 52 + descriptor.version_length

    def test_empty_quoted_va_serializes_no_bytes(self) -> None:
        metadata = (
            b"$SA=0x0",
            b"$DL=0x2",
            b"$EL=0x0",
            b"$TT=0x1",
            b"$ET=0",
            b"$CB=0x0",
            b"$CA=0x0",
            b"$CS=0",
            b"$CL=0",
            b"$CT=1",
            b"$VS=0",
            b"$VL=0",
            b'$VA=""',
        )
        descriptor = SegmentDescriptor.from_kex_block(
            KexBlock(metadata=metadata, records=b""),
        )

        assert descriptor.version_check_bytes == b""
        assert len(descriptor.to_wire()) == 52

    def test_rejects_va_length_that_disagrees_with_vl(self) -> None:
        metadata = (
            b"$SA=0x0",
            b"$DL=0x10",
            b"$EL=0x10",
            b"$TT=0x1",
            b"$ET=1",
            b"$CB=0x0",
            b"$CA=0x1234",
            b"$CS=0",
            b"$CL=0",
            b"$CT=1",
            b"$VS=0",
            b"$VL=4",
            b'$VA="ABC"',
        )

        with pytest.raises(ValueError, match="must equal version_length"):
            _ = SegmentDescriptor.from_kex_block(
                KexBlock(metadata=metadata, records=b""),
            )

    def test_stock_v103_va_and_wire_lengths(self) -> None:
        """Pin all seven $VA payloads against canonical plaintext stock KEX."""
        plaintext_path = Path("recovery/TH-D75_V103_stock_plaintext.KEX")
        if plaintext_path.exists():
            plaintext = plaintext_path.read_bytes()
        else:
            resource_path = Path(
                "ref/TH-D75_V103_E/THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
            )
            if not resource_path.exists():
                pytest.skip("official V1.03 encrypted resource not present")
            plaintext = kex.render(
                kex.parse_encrypted_resource(
                    resource_path.read_text(encoding="utf-8"),
                )
            )
        assert hashlib.sha256(plaintext).hexdigest() == (
            "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
        )
        image = kex.parse_kex_bytes(plaintext)
        descriptors = [
            SegmentDescriptor.from_kex_block(block) for block in image.blocks
        ]

        expected_va = [
            b"V1.03.000      ",
            b"1.00.02.00",
            b"Dp1.01.00R00",
            b"",
            b"1.00",
            b"",
            b"",
        ]
        expected_wire_lengths = [67, 62, 64, 52, 56, 52, 52]
        assert [item.version_check_bytes for item in descriptors] == expected_va
        assert [len(item.to_wire()) for item in descriptors] == expected_wire_lengths


class TestForFlatImage:
    """SegmentDescriptor.for_flat_image — wrap a raw .bin as a single segment."""

    def test_minimal_image_has_correct_metadata(self) -> None:
        image = b"\x00\x01\x02\x03"  # 4 bytes; checksum = 0x0100 + 0x0302 = 0x0402
        descriptor = SegmentDescriptor.for_flat_image(
            flash_start_addr=0x00200000,
            image=image,
        )
        assert descriptor.flash_start_addr == 0x00200000
        assert descriptor.data_length == 4
        assert descriptor.erase_length == D75_V103_MAIN_ERASE_CHECK_LENGTH
        assert descriptor.checksum_length == D75_V103_MAIN_ERASE_CHECK_LENGTH
        assert descriptor.expected_before_checksum == 0xFFFF
        expected_image = image + b"\xff" * (
            D75_V103_MAIN_ERASE_CHECK_LENGTH - len(image)
        )
        assert descriptor.expected_after_checksum == firmware_checksum(expected_image)
        assert descriptor.version_check_bytes == b""

    def test_real_dumper_sized_image(self) -> None:
        # ~750 bytes, mirroring the dumper.bin size on disk
        image = bytes(range(256)) * 3 + b"\xab" * 7
        descriptor = SegmentDescriptor.for_flat_image(
            flash_start_addr=0x00200000,
            image=image,
        )
        assert descriptor.data_length == len(image)
        # Wire payload round-trip (the bytes that go in the SETUP_SEGMENT frame).
        wire = descriptor.to_wire()
        assert len(wire) == 52
        # The expected_after_checksum field is the 16-bit additive sum.
        expected_image = image + b"\xff" * (
            D75_V103_MAIN_ERASE_CHECK_LENGTH - len(image)
        )
        assert descriptor.expected_after_checksum == firmware_checksum(expected_image)

    def test_explicit_erase_checksum_span_is_honored(self) -> None:
        image = b"\x01\x02\x03\x04"
        descriptor = SegmentDescriptor.for_flat_image(
            flash_start_addr=0x6020_0000,
            image=image,
            options=FlatImageOptions(erase_checksum_length=0x20),
        )
        assert descriptor.erase_length == 0x20
        assert descriptor.checksum_length == 0x20
        assert descriptor.expected_after_checksum == firmware_checksum(
            image + b"\xff" * 0x1C
        )

    def test_rejects_span_shorter_than_data(self) -> None:
        with pytest.raises(ValueError, match="cannot be shorter"):
            _ = SegmentDescriptor.for_flat_image(
                flash_start_addr=0x6020_0000,
                image=b"\x00" * 32,
                options=FlatImageOptions(erase_checksum_length=16),
            )

    def test_overridable_wait_times(self) -> None:
        descriptor = SegmentDescriptor.for_flat_image(
            flash_start_addr=0,
            image=b"\x00",
            options=FlatImageOptions(
                erase_wait_seconds=12, erase_budget_seconds=40, checksum_wait_seconds=30
            ),
        )
        assert descriptor.erase_wait_seconds == 12
        assert descriptor.erase_budget_seconds == 40
        assert descriptor.checksum_wait_seconds == 30

    def test_default_erase_budget_is_the_stock_main_segment_value(self) -> None:
        """Give a raw image the stock main segment's host erase budget.

        A raw image gets the same erase envelope as the stock main
        segment, so it gets that segment's host budget too.

        ``$ET=6``/``$EM=23`` are what the vendor declares for this exact
        ``0x280000`` span. Defaulting the budget to ``$ET`` instead would
        give a raw flash a third of the time the vendor allows its own.
        """
        descriptor = SegmentDescriptor.for_flat_image(
            flash_start_addr=0x0020_0000,
            image=b"\x00" * 64,
        )
        assert descriptor.erase_length == D75_V103_MAIN_ERASE_CHECK_LENGTH
        assert descriptor.erase_wait_seconds == 6
        assert descriptor.erase_budget_seconds == 23
        # Host-side only: the budget must not disturb the 52-byte payload.
        assert len(descriptor.to_wire()) == 52

    def test_overlay_declares_no_erase_budget(self) -> None:
        """An overlay has no erase span or vendor-host erase budget.

        The proven recovery session still sends BEGIN_TRANSFER for this
        descriptor; that command-sequence rule belongs to FlashSession rather
        than the descriptor metadata tested here.
        """
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x0020_0062,
            image=b"\xb0\x1d",
        )
        assert descriptor.erase_length == 0
        assert descriptor.erase_budget_seconds is None

    def test_rejects_a_zero_erase_budget(self) -> None:
        with pytest.raises(ValueError, match="at least 1 second"):
            _ = SegmentDescriptor.for_flat_image(
                flash_start_addr=0x0020_0000,
                image=b"\x00" * 64,
                options=FlatImageOptions(erase_budget_seconds=0),
            )


class TestValidateMainFirmwareRegion:
    """The CLI-side guardrail for modeling bounded offline --raw plans.

    Not enforced by SegmentDescriptor itself: legitimate vendor .KEX
    files occasionally describe segments outside the main-firmware
    slot. The validator is called only on the operator-supplied
    --raw + --flash-addr path; all raw hardware writes are disabled.
    """

    def test_accepts_main_firmware_start(self) -> None:
        # Exact start of the main-firmware region, 1-byte image.
        validate_main_firmware_region(MAIN_FIRMWARE_REGION_START, 1)

    def test_accepts_exact_stock_main_envelope(self) -> None:
        # An image that exactly fills stock V1.03's 0x280000 EL/CL span.
        validate_main_firmware_region(
            MAIN_FIRMWARE_REGION_START,
            MAIN_FIRMWARE_REGION_END - MAIN_FIRMWARE_REGION_START,
        )

    def test_rejects_bootloader_region(self) -> None:
        with pytest.raises(BootloaderRegionError, match="low-NOR"):
            validate_main_firmware_region(0x0000_0000, 0x1000)

    def test_rejects_just_below_main_region(self) -> None:
        with pytest.raises(BootloaderRegionError, match="below"):
            validate_main_firmware_region(MAIN_FIRMWARE_REGION_START - 4, 4)

    def test_rejects_overrun_past_main_region(self) -> None:
        with pytest.raises(BootloaderRegionError, match="extend past"):
            validate_main_firmware_region(
                MAIN_FIRMWARE_REGION_END - 0x100,
                0x200,  # 0x100 spills past the end
            )

    def test_rejects_starting_at_main_region_end(self) -> None:
        with pytest.raises(BootloaderRegionError, match="extend past"):
            validate_main_firmware_region(MAIN_FIRMWARE_REGION_END, 1)

    def test_message_includes_explicit_addresses(self) -> None:
        # The operator-facing error must include the actual numbers so
        # the operator can verify them against documentation.
        with pytest.raises(BootloaderRegionError) as exc_info:
            validate_main_firmware_region(0x0000_1000, 0x100)
        msg = str(exc_info.value)
        assert "0x00001000" in msg
        assert f"0x{MAIN_FIRMWARE_REGION_START:08X}" in msg

    def test_region_constants_match_linker_layout(self) -> None:
        # Cross-check the constants against the documented NOR layout
        # (firmware/linker.ld FLASH region: ORIGIN=0x60200000,
        # LENGTH=0x00280000 → NOR-offset 0x00200000..0x00480000).
        assert MAIN_FIRMWARE_REGION_START == 0x0020_0000
        assert MAIN_FIRMWARE_REGION_END == 0x0048_0000
        assert MAIN_FIRMWARE_REGION_END - MAIN_FIRMWARE_REGION_START == 0x0028_0000


class TestValidateNonBootloaderNorRegion:
    """Session-level plans can use all stock regions but never low NOR."""

    @pytest.mark.parametrize(
        ("start", "length"),
        [
            (MAIN_FIRMWARE_REGION_START, 1),
            (NOR_CPU_WINDOW_START + MAIN_FIRMWARE_REGION_START, 1),
            (NOR_RELATIVE_WINDOW_END - 1, 1),
            (NOR_CPU_WINDOW_END - 1, 1),
            # Stock's large 0x61600000 segment ends exactly at 0x62000000.
            (0x6160_0000, 0x00A0_0000),
        ],
    )
    def test_accepts_non_bootloader_spans(self, start: int, length: int) -> None:
        validate_non_bootloader_nor_region(start, length)

    @pytest.mark.parametrize(
        ("start", "length", "match"),
        [
            (0, 1, "low-NOR"),
            (NOR_CPU_WINDOW_START, 1, "low-NOR"),
            (MAIN_FIRMWARE_REGION_START - 1, 2, "low-NOR"),
            (NOR_CPU_WINDOW_START + MAIN_FIRMWARE_REGION_START - 1, 2, "low-NOR"),
            (NOR_RELATIVE_WINDOW_END - 1, 2, "past"),
            (NOR_CPU_WINDOW_END - 1, 2, "past"),
            (0x1000_0000, 1, "outside"),
            (MAIN_FIRMWARE_REGION_START, 0, "nonzero"),
        ],
    )
    def test_rejects_low_or_out_of_window_spans(
        self,
        start: int,
        length: int,
        match: str,
    ) -> None:
        with pytest.raises(BootloaderRegionError, match=match):
            validate_non_bootloader_nor_region(start, length)


class TestForUnerasedOverlay:
    """Constructor for the ZZZ-overlay segment.

    erase_length must be 0 so FLDM does NOT erase the surrounding
    (already-flashed) firmware.
    """

    def test_erase_length_is_zero(self) -> None:
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x0020_0040,
            image=b"\x00" * 32,
        )
        assert descriptor.erase_length == 0

    def test_data_length_matches_image(self) -> None:
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x6020_0040,
            image=b"\x42" * 32,
        )
        assert descriptor.data_length == 32
        # checksum_length=0 matches the stock V1.03 vendor pattern
        # for sub-sector overlays — the decompiled .NET updater has
        # explicit logic (f.cs::case 9) that skips VERIFY_SEGMENT
        # when $CL is zero, and every overlay segment in the stock
        # KEX (segments 5 and 6) uses $CL=0. Forcing VERIFY on an
        # overlay risks a checksum-algorithm mismatch and a NAK.
        assert descriptor.checksum_length == 0

    def test_expected_before_and_after_checksums_match_stock_pattern(self) -> None:
        # Stock V1.03 overlay segments set $CB == $CA (both fields
        # populated, both ignored by the radio since $CL=0). We
        # mirror that pattern so the wire bytes match stock closely.
        zzz = b"ZZzo..(-_- ) EX-5210 2022-07-20\x00"
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x6020_0040,
            image=zzz,
        )
        expected = firmware_checksum(zzz)
        assert descriptor.expected_before_checksum == expected
        assert descriptor.expected_after_checksum == expected

    @pytest.mark.parametrize(
        ("image", "expected"),
        [
            (CHECKBYTES_D75_V103, CHECKBYTES_SETUP_CHECKSUM_D75_V103),
            (FINAL_ZZZ_D75_V103, FINAL_ZZZ_SETUP_CHECKSUM_D75_V103),
        ],
    )
    def test_explicit_stock_setup_checksum_is_preserved(
        self,
        image: bytes,
        expected: int,
    ) -> None:
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x6020_0040,
            image=image,
            setup_checksum=expected,
        )
        assert descriptor.expected_before_checksum == expected
        assert descriptor.expected_after_checksum == expected

    def test_target_type_mask_matches_stock_default(self) -> None:
        # Every stock V1.03 segment ships $TT="0F 00 00 00 00 00 00 00",
        # which the vendor reads as 0x0F00000000000000. The radio's
        # QUERY_TARGET compatibility bytes 02 00 00 00 00 00 00 00 decode
        # the same way to 0x0200000000000000, so the two intersect and the
        # host-side compatibility check passes.
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x6020_0040,
            image=b"\x42" * 32,
        )
        assert descriptor.target_type_mask == STOCK_TARGET_TYPE_MASK_D75_V103

    def test_version_check_bytes_match_stock_overlay_pattern(self) -> None:
        # Stock overlay segments (5, 6) spell the empty value as
        # ``$VA=""`` in KEX text. Vendor p.cs strips the quotes and
        # j.cs appends zero bytes, matching $VL=0.
        descriptor = SegmentDescriptor.for_unerased_overlay(
            flash_start_addr=0x6020_0040,
            image=b"\x42" * 32,
        )
        assert descriptor.version_check_bytes == b""


class TestSplitForSafeZzzFlash:
    """The split mimics the official updater's exact resource order.

    The official Kenwood TH-D75 firmware updater writes the body with
    0x40..0x7f erased, then CHECKBYTES, then FINAL_ZZZ last. Boot gating
    remains a D74-derived D75 hypothesis.
    """

    def _real_zzz(self) -> bytes:
        return FINAL_ZZZ_D75_V103

    def _image(self) -> bytes:
        body = bytearray(b"\xab" * 128)
        body[FINALIZATION_OFFSET : FINALIZATION_OFFSET + FINALIZATION_LENGTH] = (
            FINAL_ZZZ_D75_V103 + b"\xff\xff" + CHECKBYTES_D75_V103 + b"\xff" * 28
        )
        return bytes(body)

    def test_stock_shaped_image_splits_into_three_segments(self) -> None:
        pairs = split_for_safe_zzz_flash(
            flash_start_addr=MAIN_FIRMWARE_REGION_START,
            image=self._image(),
        )
        assert len(pairs) == 3

    def test_body_segment_has_entire_finalization_block_erased(self) -> None:
        pairs = split_for_safe_zzz_flash(
            flash_start_addr=MAIN_FIRMWARE_REGION_START,
            image=self._image(),
        )
        body_desc, body_bytes = pairs[0]
        assert (
            body_bytes[FINALIZATION_OFFSET : FINALIZATION_OFFSET + FINALIZATION_LENGTH]
            == b"\xff" * FINALIZATION_LENGTH
        )
        assert body_bytes[:FINALIZATION_OFFSET] == b"\xab" * FINALIZATION_OFFSET
        assert body_desc.erase_length == D75_V103_MAIN_ERASE_CHECK_LENGTH
        assert body_desc.checksum_length == D75_V103_MAIN_ERASE_CHECK_LENGTH

    def test_overlay_payloads_and_order_match_stock(self) -> None:
        pairs = split_for_safe_zzz_flash(
            flash_start_addr=MAIN_FIRMWARE_REGION_START,
            image=self._image(),
        )
        check_desc, check_bytes = pairs[1]
        zzz_desc, zzz_bytes = pairs[2]
        assert check_bytes == CHECKBYTES_D75_V103
        assert zzz_bytes == FINAL_ZZZ_D75_V103
        assert check_desc.flash_start_addr == (
            MAIN_FIRMWARE_REGION_START + CHECKBYTES_OFFSET
        )
        assert zzz_desc.flash_start_addr == (
            MAIN_FIRMWARE_REGION_START + ZZZ_MARKER_OFFSET
        )
        assert check_desc.expected_after_checksum == 0x9DB1
        assert zzz_desc.expected_after_checksum == 0xCBA6

    def test_zzz_segment_targets_absolute_zzz_nor_address(self) -> None:
        pairs = split_for_safe_zzz_flash(
            flash_start_addr=MAIN_FIRMWARE_REGION_START,
            image=self._image(),
        )
        zzz_desc, _ = pairs[2]
        assert (
            zzz_desc.flash_start_addr == MAIN_FIRMWARE_REGION_START + ZZZ_MARKER_OFFSET
        )
        # Empirical confirmation: this matches the NOR offset the
        # official Kenwood TH-D75 firmware updater writes the 32-byte
        # ZZZ marker to (separately from the main firmware bytes).
        assert zzz_desc.flash_start_addr == 0x0020_0040

    def test_zzz_segment_has_no_erase(self) -> None:
        pairs = split_for_safe_zzz_flash(
            flash_start_addr=MAIN_FIRMWARE_REGION_START,
            image=self._image(),
        )
        check_desc, _ = pairs[1]
        zzz_desc, _ = pairs[2]
        # erase_length=0 is the safety-critical bit: FLDM must not
        # erase the sector containing the firmware we just wrote.
        assert zzz_desc.erase_length == 0
        assert check_desc.erase_length == 0

    def test_image_too_small_for_finalization_is_rejected(self) -> None:
        tiny = b"\x42" * 16
        with pytest.raises(ValueError, match="too short"):
            _ = split_for_safe_zzz_flash(
                flash_start_addr=MAIN_FIRMWARE_REGION_START,
                image=tiny,
            )

    def test_nonstock_finalization_is_rejected(self) -> None:
        unexpected = bytearray(self._image())
        unexpected[CHECKBYTES_OFFSET] ^= 1
        with pytest.raises(ValueError, match="does not match"):
            _ = split_for_safe_zzz_flash(
                flash_start_addr=MAIN_FIRMWARE_REGION_START,
                image=bytes(unexpected),
            )

    def test_total_payload_round_trips_to_original(self) -> None:
        """Reassemble the input image from the 3 segments in vendor order."""
        image = self._image()

        pairs = split_for_safe_zzz_flash(
            flash_start_addr=MAIN_FIRMWARE_REGION_START,
            image=image,
        )
        body_desc, body_bytes = pairs[0]
        check_desc, check_bytes = pairs[1]
        zzz_desc, zzz_bytes = pairs[2]

        # Reconstruct what the final NOR contents will be:
        reconstructed = bytearray(body_bytes)
        # The overlay writes at an absolute NOR address; compute its
        # offset inside the body slice.
        check_offset = check_desc.flash_start_addr - body_desc.flash_start_addr
        reconstructed[check_offset : check_offset + len(check_bytes)] = check_bytes
        zzz_offset = zzz_desc.flash_start_addr - body_desc.flash_start_addr
        reconstructed[zzz_offset : zzz_offset + len(zzz_bytes)] = zzz_bytes
        assert bytes(reconstructed) == image


class TestQuotedHexBytesParsing:
    """Parse the stock KEX's quoted-hex ``$TT`` form as well as integers.

    The stock Kenwood TH-D75 V1.03 KEX uses the format
    ``$TT="0F 00 00 00 00 00 00 00"`` for the 64-bit target_type_mask
    — a double-quoted, space-separated hex numeral whose spacing is
    cosmetic, not a plain integer literal. Our parser must accept both
    forms, or the recovery KEX won't load via thd75-flash.
    """

    def test_leading_group_is_the_high_byte(self) -> None:
        # Real V1.03 stock value. The vendor evaluates the de-spaced text
        # as one hex numeral (j.cs:1071), so 0F is the most significant
        # byte, not the least.
        assert (
            _parse_quoted_hex_u64('"0F 00 00 00 00 00 00 00"') == 0x0F00_0000_0000_0000
        )

    def test_trailing_group_is_the_low_byte(self) -> None:
        assert (
            _parse_quoted_hex_u64(
                '"00 00 00 00 00 00 00 80"',
            )
            == 0x80
        )

    def test_rejects_unquoted_value(self) -> None:
        assert _parse_quoted_hex_u64("0F 00 00 00 00 00 00 00") is None

    def test_rejects_non_hex_content(self) -> None:
        assert _parse_quoted_hex_u64('"XX YY"') is None

    def test_from_kex_block_accepts_quoted_tt(self) -> None:
        # The real-world failing case: a stock-KEX block where $TT is
        # in quoted-hex-bytes form. Prior to the parser fix this raised
        # ValueError("$ TT must be an integer in KEX metadata, got ...").
        metadata = (
            b"$SA=0x00200000",
            b"$DL=0x00000010",
            b"$EL=0x00000010",
            b'$TT="0F 00 00 00 00 00 00 00"',
            b"$ET=5",
            b"$CB=0xFFFF",
            b"$CA=0x3343",
            b"$CS=0x0",
            b"$CL=0x10",
            b"$CT=10",
            b"$VS=0",
            b"$VL=0",
            b"$VA=",
        )
        block = KexBlock(metadata=metadata, records=b"")
        descriptor = SegmentDescriptor.from_kex_block(block)
        assert descriptor.target_type_mask == STOCK_TARGET_TYPE_MASK_D75_V103


class TestRecoveryDocConsistency:
    """The recovery procedure's cited addresses must match the code.

    The stock recovery procedure in docs/FLASHING.md cites specific
    addresses; they must match the constants the code actually uses.
    Catches doc-rot when the region layout is changed in segments.py but
    not the recovery procedure.
    """

    def _recovery_doc(self) -> str:
        # Project root → docs/FLASHING.md
        doc = Path(__file__).resolve().parent.parent / "docs" / "FLASHING.md"
        assert doc.exists(), f"flashing guide missing: {doc}"
        return doc.read_text(encoding="utf-8")

    def test_doc_cites_main_firmware_region_start(self) -> None:
        doc = self._recovery_doc()
        # The documented --flash-addr for the dumper must equal the
        # main-firmware region start; otherwise we're telling the
        # operator one number while the code accepts another.
        expected = f"0x{MAIN_FIRMWARE_REGION_START:08X}".lower()
        assert expected in doc.lower(), (
            f"FLASHING.md does not mention {expected} — has the "
            f"region layout changed without updating the runbook?"
        )

    def test_doc_warns_about_zero_flash_addr(self) -> None:
        # The "do NOT pass 0x00000000" warning is the single most
        # important line in the runbook; ensure it survives edits.
        doc = self._recovery_doc()
        assert "0x00000000" in doc

    def test_doc_refuses_raw_bootloader_writes(self) -> None:
        doc = self._recovery_doc()
        assert "raw bootloader writes are not supported" in doc.lower()
