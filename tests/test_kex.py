"""Tests for .KEX firmware-file patching."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from thd75_fw import intel_hex
from thd75_fw.file_cipher import RollingKeyState, encrypt_line
from thd75_fw.kex import (
    Kex,
    KexBlock,
    firmware_checksum,
    parse_resource,
    patch_kex,
    patch_resource,
    render,
)
from thd75_fw.patch import ByteChange, PatchVerificationError, load_patch
from thd75_fw.resource import extract, replace

if TYPE_CHECKING:
    from collections.abc import Callable

    EncryptResource = Callable[[list[tuple[bytes, list[bytes]]]], str]
    IntelHexRecord = Callable[..., bytes]


def _firmware_image(kex_file: bytes) -> bytes:
    """Reconstruct the flat firmware image from a single-block .KEX file."""
    packed = b"".join(
        bytes.fromhex(line[1:].decode("ascii"))
        for line in kex_file.split(b"\r\n")
        if line.startswith(b":")
    )
    return intel_hex.parse(packed).data


def _firmware_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecord,
    image: bytes,
) -> str:
    """Build an encrypted resource holding a single FIRMWARE block."""
    payload = bytes([len(image), 0x00, 0x00, 0x00]) + image
    data_record = intel_hex_record(
        len(image), 0, 0x00, image, intel_hex.record_checksum(payload)
    )
    eof = intel_hex_record(0, 0, 0x01, b"", 0xFF)
    return encrypt_resource([
        (b"$ST", []),
        (b"$SA=0x60200000", []),
        (b"$CS=0x00000000", []),
        (b"$CL=0x%08X" % len(image), []),
        (b"$CA=0x0000", []),
        (b"$ED", [data_record + eof]),
    ])


class TestFirmwareChecksum:
    """``firmware_checksum`` is the updater's $CA/$CB algorithm: a sum
    of 16-bit little-endian words taken modulo 0x10000."""

    def test_empty(self) -> None:
        assert firmware_checksum(b"") == 0x0000

    def test_single_little_endian_word(self) -> None:
        # Bytes 0x34, 0x12 form the little-endian word 0x1234.
        assert firmware_checksum(b"\x34\x12") == 0x1234

    def test_words_sum(self) -> None:
        assert firmware_checksum(b"\x34\x12\x01\x00") == 0x1234 + 0x0001

    def test_wraps_modulo_0x10000(self) -> None:
        # 0xFFFF + 0x0002 = 0x10001, which wraps to 0x0001.
        assert firmware_checksum(b"\xFF\xFF\x02\x00") == 0x0001

    def test_odd_trailing_byte_is_low_byte_of_final_word(self) -> None:
        # An odd-length region pads with a zero high byte.
        assert firmware_checksum(b"\x34\x12\x07") == 0x1234 + 0x0007

    def test_pf_capture_patch_delta(self) -> None:
        # The PF-key patch raises two even-offset bytes by 0x18 each;
        # each is the low byte of a little-endian word, so $CA rises 0x30.
        before = b"\x1B\x00\x1B\x00"
        after = b"\x33\x00\x33\x00"
        assert firmware_checksum(after) == firmware_checksum(before) + 0x30


class TestParseResource:
    """``parse_resource`` decrypts an encrypted updater resource into a
    Kex model: one KexBlock per firmware section, holding that section's
    raw metadata lines and its packed Intel HEX records."""

    def test_single_block_metadata_and_records(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        records = intel_hex_record(
            4, 0, 0x00, b"\xAA\xBB\xCC\xDD"
        ) + intel_hex_record(0, 0, 0x01)
        text = encrypt_resource([
            (b"$ST", []),
            (b"$SA=0x60200000", []),
            (b"$ED", [records]),
        ])
        kex = parse_resource(text)
        assert len(kex.blocks) == 1
        assert kex.blocks[0].metadata == (b"$ST", b"$SA=0x60200000", b"$ED")
        assert kex.blocks[0].records == records

    def test_two_blocks_kept_in_order(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        block_a = intel_hex_record(2, 0, 0x00, b"\x11\x22")
        block_b = intel_hex_record(2, 0, 0x00, b"\x33\x44")
        text = encrypt_resource([
            (b"$SA=0x60200000", [block_a]),
            (b"$SA=0x60600000", [block_b]),
        ])
        kex = parse_resource(text)
        assert len(kex.blocks) == 2
        assert kex.blocks[0].records == block_a
        assert kex.blocks[1].records == block_b

    def test_metadata_preserves_non_ascii_bytes(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Real block-0 comment lines carry non-ASCII bytes; they must
        # survive as raw bytes, not be mangled by a lossy str decode.
        comment = b"; \xE0\xE5 ARM"
        text = encrypt_resource([
            (comment, []),
            (b"$SA=0x60200000", [intel_hex_record(0, 0, 0x01)]),
        ])
        kex = parse_resource(text)
        assert comment in kex.blocks[0].metadata


class TestRender:
    """``render`` emits a Kex model as a plaintext .KEX file: metadata
    lines verbatim, packed records as textual ``:`` Intel HEX lines,
    CRLF-terminated."""

    def test_emits_metadata_then_textual_records(
        self, intel_hex_record: IntelHexRecord,
    ) -> None:
        records = intel_hex_record(
            2, 0x0010, 0x00, b"\xAB\xCD", 0x7A
        ) + intel_hex_record(0, 0, 0x01, b"", 0xFF)
        block = KexBlock(metadata=(b"$SA=0x60200000", b"$ED"), records=records)
        out = render(Kex(blocks=(block,)))
        assert out == (
            b"$SA=0x60200000\r\n"
            b"$ED\r\n"
            b":02001000ABCD7A\r\n"
            b":00000001FF\r\n"
        )

    def test_multiple_blocks_concatenated(
        self, intel_hex_record: IntelHexRecord,
    ) -> None:
        eof = intel_hex_record(0, 0, 0x01, b"", 0xFF)
        block_a = KexBlock(metadata=(b"$SA=0x60200000",), records=eof)
        block_b = KexBlock(metadata=(b"$SA=0x60600000",), records=eof)
        out = render(Kex(blocks=(block_a, block_b)))
        assert out == (
            b"$SA=0x60200000\r\n:00000001FF\r\n"
            b"$SA=0x60600000\r\n:00000001FF\r\n"
        )

    def test_non_ascii_metadata_emitted_verbatim(
        self, intel_hex_record: IntelHexRecord,
    ) -> None:
        comment = b"; \xE0\xE5 ARM"
        block = KexBlock(
            metadata=(comment,), records=intel_hex_record(0, 0, 0x01, b"", 0xFF)
        )
        out = render(Kex(blocks=(block,)))
        assert out.startswith(comment + b"\r\n")


class TestPatchKex:
    """``patch_kex`` decrypts an encrypted resource, patches the
    FIRMWARE block's bytes, fixes the affected record checksums and the
    block $CA, then renders a patched plaintext .KEX."""

    def test_patches_firmware_byte(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        assert _firmware_image(out) == b"\x1B\x33\x1B\x1B"

    def test_recomputes_ca_over_checksum_region(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        # The patched image 1B 33 1B 1B sums (little-endian words) to
        # 0x331B + 0x1B1B = 0x4E36.
        assert b"$CA=0x4E36" in out
        assert b"$CA=0x0000" not in out

    def test_every_record_checksum_stays_valid(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        for line in out.split(b"\r\n"):
            if line.startswith(b":"):
                record = bytes.fromhex(line[1:].decode("ascii"))
                assert sum(record) % 256 == 0, f"bad checksum in {line!r}"

    def test_untouched_metadata_is_preserved(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        assert b"$SA=0x60200000" in out
        assert b"$CL=0x00000004" in out

    def test_selects_firmware_block_when_not_first(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # A non-FIRMWARE block precedes the FIRMWARE block; the patch
        # must still land in the FIRMWARE block.
        other = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        firmware = intel_hex_record(
            4, 0, 0x00, b"\x1B\x1B\x1B\x1B"
        ) + intel_hex_record(0, 0, 0x01, b"", 0xFF)
        text = encrypt_resource([
            (b"$SA=0x60600000", [other]),
            (b"$ST", []),
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x00000004", []),
            (b"$CA=0x0000", []),
            (b"$ED", [firmware]),
        ])
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        assert b"$CA=0x4E36" in out

    def test_missing_firmware_block_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        records = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        text = encrypt_resource([(b"$SA=0x60600000", [records])])
        with pytest.raises(ValueError, match="no FIRMWARE block"):
            patch_kex(text, [ByteChange(0, 0x00, 0x01)])

    def test_expect_mismatch_raises_patch_verification_error(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Image carries 0x1B at offset 1; declare expect=0x99 to force
        # a mismatch — the engine must abort with the structured
        # PatchVerificationError, not a generic ValueError, and not
        # silently apply the patch.
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        with pytest.raises(PatchVerificationError) as exc_info:
            patch_kex(text, [ByteChange(1, expect=0x99, value=0x33)])
        assert exc_info.value.offset == 1
        assert exc_info.value.expected == 0x99
        assert exc_info.value.actual == 0x1B

    def test_multi_change_mismatch_on_last_is_atomic(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # If a later change's expect mismatches, the function must raise
        # *without* returning a half-applied buffer — atomicity is a
        # documented invariant (patch.py module docstring).
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        with pytest.raises(PatchVerificationError):
            patch_kex(
                text,
                [
                    ByteChange(0, expect=0x1B, value=0x33),  # would succeed
                    ByteChange(2, expect=0x99, value=0x77),  # this fails
                ],
            )

    def test_offset_outside_data_records_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # An offset that lies past the end of the FIRMWARE image is
        # surfaced as a ValueError via intel_hex.patch_image — not
        # silently dropped (which would be the silent-failure mode
        # the v0.1.0 release set out to eliminate).
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        with pytest.raises(ValueError, match="not in any data record"):
            patch_kex(text, [ByteChange(0x9999, expect=0x00, value=0x42)])

    def test_missing_cs_metadata_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # FIRMWARE block must carry $CS=, $CL=, $CA= metadata; refuse
        # loudly if any is missing rather than silently computing $CA
        # over an unknown region.
        records = intel_hex_record(4, 0, 0x00, b"\x1B\x1B\x1B\x1B") + intel_hex_record(
            0, 0, 0x01
        )
        text = encrypt_resource([
            (b"$SA=0x60200000", []),
            (b"$CL=0x00000004", []),
            (b"$CA=0x0000", []),
            (b"$ED", [records]),
        ])
        with pytest.raises(ValueError, match=r"\$CS=.*\$CL="):
            patch_kex(text, [ByteChange(1, 0x1B, 0x33)])

    def test_missing_ca_metadata_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        records = intel_hex_record(4, 0, 0x00, b"\x1B\x1B\x1B\x1B") + intel_hex_record(
            0, 0, 0x01
        )
        text = encrypt_resource([
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x00000004", []),
            (b"$ED", [records]),
        ])
        with pytest.raises(ValueError, match=r"\$CA="):
            patch_kex(text, [ByteChange(1, 0x1B, 0x33)])

    def test_region_exceeds_image_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # $CL declares a region larger than the actual image. Python
        # slicing would silently truncate, producing a $CA computed
        # over fewer bytes than the radio's verifier will sum — brick
        # risk. Refuse loudly.
        records = intel_hex_record(
            4, 0, 0x00, b"\x1B\x1B\x1B\x1B"
        ) + intel_hex_record(0, 0, 0x01)
        text = encrypt_resource([
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x00010000", []),  # 64 KB declared, only 4 bytes present
            (b"$CA=0x0000", []),
            (b"$ED", [records]),
        ])
        with pytest.raises(ValueError, match="exceeds firmware image length"):
            patch_kex(text, [ByteChange(1, 0x1B, 0x33)])


_REAL_RESOURCE = (
    Path(__file__).resolve().parent.parent
    / "ref"
    / "TH-D75_V103_E"
    / "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
)


@pytest.mark.skipif(
    not _REAL_RESOURCE.is_file(),
    reason="real updater resource absent (ref/ is gitignored)",
)
class TestPatchKexRealResource:
    """End-to-end against the real V1.03 updater resource: the
    front-panel PF-key Screen Capture patch — flat-image offsets
    0x10444 and 0x104B8, each 0x1B -> 0x33. Skipped where ref/ is
    unavailable (e.g. CI)."""

    def test_unpatched_firmware_checksum_matches_metadata(self) -> None:
        # Known-plaintext check: the real FIRMWARE image's checksum
        # equals the $CA value the resource itself ships.
        resource = _REAL_RESOURCE.read_text(encoding="utf-8")
        firmware = parse_resource(resource).blocks[0]
        image = intel_hex.parse(firmware.records).data
        assert firmware_checksum(image) == 0x3313
        assert b"$CA=0x3313" in b"\r\n".join(firmware.metadata)

    def test_pf_capture_patch_is_surgical(self) -> None:
        # The patched .KEX must differ from the unpatched one in exactly
        # three lines: the two PF-key decoder records and $CA.
        resource = _REAL_RESOURCE.read_text(encoding="utf-8")
        unpatched = render(parse_resource(resource))
        patched = patch_kex(resource, load_patch("pf-screen-capture").changes)

        unpatched_lines = unpatched.split(b"\r\n")
        patched_lines = patched.split(b"\r\n")
        assert len(unpatched_lines) == len(patched_lines)

        changed = {
            before: after
            for before, after in zip(unpatched_lines, patched_lines, strict=True)
            if before != after
        }
        assert changed == {
            b":10044000000E01001B2908DA9A4A490051184A781F": (
                b":10044000000E0100332908DA9A4A490051184A7807"
            ),
            b":1004B000401C0006000E01001B2908DA7D4A490095": (
                b":1004B000401C0006000E0100332908DA7D4A49007D"
            ),
            b"$CA=0x3313": b"$CA=0x3343",
        }


def _encrypt_resource_lines(
    lines: list[tuple[str, bytes] | None], line_ending: str = "\n",
) -> str:
    """Encrypt ``(marker, plaintext)`` lines into a resource string.

    ``None`` produces a blank line. Lines are joined by ``line_ending``
    with a trailing one, matching the real resource's layout.
    """
    state = RollingKeyState()
    encoded: list[str] = []
    for line in lines:
        if line is None:
            encoded.append("")
        else:
            marker, plaintext = line
            encoded.append(encrypt_line(plaintext, marker, state))
    return line_ending.join(encoded) + line_ending


class TestPatchResource:
    """``patch_resource`` re-ciphers a patched FIRMWARE block back into an
    encrypted resource — byte-identical to the input except where the
    patch lands. This is the form spliced into the updater .exe."""

    def test_no_op_patch_round_trips(
        self, intel_hex_record: IntelHexRecord,
    ) -> None:
        # A resource whose $CA is already correct: patching nothing must
        # reproduce it exactly — proving blank lines, CRLF endings and
        # hex-digit markers all survive the decrypt/re-encrypt cycle.
        image = b"\x1B\x1B\x1B\x1B"
        payload = bytes([4, 0, 0, 0x00]) + image
        record = intel_hex_record(
            4, 0, 0x00, image, intel_hex.record_checksum(payload)
        ) + intel_hex_record(0, 0, 0x01, b"", 0xFF)
        resource = _encrypt_resource_lines(
            [
                ("$", b"$SA=0x60200000"),
                ("$", b"$CS=0x00000000"),
                ("$", b"$CL=0x00000004"),
                ("$", b"$CA=0x%04X" % firmware_checksum(image)),
                None,
                ("7", record),
            ],
            line_ending="\r\n",
        )
        assert patch_resource(resource, []) == resource

    def test_length_is_preserved(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        patched = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        assert len(patched) == len(resource)

    def test_patched_resource_decrypts_to_patched_firmware(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        patched = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        firmware = parse_resource(patched).blocks[0]
        assert intel_hex.parse(firmware.records).data == b"\x1B\x33\x1B\x1B"
        # $CA recomputed: 1B 33 1B 1B -> 0x331B + 0x1B1B = 0x4E36.
        assert b"$CA=0x4E36" in b"\r\n".join(firmware.metadata)

    def test_non_firmware_lines_untouched(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        other = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        firmware = intel_hex_record(
            4, 0, 0x00, b"\x1B\x1B\x1B\x1B"
        ) + intel_hex_record(0, 0, 0x01, b"", 0xFF)
        resource = encrypt_resource([
            (b"$SA=0x60600000", [other]),
            (b"$ST", []),
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x00000004", []),
            (b"$CA=0x0000", []),
            (b"$ED", [firmware]),
        ])
        patched = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        # The non-FIRMWARE block's two lines must come back byte-identical.
        assert patched.split("\n")[:2] == resource.split("\n")[:2]

    def test_missing_firmware_block_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        records = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        resource = encrypt_resource([(b"$SA=0x60600000", [records])])
        with pytest.raises(ValueError, match="no FIRMWARE block"):
            patch_resource(resource, [ByteChange(0, 0x00, 0x01)])

    def test_expect_mismatch_raises_patch_verification_error(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Same atomicity / safety guarantee as patch_kex — and applies
        # via the same intel_hex.patch_image path.
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1B\x1B\x1B\x1B"
        )
        with pytest.raises(PatchVerificationError) as exc_info:
            patch_resource(resource, [ByteChange(2, expect=0x77, value=0x33)])
        assert exc_info.value.expected == 0x77
        assert exc_info.value.actual == 0x1B

    def test_region_exceeds_image_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        records = intel_hex_record(
            4, 0, 0x00, b"\x1B\x1B\x1B\x1B"
        ) + intel_hex_record(0, 0, 0x01)
        resource = encrypt_resource([
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x00010000", []),  # 64 KB declared, only 4 bytes present
            (b"$CA=0x0000", []),
            (b"$ED", [records]),
        ])
        with pytest.raises(ValueError, match="exceeds firmware image length"):
            patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])


_REAL_EXE = (
    Path(__file__).resolve().parent.parent
    / "ref"
    / "TH-D75_V103_E"
    / "TH-D75_V103_e.exe"
)


@pytest.mark.skipif(
    not _REAL_EXE.is_file(),
    reason="real updater .exe absent (ref/ is gitignored)",
)
class TestRepackRealExe:
    """End-to-end against the real V1.03 updater .exe: the repack splices
    a patched firmware resource into the .exe, byte-surgically. Skipped
    where ref/ is unavailable (e.g. CI)."""

    def test_repack_is_surgical_and_correct(self) -> None:
        exe = _REAL_EXE.read_bytes()
        original_resource = extract(exe)
        patched_resource = patch_resource(
            original_resource, load_patch("pf-screen-capture").changes,
        )
        patched_exe = replace(exe, patched_resource)

        # In-place splice: identical total size, and the resource the
        # patched .exe carries is exactly what was spliced in.
        assert len(patched_exe) == len(exe)
        assert extract(patched_exe) == patched_resource

        # Surgical: the 42 MB resource changes in exactly three lines —
        # the two front-panel PF-key decoder records and $CA.
        original_lines = original_resource.split("\n")
        patched_lines = patched_resource.split("\n")
        assert len(original_lines) == len(patched_lines)
        changed = sum(
            1
            for before, after in zip(original_lines, patched_lines, strict=True)
            if before != after
        )
        assert changed == 3

        # The patched .exe's embedded firmware decodes correctly.
        firmware = parse_resource(patched_resource).blocks[0]
        image = intel_hex.parse(firmware.records).data
        assert image[0x10444] == 0x33
        assert image[0x104B8] == 0x33
        assert b"$CA=0x3343" in b"\r\n".join(firmware.metadata)
