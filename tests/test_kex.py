"""Tests for .KEX firmware-file patching."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from thd75_fw import intel_hex
from thd75_fw.file_cipher import RollingKeyState, encrypt_line
from thd75_fw.kex import (
    Kex,
    KexBlock,
    firmware_checksum,
    is_d75_v103_nonstandard_overlay_stream,
    parse_encrypted_resource,
    parse_kex_bytes,
    parse_resource,
    patch_kex,
    patch_kex_stack,
    patch_resource,
    patch_resource_stack,
    render,
    section_image,
)
from thd75_fw.patch import (
    ByteChange,
    ByteContext,
    Patch,
    PatchIntegrityError,
    PatchVerificationError,
    SectionHashes,
    load_patch,
)
from thd75_fw.resource import extract, replace

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.conftest import IntelHexRecordBuilder

    EncryptResource = Callable[[list[tuple[bytes, list[bytes]]]], str]


def _firmware_image(kex_file: bytes) -> bytes:
    """Reconstruct the flat firmware image from a single-block .KEX file."""
    packed = b"".join(
        bytes.fromhex(line[1:].decode("ascii"))
        for line in kex_file.split(b"\r\n")
        if line.startswith(b":")
    )
    return intel_hex.parse(packed).data


def test_v103_nonstandard_overlay_exception_requires_exact_identity() -> None:
    checkbytes = bytes.fromhex(
        "02 00 00 04 00 00 7A 02 00 00 00 B0 1D 31 00 00 00 01 FF"
    )
    assert is_d75_v103_nonstandard_overlay_stream(
        block_index=5,
        physical_address=0x6020_0062,
        records=checkbytes,
    )
    assert not is_d75_v103_nonstandard_overlay_stream(
        block_index=4,
        physical_address=0x6020_0062,
        records=checkbytes,
    )
    assert not is_d75_v103_nonstandard_overlay_stream(
        block_index=5,
        physical_address=0x6020_0040,
        records=checkbytes,
    )
    mutated = bytearray(checkbytes)
    mutated[11] ^= 0x01
    assert not is_d75_v103_nonstandard_overlay_stream(
        block_index=5,
        physical_address=0x6020_0062,
        records=bytes(mutated),
    )


def _firmware_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecordBuilder,
    image: bytes,
) -> str:
    """Build an encrypted resource holding a single FIRMWARE block."""
    payload = bytes([len(image), 0x00, 0x00, 0x00]) + image
    data_record = intel_hex_record(
        len(image), 0, 0x00, image, intel_hex.record_checksum(payload)
    )
    eof = intel_hex_record(0, 0, 0x01, b"", 0xFF)
    return encrypt_resource(
        [
            (b"$ST", []),
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x%08X" % len(image), []),
            (b"$CA=0x0000", []),
            (b"$ED", [data_record + eof]),
        ]
    )


def _strict_test_patch(
    *,
    source: bytes,
    result: bytes,
    result_kex_sha256: str | None = None,
    contexts: tuple[ByteContext, ...] = (),
) -> Patch:
    return Patch(
        name="strict-test",
        description="strict test patch",
        target_firmware="synthetic",
        changes=(ByteChange(1, 0x1B, 0x33),),
        source_sha256=hashlib.sha256(source).hexdigest(),
        result_sha256=hashlib.sha256(result).hexdigest(),
        result_kex_sha256=result_kex_sha256,
        change_count=1,
        contexts=contexts,
    )


class TestFirmwareChecksum:
    """``firmware_checksum`` is the updater's $CA/$CB algorithm.

    It is a sum of 16-bit little-endian words taken modulo 0x10000.
    """

    def test_empty(self) -> None:
        assert firmware_checksum(b"") == 0x0000

    def test_single_little_endian_word(self) -> None:
        # Bytes 0x34, 0x12 form the little-endian word 0x1234.
        assert firmware_checksum(b"\x34\x12") == 0x1234

    def test_words_sum(self) -> None:
        assert firmware_checksum(b"\x34\x12\x01\x00") == 0x1234 + 0x0001

    def test_wraps_modulo_0x10000(self) -> None:
        # 0xFFFF + 0x0002 = 0x10001, which wraps to 0x0001.
        assert firmware_checksum(b"\xff\xff\x02\x00") == 0x0001

    def test_odd_trailing_byte_is_low_byte_of_final_word(self) -> None:
        # An odd-length region pads with a zero high byte.
        assert firmware_checksum(b"\x34\x12\x07") == 0x1234 + 0x0007

    def test_pf_capture_patch_delta(self) -> None:
        # The PF-key patch raises two even-offset bytes by 0x18 each;
        # each is the low byte of a little-endian word, so $CA rises 0x30.
        before = b"\x1b\x00\x1b\x00"
        after = b"\x33\x00\x33\x00"
        assert firmware_checksum(after) == firmware_checksum(before) + 0x30


class TestParseResource:
    """``parse_resource`` decrypts an encrypted updater resource into a Kex model.

    The model holds one KexBlock per firmware section, carrying that section's
    raw metadata lines and its packed Intel HEX records.
    """

    def test_single_block_metadata_and_records(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(4, 0, 0x00, b"\xaa\xbb\xcc\xdd") + intel_hex_record(
            0, 0, 0x01
        )
        text = encrypt_resource(
            [
                (b"$ST", []),
                (b"$SA=0x60200000", []),
                (b"$ED", [records]),
            ]
        )
        kex = parse_resource(text)
        assert len(kex.blocks) == 1
        assert kex.blocks[0].metadata == (b"$ST", b"$SA=0x60200000", b"$ED")
        assert kex.blocks[0].records == records

    def test_two_blocks_kept_in_order(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        block_a = intel_hex_record(2, 0, 0x00, b"\x11\x22")
        block_b = intel_hex_record(2, 0, 0x00, b"\x33\x44")
        text = encrypt_resource(
            [
                (b"$SA=0x60200000", [block_a]),
                (b"$SA=0x60600000", [block_b]),
            ]
        )
        kex = parse_resource(text)
        assert len(kex.blocks) == 2
        assert kex.blocks[0].records == block_a
        assert kex.blocks[1].records == block_b

    def test_metadata_preserves_non_ascii_bytes(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Real block-0 comment lines carry non-ASCII bytes; they must
        # survive as raw bytes, not be mangled by a lossy str decode.
        comment = b"; \xe0\xe5 ARM"
        text = encrypt_resource(
            [
                (comment, []),
                (b"$SA=0x60200000", [intel_hex_record(0, 0, 0x01)]),
            ]
        )
        kex = parse_resource(text)
        assert comment in kex.blocks[0].metadata


class TestRender:
    """``render`` emits a Kex model as a plaintext .KEX file.

    Metadata lines come out verbatim and packed records as textual ``:``
    Intel HEX lines, every line CRLF-terminated.
    """

    def test_emits_metadata_then_textual_records(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(
            2, 0x0010, 0x00, b"\xab\xcd", 0x7A
        ) + intel_hex_record(0, 0, 0x01, b"", 0xFF)
        block = KexBlock(metadata=(b"$SA=0x60200000", b"$ED"), records=records)
        out = render(Kex(blocks=(block,)))
        assert out == (b"$SA=0x60200000\r\n$ED\r\n:02001000ABCD7A\r\n:00000001FF\r\n")

    def test_multiple_blocks_concatenated(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        eof = intel_hex_record(0, 0, 0x01, b"", 0xFF)
        block_a = KexBlock(metadata=(b"$SA=0x60200000",), records=eof)
        block_b = KexBlock(metadata=(b"$SA=0x60600000",), records=eof)
        out = render(Kex(blocks=(block_a, block_b)))
        assert out == (
            b"$SA=0x60200000\r\n:00000001FF\r\n$SA=0x60600000\r\n:00000001FF\r\n"
        )

    def test_non_ascii_metadata_emitted_verbatim(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        comment = b"; \xe0\xe5 ARM"
        block = KexBlock(
            metadata=(comment,), records=intel_hex_record(0, 0, 0x01, b"", 0xFF)
        )
        out = render(Kex(blocks=(block,)))
        assert out.startswith(comment + b"\r\n")


class TestParsePlaintextKex:
    """External KEX input is canonical plaintext bytes, never ciphertext."""

    @staticmethod
    def _artifact(records: bytes, *extra_metadata: bytes) -> bytes:
        metadata = (b"$ST", b"$SA=0x60200000", b"$ED", *extra_metadata)
        return render(Kex(blocks=(KexBlock(metadata=metadata, records=records),)))

    def test_round_trip_preserves_non_utf8_metadata(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(1, 0, 0x00, b"\xaa") + intel_hex_record(0, 0, 0x01)
        artifact = self._artifact(records, b"; opaque \xbf byte")

        parsed = parse_kex_bytes(artifact)

        assert parsed.blocks[0].metadata[-1] == b"; opaque \xbf byte"
        assert render(parsed) == artifact

    def test_encrypted_resource_is_identified_and_rejected(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        encrypted = encrypt_resource(
            [
                (b"$ST", []),
                (b"$SA=0x60200000", []),
                (b"$ED", [intel_hex_record(0, 0, 0x01)]),
            ]
        ).encode("ascii")

        with pytest.raises(ValueError, match="encrypted updater-resource"):
            _ = parse_kex_bytes(encrypted)

    def test_mixed_plaintext_and_ciphertext_is_rejected_as_structural_ambiguity(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(intel_hex_record(0, 0, 0x01))
        mixed = artifact + b"$930D67E4E627BE\r\n"

        with pytest.raises(ValueError, match="mixed storage formats"):
            _ = parse_kex_bytes(mixed)

    def test_ciphertext_data_line_before_plaintext_block_is_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(intel_hex_record(0, 0, 0x01))

        with pytest.raises(ValueError, match="encrypted-resource line"):
            _ = parse_kex_bytes(b"A930D67E4E627BE\r\n" + artifact)

    def test_plaintext_is_not_accepted_by_encrypted_resource_parser(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(intel_hex_record(0, 0, 0x01))

        with pytest.raises(ValueError, match="Non-hex"):
            _ = parse_encrypted_resource(artifact.decode("ascii"))

    @pytest.mark.parametrize(
        "mutation",
        ["lf-only", "missing-final", "bare-cr"],
    )
    def test_noncanonical_line_endings_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
        mutation: str,
    ) -> None:
        artifact = self._artifact(intel_hex_record(0, 0, 0x01))
        if mutation == "lf-only":
            malformed = artifact.replace(b"\r\n", b"\n")
        elif mutation == "missing-final":
            malformed = artifact.removesuffix(b"\r\n")
        else:
            malformed = artifact.replace(b"\r\n", b"\r\r\n", 1)

        with pytest.raises(ValueError, match=r"CRLF|line ending"):
            _ = parse_kex_bytes(malformed)

    def test_bad_record_checksum_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(1, 0, 0x00, b"\xaa", checksum=0x00)
        records += intel_hex_record(0, 0, 0x01)

        with pytest.raises(ValueError, match="bad checksum"):
            _ = parse_kex_bytes(self._artifact(records))

    def test_declared_record_length_mismatch_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(intel_hex_record(0, 0, 0x01))
        malformed = artifact.replace(b":00000001FF", b":01000001FF")

        with pytest.raises(ValueError, match="declares 1 data bytes"):
            _ = parse_kex_bytes(malformed)

    def test_missing_eof_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(intel_hex_record(1, 0, 0x00, b"\xaa"))

        with pytest.raises(ValueError, match="no EOF"):
            _ = parse_kex_bytes(artifact)

    def test_record_after_eof_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(intel_hex_record(0, 0, 0x01))
        extra = b":" + intel_hex_record(1, 0, 0x00, b"\xaa").hex().upper().encode()
        malformed = artifact.removesuffix(b"\r\n") + b"\r\n" + extra + b"\r\n"

        with pytest.raises(ValueError, match="record after EOF"):
            _ = parse_kex_bytes(malformed)

    def test_duplicate_segment_tag_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        artifact = self._artifact(
            intel_hex_record(0, 0, 0x01),
            b"$SA=0x60200000",
        )

        with pytest.raises(ValueError, match=r"duplicate.*\$SA"):
            _ = parse_kex_bytes(artifact)

    def test_overlapping_data_records_rejected(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(2, 0, 0x00, b"\x11\x22")
        records += intel_hex_record(2, 1, 0x00, b"\x33\x44")
        records += intel_hex_record(0, 0, 0x01)

        with pytest.raises(ValueError, match="overlapping"):
            _ = parse_kex_bytes(self._artifact(records))


class TestPatchKex:
    """``patch_kex`` renders a patched plaintext .KEX from an encrypted resource.

    It decrypts the resource, patches the FIRMWARE block's bytes, fixes the
    affected record checksums and the block $CA, then renders the result.
    """

    def test_patches_firmware_byte(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        assert _firmware_image(out) == b"\x1b\x33\x1b\x1b"

    def test_changes_keyword_remains_backward_compatible(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        out = patch_kex(text, changes=[ByteChange(1, 0x1B, 0x33)])
        assert _firmware_image(out) == b"\x1b\x33\x1b\x1b"

    def test_patch_object_enforces_source_context_raw_and_kex_hashes(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        source = b"\x1b\x1b\x1b\x1b"
        result = b"\x1b\x33\x1b\x1b"
        text = _firmware_resource(encrypt_resource, intel_hex_record, source)

        # First render establishes the deterministic synthetic KEX digest;
        # the second call passes the complete Patch policy and must verify it.
        baseline = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        strict_patch = _strict_test_patch(
            source=source,
            result=result,
            result_kex_sha256=hashlib.sha256(baseline).hexdigest(),
            contexts=(ByteContext(0, source),),
        )
        assert patch_kex(text, strict_patch) == baseline

    def test_patch_object_rejects_wrong_source_hash_before_result(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        source = b"\x1b\x1b\x1b\x1b"
        text = _firmware_resource(encrypt_resource, intel_hex_record, source)
        strict_patch = _strict_test_patch(
            source=source,
            result=b"\x1b\x33\x1b\x1b",
        )
        strict_patch = Patch(
            name=strict_patch.name,
            description=strict_patch.description,
            target_firmware=strict_patch.target_firmware,
            changes=strict_patch.changes,
            source_sha256="00" * 32,
            result_sha256=strict_patch.result_sha256,
            change_count=1,
        )
        with pytest.raises(PatchIntegrityError, match="source firmware SHA-256"):
            _ = patch_kex(text, strict_patch)

    def test_patch_object_rejects_wrong_full_context(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        source = b"\x1b\x1b\x1b\x1b"
        text = _firmware_resource(encrypt_resource, intel_hex_record, source)
        strict_patch = Patch(
            name="bad-context",
            description="bad context",
            target_firmware="synthetic",
            changes=(ByteChange(1, 0x1B, 0x33),),
            contexts=(ByteContext(0, b"\x1b\x1b\x99\x1b"),),
        )
        with pytest.raises(PatchIntegrityError, match="source context mismatch"):
            _ = patch_kex(text, strict_patch)

    def test_patch_object_rejects_wrong_raw_result_hash(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        source = b"\x1b\x1b\x1b\x1b"
        text = _firmware_resource(encrypt_resource, intel_hex_record, source)
        strict_patch = Patch(
            name="bad-result",
            description="bad result",
            target_firmware="synthetic",
            changes=(ByteChange(1, 0x1B, 0x33),),
            source_sha256=hashlib.sha256(source).hexdigest(),
            result_sha256="00" * 32,
        )
        with pytest.raises(PatchIntegrityError, match="patched firmware SHA-256"):
            _ = patch_kex(text, strict_patch)

    def test_patch_object_rejects_wrong_kex_result_hash(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        source = b"\x1b\x1b\x1b\x1b"
        result = b"\x1b\x33\x1b\x1b"
        text = _firmware_resource(encrypt_resource, intel_hex_record, source)
        strict_patch = _strict_test_patch(
            source=source,
            result=result,
            result_kex_sha256="00" * 32,
        )
        with pytest.raises(PatchIntegrityError, match="patched KEX SHA-256"):
            _ = patch_kex(text, strict_patch)

    def test_recomputes_ca_over_checksum_region(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        # The patched image 1B 33 1B 1B sums (little-endian words) to
        # 0x331B + 0x1B1B = 0x4E36.
        assert b"$CA=0x4E36" in out
        assert b"$CA=0x0000" not in out

    def test_every_record_checksum_stays_valid(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        for line in out.split(b"\r\n"):
            if line.startswith(b":"):
                record = bytes.fromhex(line[1:].decode("ascii"))
                assert sum(record) % 256 == 0, f"bad checksum in {line!r}"

    def test_untouched_metadata_is_preserved(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        assert b"$SA=0x60200000" in out
        assert b"$CL=0x00000004" in out

    def test_selects_firmware_block_when_not_first(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # A non-FIRMWARE block precedes the FIRMWARE block; the patch
        # must still land in the FIRMWARE block.
        other = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        firmware = intel_hex_record(4, 0, 0x00, b"\x1b\x1b\x1b\x1b") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        text = encrypt_resource(
            [
                (b"$SA=0x60600000", [other]),
                (b"$ST", []),
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x00000004", []),
                (b"$CA=0x0000", []),
                (b"$ED", [firmware]),
            ]
        )
        out = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])
        assert b"$CA=0x4E36" in out

    def test_missing_firmware_block_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        text = encrypt_resource([(b"$SA=0x60600000", [records])])
        with pytest.raises(ValueError, match="no FIRMWARE block"):
            _ = patch_kex(text, [ByteChange(0, 0x00, 0x01)])

    def test_expect_mismatch_raises_patch_verification_error(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Image carries 0x1B at offset 1; declare expect=0x99 to force
        # a mismatch — the engine must abort with the structured
        # PatchVerificationError, not a generic ValueError, and not
        # silently apply the patch.
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        with pytest.raises(PatchVerificationError) as exc_info:
            _ = patch_kex(text, [ByteChange(1, expect=0x99, value=0x33)])
        assert exc_info.value.offset == 1
        assert exc_info.value.expected == 0x99
        assert exc_info.value.actual == 0x1B

    def test_multi_change_mismatch_on_last_is_atomic(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # If a later change's expect mismatches, the function must raise
        # *without* returning a half-applied buffer — atomicity is a
        # documented invariant (patch.py module docstring).
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        with pytest.raises(PatchVerificationError):
            _ = patch_kex(
                text,
                [
                    ByteChange(0, expect=0x1B, value=0x33),  # would succeed
                    ByteChange(2, expect=0x99, value=0x77),  # this fails
                ],
            )

    def test_offset_outside_data_records_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # An offset that lies past the end of the FIRMWARE image is
        # surfaced as a ValueError via intel_hex.patch_image — not
        # silently dropped (which would be the silent-failure mode
        # the v0.1.0 release set out to eliminate).
        text = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        with pytest.raises(ValueError, match="not in any data record"):
            _ = patch_kex(text, [ByteChange(0x9999, expect=0x00, value=0x42)])

    def test_missing_cs_metadata_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # FIRMWARE block must carry $CS=, $CL=, $CA= metadata; refuse
        # loudly if any is missing rather than silently computing $CA
        # over an unknown region.
        records = intel_hex_record(4, 0, 0x00, b"\x1b\x1b\x1b\x1b") + intel_hex_record(
            0, 0, 0x01
        )
        text = encrypt_resource(
            [
                (b"$SA=0x60200000", []),
                (b"$CL=0x00000004", []),
                (b"$CA=0x0000", []),
                (b"$ED", [records]),
            ]
        )
        with pytest.raises(ValueError, match=r"\$CS=.*\$CL="):
            _ = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])

    def test_missing_ca_metadata_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(4, 0, 0x00, b"\x1b\x1b\x1b\x1b") + intel_hex_record(
            0, 0, 0x01
        )
        text = encrypt_resource(
            [
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x00000004", []),
                (b"$ED", [records]),
            ]
        )
        with pytest.raises(ValueError, match=r"\$CA="):
            _ = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])

    def test_region_exceeds_image_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # $CL declares a region larger than the actual image. Python
        # slicing would silently truncate, producing a $CA computed
        # over fewer bytes than the radio's verifier will sum — brick
        # risk. Refuse loudly.
        records = intel_hex_record(4, 0, 0x00, b"\x1b\x1b\x1b\x1b") + intel_hex_record(
            0, 0, 0x01
        )
        text = encrypt_resource(
            [
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x00010000", []),  # 64 KB declared, only 4 bytes present
                (b"$CA=0x0000", []),
                (b"$ED", [records]),
            ]
        )
        with pytest.raises(ValueError, match="exceeds firmware image length"):
            _ = patch_kex(text, [ByteChange(1, 0x1B, 0x33)])


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
    """End-to-end against the real V1.03 updater resource.

    Applies the front-panel PF-key Screen Capture patch — flat-image offsets
    0x10444 and 0x104B8, each 0x1B -> 0x33. Skipped where ref/ is
    unavailable (e.g. CI).
    """

    def test_unpatched_firmware_checksum_matches_metadata(self) -> None:
        # Known-plaintext check: the real FIRMWARE image's checksum
        # equals the $CA value the resource itself ships.
        resource = _REAL_RESOURCE.read_text(encoding="utf-8")
        firmware = parse_resource(resource).blocks[0]
        image = intel_hex.parse(firmware.records).data
        assert firmware_checksum(image) == 0x3313
        assert b"$CA=0x3313" in b"\r\n".join(firmware.metadata)

    def test_stock_plaintext_bytes_parse_exactly(self) -> None:
        resource = _REAL_RESOURCE.read_text(encoding="utf-8")
        plaintext = render(parse_encrypted_resource(resource))

        assert b"\xbf" in plaintext
        assert hashlib.sha256(plaintext).hexdigest() == (
            "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
        )
        parsed = parse_kex_bytes(plaintext)
        assert len(parsed.blocks) == 7
        assert render(parsed) == plaintext
        firmware = next(
            block for block in parsed.blocks if b"$SA=0x60200000" in block.metadata
        )
        assert hashlib.sha256(intel_hex.parse(firmware.records).data).hexdigest() == (
            "193963ca4b7a38392815686893858eec20292b629fe999f10b93a22a3a8e4001"
        )

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

    def test_service_9r_nor_read_exact_artifacts(self) -> None:
        resource = _REAL_RESOURCE.read_text(encoding="utf-8")
        selected_patch = load_patch("service-9r-nor-read")
        unpatched = render(parse_resource(resource))
        patched = patch_kex(resource, selected_patch)

        source_image = _firmware_image(unpatched)
        result_image = _firmware_image(patched)
        assert hashlib.sha256(source_image).hexdigest() == selected_patch.source_sha256
        assert hashlib.sha256(result_image).hexdigest() == selected_patch.result_sha256
        assert hashlib.sha256(patched).hexdigest() == selected_patch.result_kex_sha256
        assert render(parse_kex_bytes(patched)) == patched

        differing_offsets = [
            offset
            for offset, (before, after) in enumerate(
                zip(source_image, result_image, strict=True)
            )
            if before != after
        ]
        assert differing_offsets == [change.offset for change in selected_patch.changes]
        assert len(differing_offsets) == 19

        changed_lines = {
            before: after
            for before, after in zip(
                unpatched.split(b"\r\n"),
                patched.split(b"\r\n"),
                strict=True,
            )
            if before != after
        }
        assert changed_lines == {
            b"$CA=0x3313": b"$CA=0x0895",
            b":10F85000C91C01A8FEF770FB002804D0A026F60200": (
                b":10F85000C91C01A8FEF770FB002804D08026B6035F"
            ),
            b":10F8A00002AA0904090C0198A1F7B2FE012805D1AA": (
                b":10F8A000602636060199891902A8009AA1F78DFDF4"
            ),
        }


def _encrypt_resource_lines(
    lines: list[tuple[str, bytes] | None],
    line_ending: str = "\n",
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
    """``patch_resource`` re-ciphers a patched FIRMWARE block into the resource.

    The output is an encrypted resource byte-identical to the input except
    where the patch lands. This is the form spliced into the updater .exe.
    """

    def test_no_op_patch_round_trips(
        self,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # A resource whose $CA is already correct: patching nothing must
        # reproduce it exactly — proving blank lines, CRLF endings and
        # hex-digit markers all survive the decrypt/re-encrypt cycle.
        image = b"\x1b\x1b\x1b\x1b"
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
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        patched = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        assert len(patched) == len(resource)

    def test_changes_keyword_remains_backward_compatible(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        patched = patch_resource(
            resource,
            changes=[ByteChange(1, 0x1B, 0x33)],
        )
        assert _firmware_image(render(parse_resource(patched))) == (b"\x1b\x33\x1b\x1b")

    def test_patch_object_enforces_integrity_before_returning_resource(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        source = b"\x1b\x1b\x1b\x1b"
        result = b"\x1b\x33\x1b\x1b"
        resource = _firmware_resource(encrypt_resource, intel_hex_record, source)
        baseline = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        baseline_kex = render(parse_resource(baseline))
        strict_patch = _strict_test_patch(
            source=source,
            result=result,
            result_kex_sha256=hashlib.sha256(baseline_kex).hexdigest(),
            contexts=(ByteContext(0, source),),
        )
        assert patch_resource(resource, strict_patch) == baseline

    def test_patched_resource_decrypts_to_patched_firmware(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        patched = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        firmware = parse_resource(patched).blocks[0]
        assert intel_hex.parse(firmware.records).data == b"\x1b\x33\x1b\x1b"
        # $CA recomputed: 1B 33 1B 1B -> 0x331B + 0x1B1B = 0x4E36.
        assert b"$CA=0x4E36" in b"\r\n".join(firmware.metadata)

    def test_non_firmware_lines_untouched(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        other = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        firmware = intel_hex_record(4, 0, 0x00, b"\x1b\x1b\x1b\x1b") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        resource = encrypt_resource(
            [
                (b"$SA=0x60600000", [other]),
                (b"$ST", []),
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x00000004", []),
                (b"$CA=0x0000", []),
                (b"$ED", [firmware]),
            ]
        )
        patched = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])
        # The non-FIRMWARE block's two lines must come back byte-identical.
        assert patched.split("\n")[:2] == resource.split("\n")[:2]

    def test_missing_firmware_block_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(2, 0, 0x00, b"\x00\x00") + intel_hex_record(
            0, 0, 0x01, b"", 0xFF
        )
        resource = encrypt_resource([(b"$SA=0x60600000", [records])])
        with pytest.raises(ValueError, match="no FIRMWARE block"):
            _ = patch_resource(resource, [ByteChange(0, 0x00, 0x01)])

    def test_expect_mismatch_raises_patch_verification_error(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Same atomicity / safety guarantee as patch_kex — and applies
        # via the same intel_hex.patch_image path.
        resource = _firmware_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b"
        )
        with pytest.raises(PatchVerificationError) as exc_info:
            _ = patch_resource(resource, [ByteChange(2, expect=0x77, value=0x33)])
        assert exc_info.value.expected == 0x77
        assert exc_info.value.actual == 0x1B

    def test_region_exceeds_image_raises(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(4, 0, 0x00, b"\x1b\x1b\x1b\x1b") + intel_hex_record(
            0, 0, 0x01
        )
        resource = encrypt_resource(
            [
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x00010000", []),  # 64 KB declared, only 4 bytes present
                (b"$CA=0x0000", []),
                (b"$ED", [records]),
            ]
        )
        with pytest.raises(ValueError, match="exceeds firmware image length"):
            _ = patch_resource(resource, [ByteChange(1, 0x1B, 0x33)])


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
    """End-to-end against the real V1.03 updater .exe.

    The repack splices a patched firmware resource into the .exe,
    byte-surgically. Skipped where ref/ is unavailable (e.g. CI).
    """

    def test_repack_is_surgical_and_correct(self) -> None:
        exe = _REAL_EXE.read_bytes()
        original_resource = extract(exe)
        patched_resource = patch_resource(
            original_resource,
            load_patch("pf-screen-capture").changes,
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


def _two_block_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecordBuilder,
    firmware: bytes,
    image_data: bytes,
) -> str:
    """Encrypted resource with a FIRMWARE block and an IMAGE_DATA block."""

    def block(start_address: int, image: bytes) -> list[tuple[bytes, list[bytes]]]:
        payload = bytes([len(image), 0x00, 0x00, 0x00]) + image
        data_record = intel_hex_record(
            len(image), 0, 0x00, image, intel_hex.record_checksum(payload)
        )
        eof = intel_hex_record(0, 0, 0x01, b"", 0xFF)
        return [
            (b"$ST", []),
            (b"$SA=0x%08X" % start_address, []),
            (b"$CS=0x00000000", []),
            (b"$VS=0x00000000", []),
            (b"$VL=0x000A", []),
            (b"$CL=0x%08X" % len(image), []),
            (b"$CA=0x0000", []),
            (b'$VA="1.00.02.00"', []),
            (b"$ED", [data_record + eof]),
        ]

    return encrypt_resource(
        block(0x6020_0000, firmware) + block(0x6060_0000, image_data)
    )


def _block_ca(rendered: bytes, section: str) -> int:
    physical = {
        "FIRMWARE": b"$SA=0x60200000",
        "IMAGE_DATA": b"$SA=0x60600000",
    }[section]
    for block in parse_kex_bytes(rendered).blocks:
        if physical in block.metadata:
            for line in block.metadata:
                if line.startswith(b"$CA="):
                    return int(line[4:], 16)
    msg = f"no {section} block"
    raise AssertionError(msg)


class TestPatchKexSections:
    def test_image_data_change_patches_only_that_block(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        out = patch_kex(text, [ByteChange(2, 0xFF, 0x60, section="IMAGE_DATA")])
        model = parse_kex_bytes(out)
        assert section_image(model, "FIRMWARE") == b"\x1b\x1b\x1b\x1b"
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\x60\xff"
        assert _block_ca(out, "IMAGE_DATA") == firmware_checksum(b"\x00\x00\x60\xff")
        assert _block_ca(out, "FIRMWARE") == 0  # untouched placeholder

    def test_changes_in_two_sections_apply_together(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        out = patch_kex(
            text,
            [
                ByteChange(1, 0x1B, 0x33),
                ByteChange(3, 0xFF, 0x60, section="IMAGE_DATA"),
            ],
        )
        model = parse_kex_bytes(out)
        assert section_image(model, "FIRMWARE") == b"\x1b\x33\x1b\x1b"
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\xff\x60"

    def test_missing_block_for_section_is_an_error(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(encrypt_resource, intel_hex_record, b"\x1b\x1b")
        with pytest.raises(ValueError, match="no IMAGE_DATA block"):
            _ = patch_kex(text, [ByteChange(0, 0x1B, 0x33, section="IMAGE_DATA")])

    def test_section_pins_and_contexts_are_verified_without_changes(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        good = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(ByteChange(1, 0x1B, 0x33),),
            contexts=(ByteContext(0, b"\x00\x00", section="IMAGE_DATA"),),
            section_hashes=(
                SectionHashes(
                    "IMAGE_DATA",
                    source_sha256=hashlib.sha256(b"\x00\x00\xff\xff").hexdigest(),
                    result_sha256=hashlib.sha256(b"\x00\x00\xff\xff").hexdigest(),
                ),
            ),
        )
        _ = patch_kex(text, good)
        bad = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(ByteChange(1, 0x1B, 0x33),),
            contexts=(ByteContext(0, b"\x11\x11", section="IMAGE_DATA"),),
        )
        with pytest.raises(PatchIntegrityError, match="source context mismatch"):
            _ = patch_kex(text, bad)

    def test_section_image_unknown_section(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(encrypt_resource, intel_hex_record, b"\x1b\x1b")
        model = parse_kex_bytes(patch_kex(text, [ByteChange(0, 0x1B, 0x33)]))
        with pytest.raises(ValueError, match="unknown section 'BOGUS'"):
            _ = section_image(model, "BOGUS")


def _stage(name: str, changes: tuple[ByteChange, ...]) -> Patch:
    return Patch(name=name, description=name, target_firmware=None, changes=changes)


class TestPatchStacking:
    def test_stages_apply_in_order(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        first = _stage("first", (ByteChange(1, 0x1B, 0x33),))
        second = _stage(
            "second",
            (
                ByteChange(1, 0x33, 0x44),
                ByteChange(2, 0xFF, 0x60, section="IMAGE_DATA"),
            ),
        )
        out = patch_kex_stack(text, [first, second])
        model = parse_kex_bytes(out)
        assert section_image(model, "FIRMWARE") == b"\x1b\x44\x1b\x1b"
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\x60\xff"
        with pytest.raises(PatchVerificationError):
            _ = patch_kex_stack(text, [second, first])

    def test_result_pins_are_checked_per_stage(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        first = _stage("first", (ByteChange(1, 0x1B, 0x33),))
        first_alone = patch_kex(text, first)
        pinned_first = Patch(
            name="first",
            description="first",
            target_firmware=None,
            changes=(ByteChange(1, 0x1B, 0x33),),
            result_sha256=hashlib.sha256(b"\x1b\x33\x1b\x1b").hexdigest(),
            result_kex_sha256=hashlib.sha256(first_alone).hexdigest(),
        )
        second = _stage("second", (ByteChange(1, 0x33, 0x44),))
        # The first stage's whole-KEX pin holds on its own output even though
        # the stack keeps going.
        _ = patch_kex_stack(text, [pinned_first, second])
        wrong = Patch(
            name="second",
            description="second",
            target_firmware=None,
            changes=(ByteChange(1, 0x33, 0x44),),
            result_sha256=hashlib.sha256(b"\x1b\x33\x1b\x1b").hexdigest(),
        )
        with pytest.raises(PatchIntegrityError, match="patched firmware SHA-256"):
            _ = patch_kex_stack(text, [pinned_first, wrong])

    def test_empty_stack_rejected(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _firmware_resource(encrypt_resource, intel_hex_record, b"\x1b\x1b")
        with pytest.raises(ValueError, match="at least one patch"):
            _ = patch_kex_stack(text, [])


class TestPatchResourceSections:
    def test_image_data_block_patched_in_place(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        patched = patch_resource(
            text, [ByteChange(2, 0xFF, 0x60, section="IMAGE_DATA")]
        )
        assert len(patched) == len(text)
        model = parse_resource(patched)
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\x60\xff"
        assert section_image(model, "FIRMWARE") == b"\x1b\x1b\x1b\x1b"
        assert _block_ca(render(model), "IMAGE_DATA") == firmware_checksum(
            b"\x00\x00\x60\xff"
        )

    def test_resource_stack_matches_kex_stack(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        first = _stage("first", (ByteChange(1, 0x1B, 0x33),))
        second = _stage("second", (ByteChange(3, 0xFF, 0x60, section="IMAGE_DATA"),))
        stacked_resource = patch_resource_stack(text, [first, second])
        assert render(parse_resource(stacked_resource)) == patch_kex_stack(
            text, [first, second]
        )

    def test_resource_stage_pin_checked_on_its_own_output(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        first = _stage("first", (ByteChange(1, 0x1B, 0x33),))
        first_alone = patch_resource(text, first)
        pinned_first = Patch(
            name="first",
            description="first",
            target_firmware=None,
            changes=(ByteChange(1, 0x1B, 0x33),),
            result_encrypted_resource_sha256=hashlib.sha256(
                first_alone.encode("ascii")
            ).hexdigest(),
        )
        second = _stage("second", (ByteChange(1, 0x33, 0x44),))
        _ = patch_resource_stack(text, [pinned_first, second])
        wrong = Patch(
            name="wrong",
            description="wrong",
            target_firmware=None,
            changes=(ByteChange(1, 0x1B, 0x33),),
            result_encrypted_resource_sha256=hashlib.sha256(b"x").hexdigest(),
        )
        with pytest.raises(PatchIntegrityError, match="patched encrypted resource"):
            _ = patch_resource_stack(text, [wrong])


def _image_data_metadata(model: Kex) -> tuple[bytes, ...]:
    for block in model.blocks:
        if b"$SA=0x60600000" in block.metadata:
            return block.metadata
    msg = "no IMAGE_DATA block"
    raise AssertionError(msg)


_IMAGE_ONLY_FIRMWARE = b"\x1b\x1b\x1b\x1b"
_IMAGE_ONLY_IMAGE_DATA = b"\x00\x00\xff\xff"
_WRONG_FIRMWARE_PIN = hashlib.sha256(b"not this firmware").hexdigest()


def _image_only_patch(
    *, source_sha256: str | None = None, result_sha256: str | None = None
) -> Patch:
    """Return an IMAGE_DATA-only patch that carries top-level FIRMWARE pins."""
    return Patch(
        name="image-only",
        description="Changes IMAGE_DATA only.",
        target_firmware="synthetic",
        changes=(ByteChange(2, 0xFF, 0x60, section="IMAGE_DATA"),),
        source_sha256=source_sha256,
        result_sha256=result_sha256,
    )


def _apply_to_model(path: str, text: str, patch: Patch) -> Kex:
    """Apply ``patch`` through the named patch path and parse the result."""
    if path == "kex":
        return parse_kex_bytes(patch_kex(text, patch))
    return parse_encrypted_resource(patch_resource(text, patch))


class TestImageOnlyPatchFirmwarePins:
    """Top-level FIRMWARE pins hold even when no change names FIRMWARE."""

    @pytest.mark.parametrize("path", ["kex", "resource"])
    def test_wrong_source_pin_is_rejected(
        self,
        path: str,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource,
            intel_hex_record,
            _IMAGE_ONLY_FIRMWARE,
            _IMAGE_ONLY_IMAGE_DATA,
        )
        with pytest.raises(PatchIntegrityError, match="source firmware"):
            _ = _apply_to_model(
                path, text, _image_only_patch(source_sha256=_WRONG_FIRMWARE_PIN)
            )

    @pytest.mark.parametrize("path", ["kex", "resource"])
    def test_wrong_result_pin_is_rejected(
        self,
        path: str,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource,
            intel_hex_record,
            _IMAGE_ONLY_FIRMWARE,
            _IMAGE_ONLY_IMAGE_DATA,
        )
        with pytest.raises(PatchIntegrityError, match="patched firmware"):
            _ = _apply_to_model(
                path, text, _image_only_patch(result_sha256=_WRONG_FIRMWARE_PIN)
            )

    @pytest.mark.parametrize("path", ["kex", "resource"])
    def test_matching_pins_leave_firmware_unchanged(
        self,
        path: str,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource,
            intel_hex_record,
            _IMAGE_ONLY_FIRMWARE,
            _IMAGE_ONLY_IMAGE_DATA,
        )
        digest = hashlib.sha256(_IMAGE_ONLY_FIRMWARE).hexdigest()
        model = _apply_to_model(
            path,
            text,
            _image_only_patch(source_sha256=digest, result_sha256=digest),
        )
        assert section_image(model, "FIRMWARE") == _IMAGE_ONLY_FIRMWARE
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\x60\xff"


class TestSectionVersionRewrite:
    def _versioned(self, version: str, *, with_change: bool = True) -> Patch:
        changes = (
            (ByteChange(2, 0xFF, 0x60, section="IMAGE_DATA"),)
            if with_change
            else (ByteChange(1, 0x1B, 0x33),)
        )
        return Patch(
            name="v",
            description="v",
            target_firmware=None,
            changes=changes,
            section_hashes=(SectionHashes("IMAGE_DATA", version=version),),
        )

    def test_patch_kex_rewrites_va_with_the_changes(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        model = parse_kex_bytes(patch_kex(text, self._versioned("1.00.02.01")))
        assert b'$VA="1.00.02.01"' in _image_data_metadata(model)
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\x60\xff"
        # FIRMWARE keeps its own metadata untouched.
        assert b'$VA="1.00.02.00"' in model.blocks[0].metadata

    def test_version_only_section_rewrites_va_without_changes(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        model = parse_kex_bytes(
            patch_kex(text, self._versioned("1.00.02.01", with_change=False))
        )
        assert b'$VA="1.00.02.01"' in _image_data_metadata(model)
        assert section_image(model, "IMAGE_DATA") == b"\x00\x00\xff\xff"

    def test_length_mismatch_rejected(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        with pytest.raises(ValueError, match="same length"):
            _ = patch_kex(text, self._versioned("1.00.02.001"))

    def test_patch_resource_rewrites_va_at_the_same_length(
        self,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        text = _two_block_resource(
            encrypt_resource, intel_hex_record, b"\x1b\x1b\x1b\x1b", b"\x00\x00\xff\xff"
        )
        patched = patch_resource(text, self._versioned("1.00.02.01"))
        assert len(patched) == len(text)
        model = parse_resource(patched)
        assert b'$VA="1.00.02.01"' in _image_data_metadata(model)
        assert render(model) == patch_kex(text, self._versioned("1.00.02.01"))
