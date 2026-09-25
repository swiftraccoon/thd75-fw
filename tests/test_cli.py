"""Tests for the CLI entry points.

These exercise the four console scripts via in-process function calls
with monkeypatched ``sys.argv``. Subprocess-based tests would be more
realistic but slower and harder to debug; the entry points themselves
are thin wrappers around already-tested library code, so the focus
here is on argument parsing, error reporting, and exit codes.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from thd75_fw import __version__, cli, intel_hex, kex, patch, resource
from thd75_fw.cli import (
    main_extract,
    main_extract_images,
    main_extract_voice,
    main_flash,
    main_list_patches,
    main_patch,
    main_repack,
    main_serial_cipher,
)
from thd75_fw.patch import ByteChange, Patch, PatchIntegrityError
from thd75_fw.serial_cipher import encrypt

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch

    from tests.conftest import IntelHexRecordBuilder

    EncryptResource = Callable[[list[tuple[bytes, list[bytes]]]], str]


class TestVersionFlag:
    """Each entry point must support --version for bug-report ergonomics."""

    @pytest.mark.parametrize(
        ("main_fn", "prog"),
        [
            (main_extract, "thd75-extract"),
            (main_extract_voice, "thd75-extract-voice"),
            (main_extract_images, "thd75-extract-images"),
            (main_flash, "thd75-flash"),
            (main_list_patches, "thd75-list-patches"),
            (main_patch, "thd75-patch"),
            (main_repack, "thd75-repack"),
            (main_serial_cipher, "thd75-serial-cipher"),
        ],
    )
    def test_version_exits_zero(
        self,
        main_fn: Callable[[], None],
        prog: str,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", [prog, "--version"])
        with pytest.raises(SystemExit) as exc_info:
            main_fn()
        assert exc_info.value.code == 0
        # argparse writes --version to stdout
        assert __version__ in capsys.readouterr().out


class TestAtomicWrite:
    """Host artifacts are installed atomically after durable temp writes."""

    @staticmethod
    def _temp_files(output_path: Path) -> list[Path]:
        return list(output_path.parent.glob(f".{output_path.name}.*.tmp"))

    def test_replaces_existing_file_after_fsync(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        output_path = tmp_path / "candidate.KEX"
        _ = output_path.write_bytes(b"old")
        output_path.chmod(0o640)
        events: list[str] = []
        real_fsync = os.fsync
        real_replace = Path.replace

        def recording_fsync(fd: int) -> None:
            events.append("fsync")
            real_fsync(fd)

        def recording_replace(self: Path, target: str | Path) -> Path:
            events.append("replace")
            return real_replace(self, target)

        monkeypatch.setattr(os, "fsync", recording_fsync)
        # Patch the method, not os.replace: before Python 3.11, Path.replace
        # calls an accessor bound to os.replace at import time.
        monkeypatch.setattr(Path, "replace", recording_replace)
        cli._atomic_write_bytes(output_path, b"verified candidate")

        assert output_path.read_bytes() == b"verified candidate"
        assert output_path.stat().st_mode & 0o777 == 0o640
        assert events == ["fsync", "replace"]
        assert self._temp_files(output_path) == []

    def test_replace_failure_keeps_existing_file_and_cleans_temp(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        output_path = tmp_path / "candidate.KEX"
        _ = output_path.write_bytes(b"known-good existing artifact")

        def fail_replace(_self: Path, _target: str | Path) -> Path:
            msg = "injected replace failure"
            raise OSError(msg)

        monkeypatch.setattr(Path, "replace", fail_replace)
        with pytest.raises(OSError, match="injected replace failure"):
            cli._atomic_write_bytes(output_path, b"new artifact")

        assert output_path.read_bytes() == b"known-good existing artifact"
        assert self._temp_files(output_path) == []

    def test_fsync_failure_keeps_existing_file_and_cleans_temp(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        output_path = tmp_path / "candidate.KEX"
        _ = output_path.write_bytes(b"known-good existing artifact")

        def fail_fsync(_fd: int) -> None:
            msg = "injected fsync failure"
            raise OSError(msg)

        monkeypatch.setattr(os, "fsync", fail_fsync)
        with pytest.raises(OSError, match="injected fsync failure"):
            cli._atomic_write_bytes(output_path, b"new artifact")

        assert output_path.read_bytes() == b"known-good existing artifact"
        assert self._temp_files(output_path) == []


class TestSerialCipher:
    """Exercise the ``thd75-serial-cipher`` encrypt, decrypt and selftest paths.

    Verifies file round-trips, exit codes, and error reporting.
    """

    def test_selftest_passes(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-serial-cipher", "selftest"])
        main_serial_cipher()
        assert "PASS" in capsys.readouterr().out

    def test_decrypt_via_files_round_trips(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        plaintext = b"hello world"
        cipher_path = tmp_path / "cipher.bin"
        _ = cipher_path.write_bytes(encrypt(plaintext))
        out_path = tmp_path / "decoded.bin"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-serial-cipher",
                "decrypt",
                str(cipher_path),
                "-o",
                str(out_path),
            ],
        )
        main_serial_cipher()
        assert out_path.read_bytes() == plaintext

    def test_decrypt_missing_file_exits_two(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-serial-cipher", "decrypt", "/definitely/not/here.bin"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_serial_cipher()
        assert exc_info.value.code == 2
        assert "file not found" in capsys.readouterr().err

    def test_out_of_range_key_rejected_by_argparse(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Out-of-range keys would silently produce wrong output
        # (negative) or an opaque IndexError (>255) at runtime. The
        # CLI must reject them at argparse time with a clean error.
        in_file = tmp_path / "in.bin"
        _ = in_file.write_bytes(b"hello")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-serial-cipher",
                "decrypt",
                str(in_file),
                "--key",
                "300",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_serial_cipher()
        # argparse exits 2 on invalid argument values.
        assert exc_info.value.code == 2
        assert "key must be 0..255" in capsys.readouterr().err

    def test_non_integer_key_rejected_by_argparse(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        in_file = tmp_path / "in.bin"
        _ = in_file.write_bytes(b"hello")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-serial-cipher",
                "encrypt",
                str(in_file),
                "--key",
                "not-a-number",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_serial_cipher()
        assert exc_info.value.code == 2
        assert "key must be an integer" in capsys.readouterr().err


class TestExtractEndToEnd:
    """Drive a synthetic encrypted resource through the full extract pipeline.

    Synthesizes a tiny encrypted resource and runs it through the full
    ``_run_extract`` pipeline (resource → decrypt → Intel HEX → write).
    Exercises the heaviest 40-line block in cli.py that otherwise only the
    manual real-firmware E2E covers.
    """

    @staticmethod
    def _resource_with_exact_v103_overlays(
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> tuple[str, bytes]:
        firmware_payload = b"\xde\xad\xbe\xef"
        firmware_records = intel_hex_record(
            4, 0, 0x00, firmware_payload
        ) + intel_hex_record(0, 0, 0x01)
        placeholder_records = intel_hex_record(1, 0, 0x00, b"\x00") + intel_hex_record(
            0, 0, 0x01
        )
        checkbytes_records = bytes.fromhex(
            "02 00 00 04 00 00 7A 02 00 00 00 B0 1D 31 00 00 00 01 FF"
        )
        final_zzz_records = bytes.fromhex(
            "02 00 00 04 00 00 7A "
            "10 00 00 00 5A 5A 7A 6F 2E 2E 28 2D 5F 2D 20 29 20 45 58 2D A3 "
            "10 00 10 00 35 32 31 30 20 32 30 32 32 2D 30 37 2D 32 30 00 CF "
            "00 00 00 01 FF"
        )
        resource_text = encrypt_resource(
            [
                (b"$SA=0x60200000", [firmware_records]),
                (b"$SA=0x60600000", [placeholder_records]),
                (b"$SA=0x60E00000", [placeholder_records]),
                (b"$SA=0x61600000", [placeholder_records]),
                (b"$SA=0x61500000", [placeholder_records]),
                (b"$SA=0x60200062", [checkbytes_records]),
                (b"$SA=0x60200040", [final_zzz_records]),
            ]
        )
        return resource_text, firmware_payload

    def test_synthetic_single_block_round_trips(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Tiny firmware: 4 bytes. We don't use an extended-linear-address
        # record, so Intel HEX addresses are interpreted as 16-bit offsets
        # within the section blob — the data lands at offset 0, producing
        # a 4-byte output file. The flash address comes from $SA=, used
        # only for the filename (FIRMWARE_0x00200000.bin) — not for the
        # in-memory buffer offset.
        firmware_payload = b"\xde\xad\xbe\xef"
        data_record = intel_hex_record(4, 0, 0x00, firmware_payload)
        eof_record = intel_hex_record(0, 0, 0x01)
        record_stream = data_record + eof_record

        # Metadata: $SA=0x60200000 → filename derived from (0x60200000 - 0x60000000) = 0x00200000.
        metadata = b"$SA=0x60200000"

        encrypted_text = encrypt_resource([(metadata, [record_stream])])

        resource_path = tmp_path / "encrypted.txt"
        _ = resource_path.write_text(encrypted_text, encoding="utf-8")

        output_dir = tmp_path / "out"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",  # ignored when --resource is given
                str(output_dir),
                "--resource",
                str(resource_path),
            ],
        )
        main_extract()

        # The CLI should have written FIRMWARE_0x00200000.bin with our payload.
        expected = output_dir / "FIRMWARE_0x00200000.bin"
        assert expected.exists(), (
            f"expected file not found in {list(output_dir.iterdir())}"
        )
        assert expected.read_bytes() == firmware_payload

    def test_section_filter_validates_only_the_requested_block(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        firmware_payload = b"\xde\xad\xbe\xef"
        firmware_records = intel_hex_record(
            4, 0, 0x00, firmware_payload
        ) + intel_hex_record(0, 0, 0x01)
        bad_overlay_records = intel_hex_record(
            2, 0, 0x00, b"\xb0\x1d", checksum=0x00
        ) + intel_hex_record(0, 0, 0x01)
        encrypted_text = encrypt_resource(
            [
                (b"$SA=0x60200000", [firmware_records]),
                (b"$SA=0x60200062", [bad_overlay_records]),
            ]
        )
        resource_path = tmp_path / "encrypted.txt"
        _ = resource_path.write_text(encrypted_text, encoding="utf-8")
        output_dir = tmp_path / "firmware-only"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(output_dir),
                "--resource",
                str(resource_path),
                "--section",
                "FIRMWARE",
            ],
        )
        main_extract()

        assert [path.name for path in output_dir.iterdir()] == [
            "FIRMWARE_0x00200000.bin"
        ]
        assert (output_dir / "FIRMWARE_0x00200000.bin").read_bytes() == firmware_payload
        err = capsys.readouterr().err
        assert "Selected section: FIRMWARE (0x00200000)" in err
        assert "Unselected blocks skipped: 1" in err
        assert "Bad record checksum" not in err

        reference_dir = tmp_path / "reference"
        reference_dir.mkdir()
        _ = (reference_dir / "FIRMWARE_0x00200000.bin").write_bytes(firmware_payload)
        _ = (reference_dir / "UNRELATED.bin").write_bytes(b"must not be compared")
        verified_output = tmp_path / "verified-firmware-only"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(verified_output),
                "--resource",
                str(resource_path),
                "--section",
                "FIRMWARE",
                "--verify",
                str(reference_dir),
            ],
        )
        main_extract()
        verify_log = capsys.readouterr().err
        assert "FIRMWARE_0x00200000.bin: MATCH" in verify_log
        assert "UNRELATED.bin" not in verify_log

    @pytest.fixture
    def exact_v103_resource(
        self,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> Path:
        """Write the exact-V1.03-overlay synthetic resource and return its path."""
        encrypted_text, _ = self._resource_with_exact_v103_overlays(
            encrypt_resource,
            intel_hex_record,
        )
        resource_path = tmp_path / "encrypted.txt"
        _ = resource_path.write_text(encrypted_text, encoding="utf-8")
        return resource_path

    @pytest.mark.parametrize("reference", ["empty", "missing"])
    def test_unfiltered_verify_fails_with_nothing_to_compare(
        self,
        reference: str,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        exact_v103_resource: Path,
    ) -> None:
        resource_path = exact_v103_resource
        reference_dir = tmp_path / "reference"
        if reference == "empty":
            reference_dir.mkdir()
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(tmp_path / "out"),
                "--resource",
                str(resource_path),
                "--verify",
                str(reference_dir),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_extract()

        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        expected = "NO REFERENCE FILES" if reference == "empty" else "DIRECTORY MISSING"
        assert expected in err
        assert "Verification: FAIL" in err

    def test_unfiltered_extract_accepts_only_the_exact_v103_overlay_streams(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        encrypted_text, firmware_payload = self._resource_with_exact_v103_overlays(
            encrypt_resource,
            intel_hex_record,
        )
        resource_path = tmp_path / "encrypted.txt"
        _ = resource_path.write_text(encrypted_text, encoding="utf-8")
        output_dir = tmp_path / "all-sections"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(output_dir),
                "--resource",
                str(resource_path),
            ],
        )
        main_extract()

        assert {path.name for path in output_dir.iterdir()} == {
            "FIRMWARE_0x00200000.bin",
            "IMAGE_DATA_0x00600000.bin",
            "DATA_00E0_0x00E00000.bin",
            "DATA_0160_0x01600000.bin",
            "FONT_DATA_0x01500000.bin",
            "CHECKBYTES_0x00200062.bin",
            "FINAL_ZZZ_0x00200040.bin",
        }
        assert (output_dir / "FIRMWARE_0x00200000.bin").read_bytes() == firmware_payload
        err = capsys.readouterr().err
        assert "Block 5: recognized exact stock V1.03 nonstandard overlay" in err
        assert "Block 6: recognized exact stock V1.03 nonstandard overlay" in err

    def test_section_filter_requires_exactly_one_matching_address(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        records = intel_hex_record(1, 0, 0x00, b"\x00") + intel_hex_record(0, 0, 0x01)
        duplicate_resource = tmp_path / "duplicate.txt"
        _ = duplicate_resource.write_text(
            encrypt_resource(
                [
                    (b"$SA=0x60200000", [records]),
                    (b"$SA=0x60200000", [records]),
                ]
            ),
            encoding="utf-8",
        )
        duplicate_output = tmp_path / "duplicate-output"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(duplicate_output),
                "--resource",
                str(duplicate_resource),
                "--section",
                "FIRMWARE",
            ],
        )
        with pytest.raises(SystemExit) as duplicate_exit:
            main_extract()
        assert duplicate_exit.value.code == 1
        assert not duplicate_output.exists()
        assert "appears in more than one block" in capsys.readouterr().err

        missing_resource = tmp_path / "missing.txt"
        _ = missing_resource.write_text(
            encrypt_resource([(b"$SA=0x60600000", [records])]),
            encoding="utf-8",
        )
        missing_output = tmp_path / "missing-output"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(missing_output),
                "--resource",
                str(missing_resource),
                "--section",
                "FIRMWARE",
            ],
        )
        with pytest.raises(SystemExit) as missing_exit:
            main_extract()
        assert missing_exit.value.code == 1
        assert not missing_output.exists()
        assert "requested section FIRMWARE is not present" in capsys.readouterr().err

    def test_section_filter_does_not_waive_selected_block_corruption(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        bad_overlay_records = intel_hex_record(
            2, 0, 0x00, b"\xb0\x1d", checksum=0x00
        ) + intel_hex_record(0, 0, 0x01)
        encrypted_text = encrypt_resource([(b"$SA=0x60200062", [bad_overlay_records])])
        resource_path = tmp_path / "encrypted.txt"
        _ = resource_path.write_text(encrypted_text, encoding="utf-8")
        output_dir = tmp_path / "checkbytes-only"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(output_dir),
                "--resource",
                str(resource_path),
                "--section",
                "CHECKBYTES",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_extract()

        assert exc_info.value.code == 1
        assert not output_dir.exists()
        assert "Bad record checksum" in capsys.readouterr().err

    def test_corrupt_metadata_raises_clean_error(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Block has data but no $SA= line — CLI should produce a clean
        # error message via _extract_flash_address rather than a traceback.
        non_sa_metadata = b"$NOT_A_SA_LINE"
        records = (
            intel_hex_record(2, 0, 0x04, b"\x00\x20")
            + intel_hex_record(4, 0, 0x00, b"\x00" * 4)
            + intel_hex_record(0, 0, 0x01)
        )
        encrypted = encrypt_resource([(non_sa_metadata, [records])])

        resource_path = tmp_path / "bad.txt"
        _ = resource_path.write_text(encrypted, encoding="utf-8")

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-extract",
                "/unused.exe",
                str(tmp_path / "out"),
                "--resource",
                str(resource_path),
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_extract()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "$SA=" in err  # error message references the missing field


class TestExtractErrors:
    """Clean error paths in ``thd75-extract`` and its voice/images siblings.

    Missing files, output-path-is-file, and similar cases should produce
    one-line stderr messages with documented exit codes, never tracebacks.
    """

    def test_missing_input_file_exits_cleanly(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Goal: a non-existent .exe should produce a one-line error,
        # not a Python traceback.
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-extract", "/no/such.exe", str(tmp_path / "out")],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_extract()
        assert exc_info.value.code == 2
        assert "file not found" in capsys.readouterr().err

    def test_output_path_is_existing_file_rejected(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        # If the user types `thd75-extract foo.exe out.bin` (typo: meant
        # `out/`), we should reject up front rather than half-extracting.
        existing_file = tmp_path / "not-a-dir.txt"
        _ = existing_file.write_text("oops")
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-extract-voice", "/no/such.bin", str(existing_file)],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_extract_voice()
        # Exit 2 = clean rejection, not a stack trace.
        assert exc_info.value.code == 2


def _patchable_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecordBuilder,
) -> str:
    """Build a synthetic resource covering the PF-key patch offsets.

    The FIRMWARE block has records covering offsets 0x10444 and 0x104B8.

    ``$CL`` must reflect the actual reconstructed image length (a 1-byte
    patch at offset 0x104B8 yields a 0x104B9-byte image after 0xFF
    padding); the engine refuses ``$CS+$CL > len(image)`` to avoid
    silently computing ``$CA`` over a truncated region.
    """
    extended = intel_hex_record(2, 0, 0x04, b"\x00\x01")  # base -> 0x0001_0000
    record_a = intel_hex_record(1, 0x0444, 0x00, b"\x1b")
    record_b = intel_hex_record(1, 0x04B8, 0x00, b"\x1b")
    eof = intel_hex_record(0, 0, 0x01)
    return encrypt_resource(
        [
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x000104B9", []),  # exactly covers the image extent
            (b"$CA=0x0000", []),
            (b"$ED", [extended + record_a + record_b + eof]),
        ]
    )


def _strict_9r_context_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecordBuilder,
) -> str:
    """Synthetic FIRMWARE matching both 9R contexts but not the full hash."""
    extended = intel_hex_record(2, 0, 0x04, b"\x00\x06")
    bound_context = intel_hex_record(4, 0xF85C, 0x00, bytes.fromhex("A0 26 F6 02"))
    read_context = intel_hex_record(
        28,
        0xF8A0,
        0x00,
        bytes.fromhex(
            "02 AA 09 04 09 0C 01 98 A1 F7 B2 FE 01 28 05 D1 "
            "00 9A 02 A9 28 00 FF F7 D6 FA 04 E0"
        ),
    )
    eof = intel_hex_record(0, 0, 0x01)
    return encrypt_resource(
        [
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x0006F8BC", []),
            (b"$CA=0x0000", []),
            (b"$ED", [extended + bound_context + read_context + eof]),
        ]
    )


class TestPatch:
    """``thd75-patch`` builds a patched .KEX from a TH-D75 updater resource.

    Applies the front-panel PF-key Screen Capture patch.
    """

    def test_writes_patched_kex(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource_path = tmp_path / "resource.txt"
        _ = resource_path.write_text(
            _patchable_resource(encrypt_resource, intel_hex_record),
            encoding="utf-8",
        )
        out_path = tmp_path / "patched.KEX"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(out_path),
                "--patch",
                "pf-screen-capture",
                "--resource",
                str(resource_path),
            ],
        )
        main_patch()
        data = out_path.read_bytes()
        assert data.startswith(b"$SA=0x60200000")
        # $CA started as a 0x0000 placeholder; a recomputed value proves
        # the patch pipeline ran end to end.
        assert b"$CA=0x0000" not in data

    def test_missing_input_exits_two(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/no/such.exe",
                str(tmp_path / "out.KEX"),
                "--patch",
                "pf-screen-capture",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_patch()
        assert exc_info.value.code == 2
        assert "file not found" in capsys.readouterr().err

    def test_output_is_directory_rejected(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        # Output path is an existing directory → reject up front.
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(tmp_path),
                "--patch",
                "pf-screen-capture",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_patch()
        assert exc_info.value.code == 2

    def test_unknown_patch_name_exits_one(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Catalog miss is a data error (exit 1, not 2): the patch
        # argument was syntactically valid but didn't resolve.
        resource_path = tmp_path / "resource.txt"
        _ = resource_path.write_text(
            _patchable_resource(encrypt_resource, intel_hex_record),
            encoding="utf-8",
        )
        out_path = tmp_path / "out.KEX"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(out_path),
                "--patch",
                "no-such-patch",
                "--resource",
                str(resource_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_patch()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "not found" in err
        # User sees the available catalog names — helps recover.
        assert "pf-screen-capture" in err
        # Atomic: no output file written on failure.
        assert not out_path.exists()

    def test_expect_mismatch_leaves_no_output(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Build a resource whose FIRMWARE bytes at 0x10444/0x104B8 are
        # NOT 0x1B — the catalog patch's expect — and check that the
        # CLI refuses, exits non-zero, and creates no .KEX output.
        extended = intel_hex_record(2, 0, 0x04, b"\x00\x01")
        record_a = intel_hex_record(1, 0x0444, 0x00, b"\xaa")  # wrong byte
        record_b = intel_hex_record(1, 0x04B8, 0x00, b"\xaa")
        eof = intel_hex_record(0, 0, 0x01)
        resource_text = encrypt_resource(
            [
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x000104B9", []),
                (b"$CA=0x0000", []),
                (b"$ED", [extended + record_a + record_b + eof]),
            ]
        )
        resource_path = tmp_path / "wrong-firmware.txt"
        _ = resource_path.write_text(resource_text, encoding="utf-8")
        out_path = tmp_path / "should-not-exist.KEX"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(out_path),
                "--patch",
                "pf-screen-capture",
                "--resource",
                str(resource_path),
            ],
        )

        def unexpected_write(_path: Path, _data: bytes) -> None:
            pytest.fail("integrity failure reached the atomic output writer")

        monkeypatch.setattr(cli, "_atomic_write_bytes", unexpected_write)
        with pytest.raises(SystemExit) as exc_info:
            main_patch()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        # Error names both the expected and actual bytes — operator
        # can immediately tell whether their firmware is "wrong
        # version" vs "already patched" vs "corrupt".
        assert "expected 0x1B" in err
        assert "0xAA" in err
        # Atomic: no .KEX written when the engine refuses.
        assert not out_path.exists()

    def test_strict_patch_wrong_full_image_hash_leaves_no_output(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource_path = tmp_path / "wrong-v103-resource.txt"
        _ = resource_path.write_text(
            _strict_9r_context_resource(encrypt_resource, intel_hex_record),
            encoding="utf-8",
        )
        out_path = tmp_path / "should-not-exist.KEX"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(out_path),
                "--patch",
                "service-9r-nor-read",
                "--resource",
                str(resource_path),
            ],
        )

        def unexpected_write(_path: Path, _data: bytes) -> None:
            pytest.fail("integrity failure reached the atomic output writer")

        monkeypatch.setattr(cli, "_atomic_write_bytes", unexpected_write)
        with pytest.raises(SystemExit) as exc_info:
            main_patch()
        assert exc_info.value.code == 1
        assert "source firmware SHA-256 mismatch" in capsys.readouterr().err
        assert not out_path.exists()


class TestPatchUpdaterHashPins:
    """Updater-backed patching authenticates the bytes it extracts."""

    @staticmethod
    def _pinned_patch(updater: bytes, *, exact: bool = True) -> Patch:
        digest = hashlib.sha256(updater).hexdigest() if exact else "00" * 32
        return Patch(
            name="strict-patch-test",
            description="strict patch policy test",
            target_firmware=None,
            changes=(ByteChange(0, 0, 1),),
            source_updater_sha256=digest,
        )

    @staticmethod
    def _stub_selected_patch(
        monkeypatch: MonkeyPatch,
        selected_patch: Patch,
    ) -> None:
        def load_patch_stub(_patch_id: str | Path) -> Patch:
            return selected_patch

        monkeypatch.setattr(patch, "load_patch", load_patch_stub)

    def test_exact_updater_is_verified_then_extracted(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        exe_data = b"exact official updater"
        resource_text = "$encrypted-source"
        patched_kex = b"exact patched KEX"
        selected_patch = self._pinned_patch(exe_data)
        exe_path = tmp_path / "official.exe"
        _ = exe_path.write_bytes(exe_data)
        output_path = tmp_path / "patched.KEX"

        self._stub_selected_patch(monkeypatch, selected_patch)

        def extract_stub(data: bytes) -> str:
            assert data == exe_data
            return resource_text

        def patch_kex_stub(text: str, policies: Sequence[Patch]) -> bytes:
            assert text == resource_text
            assert list(policies) == [selected_patch]
            return patched_kex

        monkeypatch.setattr(resource, "extract", extract_stub)
        monkeypatch.setattr(kex, "patch_kex_stack", patch_kex_stub)

        cli._run_patch(exe_path, output_path, None, ["strict-patch-test"])

        assert output_path.read_bytes() == patched_kex

    def test_wrong_updater_stops_before_extraction_or_output(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        exe_data = b"wrong updater"
        selected_patch = self._pinned_patch(exe_data, exact=False)
        exe_path = tmp_path / "wrong.exe"
        _ = exe_path.write_bytes(exe_data)
        output_path = tmp_path / "patched.KEX"
        _ = output_path.write_bytes(b"known-good existing output")

        self._stub_selected_patch(monkeypatch, selected_patch)

        def unexpected_extract(_data: bytes) -> str:
            pytest.fail("updater mismatch reached resource extraction")

        def unexpected_patch(_text: str, _policies: Sequence[Patch]) -> bytes:
            pytest.fail("updater mismatch reached firmware patching")

        def unexpected_write(_path: Path, _data: bytes) -> None:
            pytest.fail("updater mismatch reached atomic output")

        monkeypatch.setattr(resource, "extract", unexpected_extract)
        monkeypatch.setattr(kex, "patch_kex_stack", unexpected_patch)
        monkeypatch.setattr(cli, "_atomic_write_bytes", unexpected_write)

        with pytest.raises(PatchIntegrityError, match="source updater SHA-256"):
            cli._run_patch(exe_path, output_path, None, ["strict-patch-test"])
        assert output_path.read_bytes() == b"known-good existing output"

    def test_explicit_resource_does_not_authenticate_unused_updater(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        resource_text = "$explicit-resource"
        patched_kex = b"patched from explicit resource"
        selected_patch = self._pinned_patch(b"some updater", exact=False)
        resource_path = tmp_path / "resource.txt"
        _ = resource_path.write_text(resource_text, encoding="utf-8")
        output_path = tmp_path / "patched.KEX"

        self._stub_selected_patch(monkeypatch, selected_patch)

        def patch_kex_stub(text: str, policies: Sequence[Patch]) -> bytes:
            assert text == resource_text
            assert list(policies) == [selected_patch]
            return patched_kex

        monkeypatch.setattr(kex, "patch_kex_stack", patch_kex_stub)

        cli._run_patch(
            tmp_path / "unused-and-missing.exe",
            output_path,
            resource_path,
            ["strict-patch-test"],
        )

        assert output_path.read_bytes() == patched_kex


@dataclass(frozen=True, slots=True, kw_only=True)
class _RepackArtifacts:
    """The byte artifacts a stubbed repack pipeline threads together.

    Attributes:
        exe_data: The official updater .exe bytes fed to the repack.
        resource_text: The encrypted resource extracted from ``exe_data``.
        patched_resource: The re-ciphered resource after patching.
        patched_exe: The final repacked updater .exe bytes.

    """

    exe_data: bytes
    resource_text: str
    patched_resource: str
    patched_exe: bytes


class TestRepackHashPins:
    """A strict repack policy gates every artifact before atomic output."""

    @staticmethod
    def _pinned_repack_patch(
        artifacts: _RepackArtifacts,
        *,
        wrong_stage: str | None = None,
    ) -> Patch:
        def digest(stage: str, data: bytes) -> str:
            if stage == wrong_stage:
                return "00" * 32
            return hashlib.sha256(data).hexdigest()

        return Patch(
            name="strict-repack-test",
            description="strict repack policy test",
            target_firmware=None,
            changes=(ByteChange(0, 0, 1),),
            source_updater_sha256=digest("source", artifacts.exe_data),
            result_encrypted_resource_sha256=digest(
                "resource",
                artifacts.patched_resource.encode("ascii"),
            ),
            result_updater_sha256=digest("updater", artifacts.patched_exe),
        )

    @staticmethod
    def _stub_repack_pipeline(
        monkeypatch: MonkeyPatch,
        *,
        selected_patch: Patch,
        artifacts: _RepackArtifacts,
    ) -> None:
        def load_patch_stub(_patch_id: str | Path) -> Patch:
            return selected_patch

        def extract_stub(data: bytes) -> str:
            assert data == artifacts.exe_data
            return artifacts.resource_text

        def patch_resource_stub(text: str, policy: object) -> str:
            assert text == artifacts.resource_text
            assert policy is selected_patch
            return artifacts.patched_resource

        def replace_stub(data: bytes, replacement: str) -> bytes:
            assert data == artifacts.exe_data
            assert replacement == artifacts.patched_resource
            return artifacts.patched_exe

        monkeypatch.setattr(patch, "load_patch", load_patch_stub)
        monkeypatch.setattr(resource, "extract", extract_stub)
        monkeypatch.setattr(kex, "patch_resource", patch_resource_stub)
        monkeypatch.setattr(resource, "replace", replace_stub)

    def test_exact_repack_hash_chain_reaches_atomic_output(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        artifacts = _RepackArtifacts(
            exe_data=b"exact official updater",
            resource_text="$encrypted-source",
            patched_resource="$encrypted-patched",
            patched_exe=b"exact repacked updater",
        )
        selected_patch = self._pinned_repack_patch(artifacts)
        exe_path = tmp_path / "official.exe"
        _ = exe_path.write_bytes(artifacts.exe_data)
        output_path = tmp_path / "patched.exe"

        self._stub_repack_pipeline(
            monkeypatch,
            selected_patch=selected_patch,
            artifacts=artifacts,
        )

        cli._run_repack(exe_path, output_path, ["strict-repack-test"])
        assert output_path.read_bytes() == artifacts.patched_exe

    def test_wrong_patched_resource_hash_stops_before_exe_or_output(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        artifacts = _RepackArtifacts(
            exe_data=b"exact official updater",
            resource_text="$encrypted-source",
            patched_resource="$encrypted-patched",
            patched_exe=b"exact repacked updater",
        )
        selected_patch = self._pinned_repack_patch(artifacts, wrong_stage="resource")
        exe_path = tmp_path / "official.exe"
        _ = exe_path.write_bytes(artifacts.exe_data)
        output_path = tmp_path / "patched.exe"
        _ = output_path.write_bytes(b"known-good existing output")

        self._stub_repack_pipeline(
            monkeypatch,
            selected_patch=selected_patch,
            artifacts=artifacts,
        )

        def unexpected_replace(_data: bytes, _replacement: str) -> bytes:
            pytest.fail("resource mismatch reached EXE replacement")

        def unexpected_write(_path: Path, _data: bytes) -> None:
            pytest.fail("resource mismatch reached atomic output")

        monkeypatch.setattr(resource, "replace", unexpected_replace)
        monkeypatch.setattr(cli, "_atomic_write_bytes", unexpected_write)

        with pytest.raises(
            PatchIntegrityError,
            match="patched encrypted resource SHA-256 mismatch",
        ):
            cli._run_repack(exe_path, output_path, ["strict-repack-test"])
        assert output_path.read_bytes() == b"known-good existing output"

    def test_wrong_repacked_updater_hash_stops_before_output(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        artifacts = _RepackArtifacts(
            exe_data=b"exact official updater",
            resource_text="$encrypted-source",
            patched_resource="$encrypted-patched",
            patched_exe=b"wrong final updater",
        )
        selected_patch = self._pinned_repack_patch(artifacts, wrong_stage="updater")
        exe_path = tmp_path / "official.exe"
        _ = exe_path.write_bytes(artifacts.exe_data)
        output_path = tmp_path / "patched.exe"
        _ = output_path.write_bytes(b"known-good existing output")

        self._stub_repack_pipeline(
            monkeypatch,
            selected_patch=selected_patch,
            artifacts=artifacts,
        )

        def unexpected_write(_path: Path, _data: bytes) -> None:
            pytest.fail("repacked updater mismatch reached atomic output")

        monkeypatch.setattr(cli, "_atomic_write_bytes", unexpected_write)

        with pytest.raises(
            PatchIntegrityError,
            match="repacked updater SHA-256 mismatch",
        ):
            cli._run_repack(exe_path, output_path, ["strict-repack-test"])
        assert output_path.read_bytes() == b"known-good existing output"


class TestRepack:
    """``thd75-repack`` patches the updater's embedded firmware.

    Writes a new .exe with the re-ciphered resource spliced in place.
    """

    def test_writes_patched_exe(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        resource_text = _patchable_resource(encrypt_resource, intel_hex_record)
        fake_exe = (
            b"MZ"
            + b"\x00" * 64
            + resource_text.encode("ascii")
            + b"\x00\x00binary-trailer"
        )
        exe_path = tmp_path / "updater.exe"
        _ = exe_path.write_bytes(fake_exe)
        out_path = tmp_path / "patched.exe"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-repack",
                str(exe_path),
                str(out_path),
                "--patch",
                "pf-screen-capture",
            ],
        )
        main_repack()
        patched = out_path.read_bytes()
        assert len(patched) == len(fake_exe)  # in-place splice
        assert patched[:66] == fake_exe[:66]  # PE header untouched
        assert patched != fake_exe  # firmware actually changed
        assert resource.extract(patched) != resource_text

    def test_missing_input_exits_two(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-repack",
                "/no/such.exe",
                str(tmp_path / "out.exe"),
                "--patch",
                "pf-screen-capture",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_repack()
        assert exc_info.value.code == 2
        assert "file not found" in capsys.readouterr().err

    def test_output_is_directory_rejected(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-repack",
                "/unused.exe",
                str(tmp_path),
                "--patch",
                "pf-screen-capture",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_repack()
        assert exc_info.value.code == 2

    def test_unknown_patch_name_exits_one(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        resource_text = _patchable_resource(encrypt_resource, intel_hex_record)
        fake_exe = (
            b"MZ" + b"\x00" * 64 + resource_text.encode("ascii") + b"\x00\x00trailer"
        )
        exe_path = tmp_path / "updater.exe"
        _ = exe_path.write_bytes(fake_exe)
        out_path = tmp_path / "patched.exe"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-repack",
                str(exe_path),
                str(out_path),
                "--patch",
                "no-such-patch",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_repack()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "not found" in err
        assert "pf-screen-capture" in err
        # Atomic: the patched .exe is not created.
        assert not out_path.exists()

    def test_expect_mismatch_leaves_no_output(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        # Build a synthetic resource whose FIRMWARE bytes don't match
        # the catalog patch's expect → the engine refuses, the CLI
        # exits non-zero, and no .exe is written.
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        extended = intel_hex_record(2, 0, 0x04, b"\x00\x01")
        record_a = intel_hex_record(1, 0x0444, 0x00, b"\xaa")  # wrong byte
        record_b = intel_hex_record(1, 0x04B8, 0x00, b"\xaa")
        eof = intel_hex_record(0, 0, 0x01)
        resource_text = encrypt_resource(
            [
                (b"$SA=0x60200000", []),
                (b"$CS=0x00000000", []),
                (b"$CL=0x000104B9", []),
                (b"$CA=0x0000", []),
                (b"$ED", [extended + record_a + record_b + eof]),
            ]
        )
        fake_exe = (
            b"MZ" + b"\x00" * 64 + resource_text.encode("ascii") + b"\x00\x00trailer"
        )
        exe_path = tmp_path / "updater.exe"
        _ = exe_path.write_bytes(fake_exe)
        out_path = tmp_path / "should-not-exist.exe"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-repack",
                str(exe_path),
                str(out_path),
                "--patch",
                "pf-screen-capture",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_repack()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "expected 0x1B" in err
        assert "0xAA" in err
        assert not out_path.exists()

    def test_strict_patch_wrong_updater_hash_leaves_no_output(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        resource_text = _strict_9r_context_resource(encrypt_resource, intel_hex_record)
        fake_exe = (
            b"MZ" + b"\x00" * 64 + resource_text.encode("ascii") + b"\x00\x00trailer"
        )
        exe_path = tmp_path / "updater.exe"
        _ = exe_path.write_bytes(fake_exe)
        out_path = tmp_path / "should-not-exist.exe"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-repack",
                str(exe_path),
                str(out_path),
                "--patch",
                "service-9r-nor-read",
            ],
        )

        def unexpected_write(_path: Path, _data: bytes) -> None:
            pytest.fail("integrity failure reached the atomic output writer")

        monkeypatch.setattr(cli, "_atomic_write_bytes", unexpected_write)
        with pytest.raises(SystemExit) as exc_info:
            main_repack()
        assert exc_info.value.code == 1
        assert "source updater SHA-256 mismatch" in capsys.readouterr().err
        assert not out_path.exists()


class TestListPatches:
    """``thd75-list-patches`` prints every built-in catalog patch.

    Each entry shows the metadata an operator needs to pick one (name,
    target firmware, byte changes, description).
    """

    def test_lists_seed_patch(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-list-patches"])
        main_list_patches()
        out: str = capsys.readouterr().out
        # The catalog ships at least the screen-capture seed; surface its
        # name (the --patch argument), its byte changes, and prose.
        assert "pf-screen-capture" in out
        assert "0x10444" in out
        assert "0x104B8" in out
        assert "Screen Capture" in out
        assert "target firmware:" in out

    def test_extra_args_rejected(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        # The command takes no positional arguments; argparse exits 2.
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-list-patches", "unexpected"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_list_patches()
        assert exc_info.value.code == 2


def _two_section_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecordBuilder,
) -> str:
    def block(start_address: int, image: bytes) -> list[tuple[bytes, list[bytes]]]:
        payload = bytes([len(image), 0x00, 0x00, 0x00]) + image
        record = intel_hex_record(
            len(image), 0, 0x00, image, intel_hex.record_checksum(payload)
        )
        eof = intel_hex_record(0, 0, 0x01, b"", 0xFF)
        return [
            (b"$ST", []),
            (b"$SA=0x%08X" % start_address, []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x%08X" % len(image), []),
            (b"$CA=0x0000", []),
            (b"$ED", [record + eof]),
        ]

    return encrypt_resource(
        block(0x6020_0000, b"\x1b\x1b\x1b\x1b")
        + block(0x6060_0000, b"\x00\x00\xff\xff")
    )


_FIRST_TOML = (
    'name = "first"\ndescription = "first"\n'
    "[[changes]]\noffset = 1\nexpect = 0x1B\nvalue = 0x33\n"
)
_SECOND_TOML = (
    'name = "second"\ndescription = "second"\n'
    "[[changes]]\noffset = 1\nexpect = 0x33\nvalue = 0x44\n"
    '[[changes]]\nsection = "IMAGE_DATA"\noffset = 2\nexpect = "FF FF"\nvalue = "60 FF"\n'
)


class TestStackedPatchCli:
    def test_two_patches_apply_in_order_and_hash_is_logged(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: CaptureFixture[str],
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource_path = tmp_path / "resource.txt"
        _ = resource_path.write_text(
            _two_section_resource(encrypt_resource, intel_hex_record), encoding="utf-8"
        )
        first = tmp_path / "first.toml"
        _ = first.write_text(_FIRST_TOML, encoding="utf-8")
        second = tmp_path / "second.toml"
        _ = second.write_text(_SECOND_TOML, encoding="utf-8")
        out_path = tmp_path / "patched.KEX"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(out_path),
                "--patch",
                str(first),
                "--patch",
                str(second),
                "--resource",
                str(resource_path),
            ],
        )
        main_patch()
        rendered = out_path.read_bytes()
        model = kex.parse_kex_bytes(rendered)
        assert kex.section_image(model, "FIRMWARE") == b"\x1b\x44\x1b\x1b"
        assert kex.section_image(model, "IMAGE_DATA") == b"\x00\x00\x60\xff"
        err = capsys.readouterr().err
        assert (
            f"SHA-256 of rendered .KEX: {hashlib.sha256(rendered).hexdigest()}" in err
        )
        assert "IMAGE_DATA offset 0x00002: 0xFF -> 0x60" in err

    def test_wrong_order_fails_closed(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: CaptureFixture[str],
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecordBuilder,
    ) -> None:
        resource_path = tmp_path / "resource.txt"
        _ = resource_path.write_text(
            _two_section_resource(encrypt_resource, intel_hex_record), encoding="utf-8"
        )
        first = tmp_path / "first.toml"
        _ = first.write_text(_FIRST_TOML, encoding="utf-8")
        second = tmp_path / "second.toml"
        _ = second.write_text(_SECOND_TOML, encoding="utf-8")
        out_path = tmp_path / "patched.KEX"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-patch",
                "/unused.exe",
                str(out_path),
                "--patch",
                str(second),
                "--patch",
                str(first),
                "--resource",
                str(resource_path),
            ],
        )
        with pytest.raises(SystemExit) as excinfo:
            main_patch()
        assert excinfo.value.code == 1
        assert not out_path.exists()
        assert "expected 0x33 but firmware has 0x1B" in capsys.readouterr().err


class TestChangeSummaryLog:
    def test_large_patch_is_summarised_per_section(
        self, capsys: CaptureFixture[str]
    ) -> None:
        changes = tuple(
            ByteChange(offset=i, expect=0, value=1, section="IMAGE_DATA")
            for i in range(40)
        )
        changes += (ByteChange(offset=7, expect=0, value=1),)
        entry = Patch(
            name="big", description="big", target_firmware=None, changes=changes
        )
        cli._log_changes(entry)
        err = capsys.readouterr().err
        assert "FIRMWARE: 1 byte change between 0x00007 and 0x00007" in err
        assert "IMAGE_DATA: 40 byte changes between 0x00000 and 0x00027" in err

    def test_small_patch_lists_every_change(self, capsys: CaptureFixture[str]) -> None:
        entry = Patch(
            name="small",
            description="small",
            target_firmware=None,
            changes=(ByteChange(offset=0x10444, expect=0x1B, value=0x33),),
        )
        cli._log_changes(entry)
        assert "FIRMWARE offset 0x10444: 0x1B -> 0x33" in capsys.readouterr().err


class TestStackedUpdaterPins:
    def test_only_the_first_stage_authenticates_the_updater(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: CaptureFixture[str],
    ) -> None:
        exe_data = b"exact official updater"
        first = Patch(
            name="first",
            description="first",
            target_firmware=None,
            changes=(ByteChange(0, 0, 1),),
            source_updater_sha256=hashlib.sha256(exe_data).hexdigest(),
        )
        second = Patch(
            name="second",
            description="second",
            target_firmware=None,
            changes=(ByteChange(1, 0, 1),),
            source_updater_sha256="00" * 32,  # pins an intermediate repacked exe
        )
        exe_path = tmp_path / "official.exe"
        _ = exe_path.write_bytes(exe_data)
        output_path = tmp_path / "patched.KEX"
        catalog = {"first": first, "second": second}

        def load_patch_stub(patch_id: str | Path) -> Patch:
            return catalog[str(patch_id)]

        def extract_stub(data: bytes) -> str:
            assert data == exe_data
            return "$encrypted-source"

        def patch_kex_stub(_text: str, policies: Sequence[Patch]) -> bytes:
            assert list(policies) == [first, second]
            return b"stacked KEX"

        monkeypatch.setattr(patch, "load_patch", load_patch_stub)
        monkeypatch.setattr(resource, "extract", extract_stub)
        monkeypatch.setattr(kex, "patch_kex_stack", patch_kex_stub)

        cli._run_patch(exe_path, output_path, None, ["first", "second"])
        assert output_path.read_bytes() == b"stacked KEX"
        assert "second: updater source pin describes" in capsys.readouterr().err
