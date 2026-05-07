"""Tests for the CLI entry points.

These exercise the four console scripts via in-process function calls
with monkeypatched ``sys.argv``. Subprocess-based tests would be more
realistic but slower and harder to debug; the entry points themselves
are thin wrappers around already-tested library code, so the focus
here is on argument parsing, error reporting, and exit codes.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from thd75_fw.cli import (
    main_extract,
    main_extract_images,
    main_extract_voice,
    main_serial_cipher,
)
from thd75_fw.serial_cipher import encrypt

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch

    EncryptResource = Callable[[list[tuple[bytes, list[bytes]]]], str]
    IntelHexRecord = Callable[..., bytes]


class TestVersionFlag:
    """Each entry point must support --version for bug-report ergonomics."""

    @pytest.mark.parametrize(
        ("main_fn", "prog"),
        [
            (main_extract, "thd75-extract"),
            (main_extract_voice, "thd75-extract-voice"),
            (main_extract_images, "thd75-extract-images"),
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
        assert "0.1.0" in capsys.readouterr().out


class TestSerialCipher:
    """``thd75-serial-cipher`` subcommands: encrypt, decrypt, selftest.
    Verifies file round-trips, exit codes, and error reporting."""

    def test_selftest_passes(
        self, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-serial-cipher", "selftest"])
        main_serial_cipher()
        assert "PASS" in capsys.readouterr().out

    def test_decrypt_via_files_round_trips(
        self, monkeypatch: MonkeyPatch, tmp_path: Path,
    ) -> None:
        plaintext = b"hello world"
        cipher_path = tmp_path / "cipher.bin"
        cipher_path.write_bytes(encrypt(plaintext))
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
        self, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str],
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


class TestExtractEndToEnd:
    """Synthesize a tiny encrypted resource and run it through the
    full ``_run_extract`` pipeline (resource → decrypt → Intel HEX →
    write). Exercises the heaviest 40-line block in cli.py that
    otherwise only the manual real-firmware E2E covers."""

    def test_synthetic_single_block_round_trips(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Tiny firmware: 4 bytes. We don't use an extended-linear-address
        # record, so Intel HEX addresses are interpreted as 16-bit offsets
        # within the section blob — the data lands at offset 0, producing
        # a 4-byte output file. The flash address comes from $SA=, used
        # only for the filename (FIRMWARE_0x00200000.bin) — not for the
        # in-memory buffer offset.
        firmware_payload = b"\xDE\xAD\xBE\xEF"
        data_record = intel_hex_record(4, 0, 0x00, firmware_payload)
        eof_record = intel_hex_record(0, 0, 0x01)
        record_stream = data_record + eof_record

        # Metadata: $SA=0x60200000 → filename derived from (0x60200000 - 0x60000000) = 0x00200000.
        metadata = b"$SA=0x60200000"

        encrypted_text = encrypt_resource([(metadata, [record_stream])])

        resource_path = tmp_path / "encrypted.txt"
        resource_path.write_text(encrypted_text, encoding="utf-8")

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
        assert expected.exists(), f"expected file not found in {list(output_dir.iterdir())}"
        assert expected.read_bytes() == firmware_payload

    def test_corrupt_metadata_raises_clean_error(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
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
        resource_path.write_text(encrypted, encoding="utf-8")

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
    """Clean error paths in ``thd75-extract``/-voice/-images: missing
    files, output-path-is-file, etc. Should produce one-line stderr
    messages with documented exit codes, never tracebacks."""

    def test_missing_input_file_exits_cleanly(
        self, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str], tmp_path: Path,
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
        existing_file.write_text("oops")
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-extract-voice", "/no/such.bin", str(existing_file)],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_extract_voice()
        # Exit 2 = clean rejection, not a stack trace.
        assert exc_info.value.code == 2
