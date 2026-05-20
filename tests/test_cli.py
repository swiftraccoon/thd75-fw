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

from thd75_fw import __version__, resource
from thd75_fw.cli import (
    main_extract,
    main_extract_images,
    main_extract_voice,
    main_list_patches,
    main_patch,
    main_repack,
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
        in_file.write_bytes(b"hello")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-serial-cipher", "decrypt", str(in_file),
                "--key", "300",
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
        in_file.write_bytes(b"hello")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-serial-cipher", "encrypt", str(in_file),
                "--key", "not-a-number",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_serial_cipher()
        assert exc_info.value.code == 2
        assert "key must be an integer" in capsys.readouterr().err


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


def _patchable_resource(
    encrypt_resource: EncryptResource,
    intel_hex_record: IntelHexRecord,
) -> str:
    """Build a synthetic resource whose FIRMWARE block has records
    covering the PF-key patch offsets 0x10444 and 0x104B8.

    ``$CL`` must reflect the actual reconstructed image length (a 1-byte
    patch at offset 0x104B8 yields a 0x104B9-byte image after 0xFF
    padding); the engine refuses ``$CS+$CL > len(image)`` to avoid
    silently computing ``$CA`` over a truncated region.
    """
    extended = intel_hex_record(2, 0, 0x04, b"\x00\x01")  # base -> 0x0001_0000
    record_a = intel_hex_record(1, 0x0444, 0x00, b"\x1B")
    record_b = intel_hex_record(1, 0x04B8, 0x00, b"\x1B")
    eof = intel_hex_record(0, 0, 0x01)
    return encrypt_resource([
        (b"$SA=0x60200000", []),
        (b"$CS=0x00000000", []),
        (b"$CL=0x000104B9", []),  # exactly covers the image extent
        (b"$CA=0x0000", []),
        (b"$ED", [extended + record_a + record_b + eof]),
    ])


class TestPatch:
    """``thd75-patch`` builds a patched .KEX from a TH-D75 updater
    resource, applying the front-panel PF-key Screen Capture patch."""

    def test_writes_patched_kex(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
    ) -> None:
        resource_path = tmp_path / "resource.txt"
        resource_path.write_text(
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
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Catalog miss is a data error (exit 1, not 2): the patch
        # argument was syntactically valid but didn't resolve.
        resource_path = tmp_path / "resource.txt"
        resource_path.write_text(
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
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Build a resource whose FIRMWARE bytes at 0x10444/0x104B8 are
        # NOT 0x1B — the catalog patch's expect — and check that the
        # CLI refuses, exits non-zero, and creates no .KEX output.
        extended = intel_hex_record(2, 0, 0x04, b"\x00\x01")
        record_a = intel_hex_record(1, 0x0444, 0x00, b"\xAA")  # wrong byte
        record_b = intel_hex_record(1, 0x04B8, 0x00, b"\xAA")
        eof = intel_hex_record(0, 0, 0x01)
        resource_text = encrypt_resource([
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x000104B9", []),
            (b"$CA=0x0000", []),
            (b"$ED", [extended + record_a + record_b + eof]),
        ])
        resource_path = tmp_path / "wrong-firmware.txt"
        resource_path.write_text(resource_text, encoding="utf-8")
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


class TestRepack:
    """``thd75-repack`` patches the updater's embedded firmware and writes
    a new .exe with the resource spliced in place."""

    def test_writes_patched_exe(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        encrypt_resource: EncryptResource,
        intel_hex_record: IntelHexRecord,
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
        exe_path.write_bytes(fake_exe)
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
        intel_hex_record: IntelHexRecord,
    ) -> None:
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        resource_text = _patchable_resource(encrypt_resource, intel_hex_record)
        fake_exe = (
            b"MZ" + b"\x00" * 64 + resource_text.encode("ascii") + b"\x00\x00trailer"
        )
        exe_path = tmp_path / "updater.exe"
        exe_path.write_bytes(fake_exe)
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
        intel_hex_record: IntelHexRecord,
    ) -> None:
        # Build a synthetic resource whose FIRMWARE bytes don't match
        # the catalog patch's expect → the engine refuses, the CLI
        # exits non-zero, and no .exe is written.
        monkeypatch.setattr(resource, "_MIN_RESOURCE_SIZE", 100)
        extended = intel_hex_record(2, 0, 0x04, b"\x00\x01")
        record_a = intel_hex_record(1, 0x0444, 0x00, b"\xAA")  # wrong byte
        record_b = intel_hex_record(1, 0x04B8, 0x00, b"\xAA")
        eof = intel_hex_record(0, 0, 0x01)
        resource_text = encrypt_resource([
            (b"$SA=0x60200000", []),
            (b"$CS=0x00000000", []),
            (b"$CL=0x000104B9", []),
            (b"$CA=0x0000", []),
            (b"$ED", [extended + record_a + record_b + eof]),
        ])
        fake_exe = (
            b"MZ" + b"\x00" * 64 + resource_text.encode("ascii") + b"\x00\x00trailer"
        )
        exe_path = tmp_path / "updater.exe"
        exe_path.write_bytes(fake_exe)
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


class TestListPatches:
    """``thd75-list-patches`` prints every built-in catalog patch with
    the metadata an operator needs to pick one (name, target firmware,
    byte changes, description)."""

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
            sys, "argv", ["thd75-list-patches", "unexpected"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_list_patches()
        assert exc_info.value.code == 2
