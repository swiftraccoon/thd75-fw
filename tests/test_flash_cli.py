"""Tests for thd75_fw.cli.main_flash."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from thd75_fw import cli, flash_ui, intel_hex, kex
from thd75_fw.cli import (
    _post_flash_message,
    _pre_flash_message,
    _render_flash_error,
    main_flash,
)
from thd75_fw.flash import handshake as flash_handshake
from thd75_fw.flash import serial_io as flash_serial_io
from thd75_fw.flash import session as flash_session
from thd75_fw.flash.segments import ZZZ_MARKER_OFFSET, SegmentDescriptor
from thd75_fw.flash.session import (
    FlashError,
    FlashOutcome,
    FlashSession,
    FlashSessionOptions,
    SetupCalibrationOutcome,
    TargetInfo,
)
from thd75_fw.kex import parse_encrypted_resource, patch_kex, render
from thd75_fw.patch import load_patch

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch
    from _pytest.tmpdir import TempPathFactory


_REAL_RESOURCE = (
    Path(__file__).resolve().parent.parent
    / "ref"
    / "TH-D75_V103_E"
    / "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
)


@pytest.fixture(autouse=True)
def enumerated_test_usb_ports(monkeypatch: MonkeyPatch) -> None:
    """Give hardware-path tests explicit, exact TH-D75 USB identities."""
    ports = [
        (device, 0x2166, 0x9023)
        for device in ("unused", "/dev/null", "/dev/cu.usbmodem-test")
    ]
    monkeypatch.setattr(cli, "_enumerate_fldm_serial_ports", lambda: ports)


class _CloseFailingSerialContext:
    """Context stub with the same failure-preservation contract as SerialIO."""

    def __init__(self, transport: object) -> None:
        super().__init__()
        self.transport = transport

    def __enter__(self) -> object:
        return self.transport

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        del exc_type, exc_tb
        raise flash_serial_io.SerialCloseError(
            close_error=OSError("simulated close failure"),
            operation_error=exc_val,
        )


@pytest.fixture(scope="module")
def real_9r_plaintext_kex() -> bytes:
    """Generate the exact audited plaintext KEX without tracking a 43 MB file."""
    if not _REAL_RESOURCE.is_file():
        pytest.skip("real updater resource absent (ref/ is gitignored)")

    resource_text = _REAL_RESOURCE.read_text(encoding="utf-8")
    return patch_kex(resource_text, load_patch("service-9r-nor-read"))


@pytest.fixture(scope="module")
def real_stock_plaintext_kex() -> bytes:
    """Render the official encrypted resource into an external plaintext KEX."""
    if not _REAL_RESOURCE.is_file():
        pytest.skip("real updater resource absent (ref/ is gitignored)")

    resource_text = _REAL_RESOURCE.read_text(encoding="utf-8")
    return render(parse_encrypted_resource(resource_text))


@pytest.fixture(scope="module")
def real_normal_gm_ddr_kex_path(tmp_path_factory: TempPathFactory) -> Path:
    """Return one retained/generated exact DDR artifact for the whole module."""
    retained = (
        Path(__file__).resolve().parent.parent
        / "recovery"
        / "TH-D75_V103_normal-gm-ddr-read_plaintext.KEX"
    )
    if retained.is_file():
        return retained
    if not _REAL_RESOURCE.is_file():
        pytest.skip(
            "normal-GM DDR KEX and real updater resource are both absent "
            "(recovery/ and ref/ are gitignored)"
        )

    rendered = patch_kex(
        _REAL_RESOURCE.read_text(encoding="utf-8"),
        load_patch("normal-gm-ddr-read"),
    )
    generated = tmp_path_factory.mktemp("normal-gm-ddr") / "normal-gm-ddr.KEX"
    _ = generated.write_bytes(rendered)
    return generated


@pytest.fixture(scope="module")
def real_normal_gm_nor_kex_path(tmp_path_factory: TempPathFactory) -> Path:
    """Return one retained/generated exact NOR artifact for the whole module."""
    retained = (
        Path(__file__).resolve().parent.parent
        / "recovery"
        / "TH-D75_V103_normal-gm-nor-read_plaintext.KEX"
    )
    if retained.is_file():
        return retained
    if not _REAL_RESOURCE.is_file():
        pytest.skip(
            "normal-GM NOR KEX and real updater resource are both absent "
            "(recovery/ and ref/ are gitignored)"
        )

    rendered = patch_kex(
        _REAL_RESOURCE.read_text(encoding="utf-8"),
        load_patch("normal-gm-nor-read"),
    )
    generated = tmp_path_factory.mktemp("normal-gm-nor") / "normal-gm-nor.KEX"
    _ = generated.write_bytes(rendered)
    return generated


@pytest.fixture(scope="module")
def real_normal_gm_flash_plan(
    real_normal_gm_ddr_kex_path: Path,
) -> tuple[
    str,
    list[SegmentDescriptor],
    dict[int, bytes],
]:
    """Parse the exact normal-GM artifact once for fast-plan pin tests."""
    rendered = real_normal_gm_ddr_kex_path.read_bytes()
    image = kex.parse_kex_bytes(rendered)
    segments = [SegmentDescriptor.from_kex_block(block) for block in image.blocks]
    segment_data = {
        index: intel_hex.parse(block.records).data
        for index, block in enumerate(image.blocks)
    }
    return hashlib.sha256(rendered).hexdigest(), segments, segment_data


class TestFlashCliArgparse:
    def test_version_exits_zero(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--version"])
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 0

    def test_help_marks_every_raw_path_dry_run_only(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 0
        help_text = " ".join(capsys.readouterr().out.split())
        assert "Raw mode is currently dry-run-only" in help_text
        assert "raw hardware writes are disabled" in help_text
        assert "modeled as LE u32" in help_text
        assert "--acknowledge-service-9r-write" in help_text
        assert "Required in addition to any --yes" in help_text
        assert "untouched-stock USB-C 9R baseline" in help_text
        assert "positive SETUP controls pass" in help_text
        assert "a full radio power cycle" in help_text
        assert "exact mismatch/repeat result (1,0) passes" in help_text
        assert "another full radio power cycle" in help_text
        assert "verified stock restore artifact retained" in help_text
        assert "patched read/bounds check follows this write" in help_text
        assert "one-byte-first patched USB-C check" not in help_text

    @pytest.mark.parametrize(
        "mode_args",
        [
            ["--probe-only", "--port", "unused"],
            ["--probe-target", "--port", "unused"],
            ["--setup-controls-only", "--port", "unused"],
            [
                "--setup-mismatch-repeat-only",
                "--allow-unproven-setup-repeat",
                "--port",
                "unused",
            ],
            ["--dry-run", "unused.KEX"],
            ["--raw", "--port", "unused", "unused.bin"],
        ],
    )
    def test_service_9r_write_ack_rejected_outside_real_kex_write(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        mode_args: list[str],
    ) -> None:

        flash_runner = MagicMock()
        probe_runner = MagicMock()
        target_runner = MagicMock()
        setup_runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", flash_runner)
        monkeypatch.setattr(cli, "_run_flash_probe", probe_runner)
        monkeypatch.setattr(cli, "_run_flash_probe_target", target_runner)
        monkeypatch.setattr(cli, "_run_setup_calibration", setup_runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                *mode_args,
                "--acknowledge-service-9r-write",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert (
            "valid only for a real write of the exact service-9r-nor-read"
            in capsys.readouterr().err
        )
        flash_runner.assert_not_called()
        probe_runner.assert_not_called()
        target_runner.assert_not_called()
        setup_runner.assert_not_called()

    def test_service_9r_write_ack_does_not_skip_generic_prompt(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--acknowledge-service-9r-write",
                "service-9r.KEX",
            ],
        )

        main_flash()

        assert runner.call_args.args[0].acknowledge_service_9r_write is True
        assert runner.call_args.args[0].skip_prompt is False

    def test_missing_port_rejected(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "some.KEX"])
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 2

    @pytest.mark.parametrize(
        "mode_args",
        [
            ["--probe-only"],
            ["--probe-target"],
            ["--setup-controls-only"],
            [
                "--setup-mismatch-repeat-only",
                "--allow-unproven-setup-repeat",
            ],
            ["stock.KEX"],
        ],
    )
    @pytest.mark.parametrize(
        "bad_port_identity",
        [
            ("/dev/cu.TH-D75", None, None),
            ("/dev/cu.usbserial-unrelated", 0x1234, 0x5678),
        ],
    )
    def test_every_hardware_mode_rejects_non_d75_usb_before_runner_or_open(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        mode_args: list[str],
        bad_port_identity: tuple[str, int | None, int | None],
    ) -> None:
        bad_port, vid, pid = bad_port_identity
        monkeypatch.setattr(
            cli,
            "_enumerate_fldm_serial_ports",
            lambda: [(bad_port, vid, pid)],
        )
        runners = [
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ]
        monkeypatch.setattr(cli, "_run_flash_probe", runners[0])
        monkeypatch.setattr(cli, "_run_flash_probe_target", runners[1])
        monkeypatch.setattr(cli, "_run_setup_calibration", runners[2])
        monkeypatch.setattr(cli, "_run_flash", runners[3])
        serial_constructor = MagicMock(
            side_effect=AssertionError("identity refusal opened SerialIO")
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", bad_port, *mode_args],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "not a currently enumerated TH-D75 USB endpoint" in err
        assert "VID:PID 2166:9023" in err
        assert "does not prove Firmware Programming Mode" in err
        assert "PTT+1" in err
        for runner in runners:
            runner.assert_not_called()
        serial_constructor.assert_not_called()

    def test_dry_run_does_not_require_port(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        image = tmp_path / "payload.bin"
        _ = image.write_bytes(b"\x00" * 16)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--dry-run",
                "--raw",
                str(image),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--chunk-size",
                "128",
                "--single-segment",
            ],
        )

        main_flash()

    def test_missing_input_without_probe_only_exits_two(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--port", "/dev/null"])
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 2

    def test_raw_requires_flash_addr(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # --raw without --flash-addr should exit before any I/O
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "/dev/null", "--raw", str(tmp_path / "foo.bin")],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 2
        assert "--flash-addr" in capsys.readouterr().err

    def test_raw_flash_addr_parses_hex(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        # argparse should accept 0x-prefixed hex thanks to lambda s: int(s, 0)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                "/nonexistent.bin",
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--yes",
            ],
        )
        # The pre-flash prompt is skipped via --yes; the read of the
        # nonexistent file then raises FileNotFoundError, which the CLI
        # translates to exit 2 (I/O problem).
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 2

    @pytest.mark.parametrize("chunk_size", ["0", "-1", "2049"])
    def test_chunk_size_outside_loader_limit_is_rejected(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        chunk_size: str,
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--chunk-size",
                chunk_size,
                "some.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "1..2048" in capsys.readouterr().err

    @pytest.mark.parametrize("chunk_size", ["1", "128", "255", "257", "2048"])
    def test_real_write_rejects_every_unproven_chunk_size_before_runner(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        chunk_size: str,
    ) -> None:

        runner = MagicMock(
            side_effect=AssertionError("unproven chunk size reached flash runner")
        )
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--chunk-size",
                chunk_size,
                "some.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "require --chunk-size 256" in capsys.readouterr().err
        runner.assert_not_called()

    def test_real_write_accepts_the_proven_chunk_size(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "--chunk-size", "256", "some.KEX"],
        )

        main_flash()

        assert runner.call_args.args[0].chunk_size == 256
        assert runner.call_args.args[0].reference_transport is True

    def test_real_write_rejects_unproven_vendor_data_unit(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        """The OEM host's 1024-byte choice is not the proven recovery path."""
        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "--chunk-size", "1024", "some.KEX"],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "require --chunk-size 256" in capsys.readouterr().err
        runner.assert_not_called()

    def test_default_chunk_size_fits_the_platform_output_ring(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """The CLI defaults to the packet size proven by both stock restores."""
        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "some.KEX"],
        )

        main_flash()

        assert runner.call_args.args[0].chunk_size == 256
        assert cli._DEFAULT_CHUNK_SIZE == 256
        assert frozenset({256}) == cli._WRITABLE_CHUNK_SIZES

    def test_setup_controls_dispatch_without_input(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_setup_calibration", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--setup-controls-only",
                "--port",
                "/dev/cu.usbmodem-test",
            ],
        )

        main_flash()

        runner.assert_called_once_with(
            "/dev/cu.usbmodem-test",
            mismatch_repeat=False,
            reference_transport=False,
        )

    def test_setup_mismatch_requires_explicit_acknowledgement(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--setup-mismatch-repeat-only",
                "--port",
                "/dev/cu.usbmodem-test",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "--allow-unproven-setup-repeat" in capsys.readouterr().err

    def test_setup_mismatch_dispatches_only_with_acknowledgement(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_setup_calibration", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--setup-mismatch-repeat-only",
                "--allow-unproven-setup-repeat",
                "--port",
                "/dev/cu.usbmodem-test",
            ],
        )

        main_flash()

        runner.assert_called_once_with(
            "/dev/cu.usbmodem-test",
            mismatch_repeat=True,
            reference_transport=False,
        )

    def test_setup_mode_rejects_input_image(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--setup-controls-only",
                "--port",
                "/dev/cu.usbmodem-test",
                "unexpected.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "do not accept an input image" in capsys.readouterr().err

    def test_deep_probe_flash_error_requires_power_cycle(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        transport = object()
        serial_context = MagicMock()
        serial_context.__enter__.return_value = transport
        serial_constructor = MagicMock(return_value=serial_context)
        session = MagicMock()
        session.probe_target_only.side_effect = FlashError(
            step="QUERY_TARGET",
            cause="target info payload must be 17 bytes, got 16",
            recoverable=True,
        )
        session_constructor = MagicMock(return_value=session)
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--probe-target", "--port", "unused"],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 3
        err = capsys.readouterr().err
        assert "deep probe failed" in err
        assert "QUERY_TARGET: target info payload must be 17 bytes, got 16" in err
        assert "Power-cycle the radio" in err
        assert "diagnose this exact failed step" in err
        assert "MANDATORY: disconnect USB and fully power-cycle" in err


class TestHardwareSessionCleanup:
    @pytest.mark.parametrize("operation_fails", [False, True])
    def test_probe_preserves_close_failure_and_prior_operation(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        *,
        operation_fails: bool,
    ) -> None:

        context = _CloseFailingSerialContext(object())
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(return_value=context),
        )
        if operation_fails:
            monkeypatch.setattr(
                flash_handshake,
                "perform_handshake",
                MagicMock(
                    side_effect=flash_handshake.HandshakeError(
                        "simulated unlock failure"
                    )
                ),
            )
        else:
            monkeypatch.setattr(
                flash_handshake,
                "perform_handshake",
                MagicMock(return_value=SimpleNamespace(baud=19_200, xor_key=0x42)),
            )

        with pytest.raises(SystemExit) as exc_info:
            cli._run_flash_probe("/dev/cu.usbmodem-test", None)

        assert exc_info.value.code == 3
        err = capsys.readouterr().err
        assert "simulated close failure" in err
        assert "MANDATORY: disconnect USB and fully power-cycle" in err
        if operation_fails:
            assert "operation failed" in err
            assert "simulated unlock failure" in err

    @pytest.mark.parametrize("operation_fails", [False, True])
    def test_setup_preserves_close_failure_and_prior_operation(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        *,
        operation_fails: bool,
    ) -> None:

        context = _CloseFailingSerialContext(object())
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(return_value=context),
        )
        session = MagicMock()
        if operation_fails:
            session.calibrate_setup_controls_only.side_effect = FlashError(
                step="SETUP_CALIBRATION[0]",
                cause="simulated SETUP failure",
                recoverable=True,
            )
        else:
            target = TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            )
            session.calibrate_setup_controls_only.return_value = (
                SetupCalibrationOutcome(target=target, setup_results=(0, 0, 0))
            )
        monkeypatch.setattr(
            flash_session,
            "FlashSession",
            MagicMock(return_value=session),
        )

        with pytest.raises(SystemExit) as exc_info:
            cli._run_setup_calibration(
                "/dev/cu.usbmodem-test",
                mismatch_repeat=False,
            )

        assert exc_info.value.code == 3
        err = capsys.readouterr().err
        assert "simulated close failure" in err
        assert "MANDATORY: disconnect USB and fully power-cycle" in err
        if operation_fails:
            assert "operation failed" in err
            assert "simulated SETUP failure" in err

    @pytest.mark.parametrize("operation_fails", [False, True])
    def test_full_flash_preserves_close_failure_and_prior_operation(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
        *,
        operation_fails: bool,
    ) -> None:

        image_path = tmp_path / "service-9r.KEX"
        _ = image_path.write_bytes(real_9r_plaintext_kex)
        transport = object()
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            MagicMock(return_value=_CloseFailingSerialContext(transport)),
        )
        session = MagicMock()
        if operation_fails:
            session.flash_segments.side_effect = FlashError(
                step="SEND_CHUNK[segment_0]",
                cause="simulated flash failure",
                recoverable=True,
            )
        else:
            session.flash_segments.return_value = FlashOutcome(
                target=TargetInfo(
                    raw_payload=b"\x00" * 17,
                    target_mask_bytes=b"\x00" * 8,
                    opaque_bytes_8_15=b"\x00" * 8,
                    trailing_status=0,
                ),
                segments_written=7,
                bytes_written=2_621_440,
                elapsed_seconds=0.0,
            )
        session_constructor = MagicMock(return_value=session)
        session_constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
        session_constructor.validate_plan = FlashSession.validate_plan
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            flash_ui,
            "RichProgressListener",
            MagicMock(return_value=object()),
        )

        with pytest.raises(SystemExit) as exc_info:
            cli._run_flash(
                cli._FlashRequest(
                    input_path=image_path,
                    port="/dev/cu.usbmodem-test",
                    baud_ladder_text=None,
                    skip_prompt=True,
                    dry_run=False,
                    show_post_hint=False,
                    chunk_size=256,
                    raw=False,
                    flash_addr=None,
                    cleartext_unlock=True,
                    cleartext_baud=576_000,
                    acknowledge_service_9r_write=True,
                )
            )

        assert exc_info.value.code == 3
        err = capsys.readouterr().err
        assert "simulated close failure" in err
        assert "MANDATORY: disconnect USB and fully power-cycle" in err
        if operation_fails:
            assert "operation failed" in err
            assert "simulated flash failure" in err

    @pytest.mark.parametrize("operation_fails", [False, True])
    def test_probe_always_prints_mandatory_disconnect_and_power_cycle(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        *,
        operation_fails: bool,
    ) -> None:

        context = MagicMock()
        context.__enter__.return_value = object()
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(return_value=context),
        )
        handshake = MagicMock(return_value=SimpleNamespace(baud=19_200, xor_key=0x42))
        if operation_fails:
            handshake.side_effect = flash_handshake.HandshakeError(
                "simulated handshake failure"
            )
        monkeypatch.setattr(flash_handshake, "perform_handshake", handshake)

        if operation_fails:
            with pytest.raises(SystemExit):
                cli._run_flash_probe("/dev/cu.usbmodem-test", None)
        else:
            cli._run_flash_probe("/dev/cu.usbmodem-test", None)

        assert (
            "MANDATORY: disconnect USB and fully power-cycle" in capsys.readouterr().err
        )

    @pytest.mark.parametrize("operation_fails", [False, True])
    def test_deep_probe_always_prints_mandatory_disconnect_and_power_cycle(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        *,
        operation_fails: bool,
    ) -> None:

        context = MagicMock()
        context.__enter__.return_value = object()
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(return_value=context),
        )
        session = MagicMock()
        if operation_fails:
            session.probe_target_only.side_effect = FlashError(
                step="QUERY_TARGET",
                cause="simulated deep-probe failure",
                recoverable=True,
            )
        else:
            session.probe_target_only.return_value = TargetInfo(
                raw_payload=(
                    b"\x02\x00\x00\x00\x00\x00\x00\x00"
                    b"\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                target_mask_bytes=b"\x02" + b"\x00" * 7,
                opaque_bytes_8_15=b"\x02" + b"\x00" * 7,
                trailing_status=0,
            )
        monkeypatch.setattr(
            flash_session,
            "FlashSession",
            MagicMock(return_value=session),
        )

        if operation_fails:
            with pytest.raises(SystemExit):
                cli._run_flash_probe_target("/dev/cu.usbmodem-test", None)
        else:
            cli._run_flash_probe_target("/dev/cu.usbmodem-test", None)

        assert (
            "MANDATORY: disconnect USB and fully power-cycle" in capsys.readouterr().err
        )


class TestRawFlashRegionGuardrail:
    """The audited raw profile permits only the main-firmware start."""

    def test_rejects_bootloader_region_by_default(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Create a tiny .bin so the read succeeds; the guardrail must
        # then fire BEFORE any serial I/O happens.
        bin_path = tmp_path / "evil.bin"
        _ = bin_path.write_bytes(b"\x00" * 16)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00000000",
                "--complete-code",
                "0x1DB0",
                "--yes",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "bootloader" in err.lower()
        assert "not supported" in err

    def test_rejects_overrun_past_main_region(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # 0x101 bytes starting 0x100 below the slot end → overruns.
        bin_path = tmp_path / "too-long.bin"
        _ = bin_path.write_bytes(b"\x00" * 0x101)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x004FFF00",
                "--complete-code",
                "0x1DB0",
                "--yes",
            ],
        )
        with pytest.raises(SystemExit) as exc_info:
            main_flash()
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "other NOR region" in err

    def test_3segment_vendor_order_announced_in_log(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Build a synthetic dumper-shaped image: 128 bytes with a real
        # ZZZ marker at offset 0x40. --raw default should split it.
        zzz = b"ZZzo..(-_- ) EX-5210 2022-07-20\x00"
        body = bytearray(b"\x12" * 128)
        body[0x40:0x80] = zzz + b"\xff\xff\xb0\x1d" + b"\xff" * 28
        bin_path = tmp_path / "dumper-like.bin"
        _ = bin_path.write_bytes(bytes(body))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--yes",
            ],
        )
        with pytest.raises((SystemExit, Exception)):
            main_flash()
        err = capsys.readouterr().err
        assert "3-segment vendor finalization order" in err
        assert "CHECKBYTES" in err
        assert "FINAL_ZZZ last" in err

    def test_single_segment_flag_uses_legacy_mode(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:

        zzz = b"ZZzo..(-_- ) EX-5210 2022-07-20\x00"
        body = bytearray(b"\x12" * 128)
        body[ZZZ_MARKER_OFFSET : ZZZ_MARKER_OFFSET + len(zzz)] = zzz
        bin_path = tmp_path / "dumper-like.bin"
        _ = bin_path.write_bytes(bytes(body))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--yes",
                "--single-segment",
            ],
        )
        with pytest.raises((SystemExit, Exception)):
            main_flash()
        err = capsys.readouterr().err
        assert "single segment (offline diagnostic only" in err
        assert "Flash strategy: 3-segment" not in err

    def test_image_without_stock_finalization_is_rejected(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # An image with 0xFF at the ZZZ slot has nothing to defer —
        # we should emit a single segment even without --single-segment.
        bin_path = tmp_path / "no-marker.bin"
        _ = bin_path.write_bytes(b"\xab" * 0x40 + b"\xff" * 32 + b"\xab" * 32)

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--yes",
            ],
        )
        with pytest.raises((SystemExit, Exception)):
            main_flash()
        err = capsys.readouterr().err
        assert "finalization block does not match" in err

    def test_safe_region_prints_reassuring_tag(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        bin_path = tmp_path / "ok.bin"
        _ = bin_path.write_bytes(b"\x00" * 16)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "/dev/null",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--yes",
                "--single-segment",
            ],
        )
        # As with the override test, the actual flash will fail at the
        # serial layer. We only assert on the pre-flash region log.
        with pytest.raises((SystemExit, Exception)):
            main_flash()
        err = capsys.readouterr().err
        assert "main-firmware slot" in err
        assert "protected low-NOR candidate untouched" in err
        # The address must appear explicitly so the operator can verify.
        assert "0x00200000" in err

    def test_raw_hardware_write_is_disabled_before_serial_open(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        bin_path = tmp_path / "payload.bin"
        image = bytearray(b"\x00" * 128)
        image[0x40:0x80] = (
            b"ZZzo..(-_- ) EX-5210 2022-07-20\x00" + b"\xff\xff\xb0\x1d" + b"\xff" * 28
        )
        _ = bin_path.write_bytes(image)

        serial_context = MagicMock()
        serial_context.__enter__.return_value = object()
        serial_constructor = MagicMock(return_value=serial_context)
        session = MagicMock()
        session.flash_segments.return_value = FlashOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            segments_written=1,
            bytes_written=16,
            elapsed_seconds=0.0,
        )
        session_constructor = MagicMock(return_value=session)
        session_constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--yes",
                "--no-post-hint",
                "--cleartext",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "hardware raw-image writes are disabled" in capsys.readouterr().err
        serial_constructor.assert_not_called()
        session.flash_segments.assert_not_called()

    def test_dry_run_validates_plan_without_device_io(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        bin_path = tmp_path / "payload.bin"
        _ = bin_path.write_bytes(b"\x00" * 16)
        serial_constructor = MagicMock(
            side_effect=AssertionError("dry-run opened the serial device"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--raw",
                str(bin_path),
                "--flash-addr",
                "0x00200000",
                "--complete-code",
                "0x1DB0",
                "--dry-run",
                "--single-segment",
            ],
        )

        main_flash()

        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert "0x1DB0 as LE u32 (b0 1d 00 00)" in err
        assert "Packet padding: 16 + 240 erased bytes = 256" in err
        assert "packets=1" in err
        assert "no serial device opened and no bytes sent" in err


class TestPlaintextKexFlashInput:
    """The flasher consumes external plaintext bytes and rejects ciphertext."""

    def test_exact_9r_patch_reaches_complete_offline_plan(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "service-9r.KEX"
        _ = image_path.write_bytes(real_9r_plaintext_kex)
        serial_constructor = MagicMock(
            side_effect=AssertionError("plaintext KEX dry-run opened device"),
        )
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(side_effect=AssertionError("legacy transport was opened")),
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            serial_constructor,
        )
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--dry-run", str(image_path)],
        )

        main_flash()

        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert "canonical plaintext external KEX (no decryption)" in err
        assert (
            err.count(
                "fa95a673156c2d47b06a85fd6038682bbe1adfcbd1b7bdfdb7529ecfc1ca9541"
            )
            == 2
        )
        assert "Audited KEX artifact: TH-D75 V1.03 service-9r-nor-read" in err
        assert "Segment 0: start=0x60200000" in err
        assert "Segment 3: start=0x61600000" in err
        assert "Fast plan:" not in err
        assert "Host omission:" not in err
        assert (
            "payload_sha256=c7cd9d300a73c984408df39c50d2fb7802f826b7300cb8ffb7122c366c010e91"
            in err
        )
        assert "no serial device opened and no bytes sent" in err

    def test_exact_stock_plaintext_reaches_complete_offline_plan(
        self,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "stock.KEX"
        _ = image_path.write_bytes(real_stock_plaintext_kex)
        serial_constructor = MagicMock(
            side_effect=AssertionError("stock KEX dry-run opened device"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--dry-run", str(image_path)],
        )

        main_flash()

        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert (
            err.count(
                "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
            )
            == 2
        )
        assert "Audited KEX artifact: official TH-D75 V1.03 stock" in err
        assert "Segment 0: start=0x60200000" in err
        assert "Segment 3: start=0x61600000" in err
        assert "Fast plan:" not in err
        assert "Host omission:" not in err
        assert (
            "payload_sha256=193963ca4b7a38392815686893858eec20292b629fe999f10b93a22a3a8e4001"
            in err
        )
        assert "no serial device opened and no bytes sent" in err

    def test_exact_9r_real_write_requires_dedicated_ack_even_with_yes(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "service-9r.KEX"
        _ = image_path.write_bytes(real_9r_plaintext_kex)
        serial_constructor = MagicMock(
            side_effect=AssertionError("unacknowledged service-9R write opened device"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                str(image_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert "requires --acknowledge-service-9r-write" in err
        assert "positive SETUP controls pass" in err
        assert "a full radio power cycle" in err
        assert "exact mismatch/repeat result (1,0) passes" in err
        assert "another full radio power cycle" in err
        assert "patched read/bounds check follows this write" in err
        assert "one-byte-first patched USB-C check" not in err
        assert "--yes does not satisfy this dedicated gate" in err

    def test_offline_preflight_flash_error_is_a_controlled_refusal(
        self,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Keep the canonical grammar/profile and payload intact, but move the
        # first descriptor into the protected low-NOR span. This reaches the
        # pure validate_plan() call that previously leaked FlashError.
        invalid_plan = real_stock_plaintext_kex.replace(
            b"$SA=0x60200000",
            b"$SA=0x60000000",
            1,
        )
        assert invalid_plan != real_stock_plaintext_kex
        image_path = tmp_path / "protected-low-nor.KEX"
        _ = image_path.write_bytes(invalid_plan)
        serial_constructor = MagicMock(
            side_effect=AssertionError("invalid offline plan opened device"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--dry-run", str(image_path)],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert "invalid flash plan at PREFLIGHT" in err
        assert "forbidden NOR span" in err
        assert "Traceback" not in err

    def test_service_9r_write_ack_is_rejected_for_stock_hash_before_io(
        self,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "stock.KEX"
        _ = image_path.write_bytes(real_stock_plaintext_kex)
        serial_constructor = MagicMock(
            side_effect=AssertionError("out-of-scope service-9R ack opened device"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                "--acknowledge-service-9r-write",
                str(image_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        serial_constructor.assert_not_called()
        assert (
            "valid only for a real write of the exact service-9r-nor-read"
            in capsys.readouterr().err
        )

    def test_service_9r_write_ack_is_rejected_for_unpinned_hash_before_io(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        unpinned = real_9r_plaintext_kex.replace(
            b"; Program Data",
            b"; Program Datz",
            1,
        )
        assert unpinned != real_9r_plaintext_kex
        image_path = tmp_path / "unpinned.KEX"
        _ = image_path.write_bytes(unpinned)
        serial_constructor = MagicMock(
            side_effect=AssertionError("unpinned service-9R ack opened device"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                "--acknowledge-service-9r-write",
                str(image_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert "Audited KEX artifact: NO" in err
        assert "valid only for a real write of the exact service-9r-nor-read" in err

    def test_exact_9r_with_both_acknowledgements_reaches_mocked_session(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:

        image_path = tmp_path / "service-9r.KEX"
        _ = image_path.write_bytes(real_9r_plaintext_kex)
        transport = object()
        serial_context = MagicMock()
        serial_context.__enter__.return_value = transport
        serial_constructor = MagicMock(return_value=serial_context)
        session = MagicMock()
        session.flash_segments.return_value = FlashOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            segments_written=7,
            bytes_written=2_621_440,
            elapsed_seconds=0.0,
        )
        session_constructor = MagicMock(return_value=session)
        session_constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
        session_constructor.validate_plan = FlashSession.validate_plan
        listener = object()
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(side_effect=AssertionError("legacy transport was opened")),
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            serial_constructor,
        )
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            flash_ui, "RichProgressListener", MagicMock(return_value=listener)
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--no-post-hint",
                "--cleartext",
                "--acknowledge-service-9r-write",
                str(image_path),
            ],
        )

        main_flash()

        serial_constructor.assert_called_once_with(
            "unused",
            baud=576_000,
            options=flash_serial_io.ReferenceSerialOptions(reassert_read_timeout=False),
        )
        session_constructor.assert_called_once_with(
            transport,
            # Diagnostics defaults: the wire trace is opt-in, the periodic
            # throughput line is not.
            FlashSessionOptions(chunk_size=256, progress_every_chunks=256),
            progress=listener,
            trace=None,
        )
        session.flash_segments.assert_called_once()
        flash_call = session.flash_segments.call_args
        assert len(flash_call.args[0]) == 7
        assert len(flash_call.args[1]) == 7
        run_options = flash_call.args[2]
        assert run_options.complete_update_value == 0x1DB0
        assert run_options.complete_update_width == 4
        # The KEX declares #AF=1, but the default is now to let the loader's
        # own SETUP equality answer decide, so unchanged segments are skipped.
        # Dry runs can model the vendor's force policy; real writes cannot.
        assert run_options.always_flash is False
        assert run_options.force_segment_indices == frozenset()
        assert run_options.cleartext_unlock is True
        assert run_options.cleartext_baud == 576_000

    def test_encrypted_resource_disguised_as_kex_is_rejected_before_io(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "mislabeled.KEX"
        _ = image_path.write_bytes(b"$930D67E4E627BE\r\n$A4B324EAFA\r\n")
        serial_constructor = MagicMock(
            side_effect=AssertionError("encrypted resource reached device I/O"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--dry-run", str(image_path)],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        serial_constructor.assert_not_called()
        assert "encrypted updater-resource text" in capsys.readouterr().err

    def test_unpinned_plaintext_hash_is_dry_run_only(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Change one ignored comment byte without disturbing the canonical
        # KEX grammar, metadata profile, descriptors, or section payloads.
        unpinned = real_9r_plaintext_kex.replace(
            b"; Program Data",
            b"; Program Datz",
            1,
        )
        assert unpinned != real_9r_plaintext_kex
        image_path = tmp_path / "unpinned.KEX"
        _ = image_path.write_bytes(unpinned)
        serial_constructor = MagicMock(
            side_effect=AssertionError("unpinned KEX reached device I/O"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                str(image_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        serial_constructor.assert_not_called()
        err = capsys.readouterr().err
        assert "Audited KEX artifact: NO" in err
        assert "hardware KEX writes are limited to the exact audited" in err
        assert "stock V1.03" in err
        assert "service-9r-nor-read" in err
        assert "normal-gm-ddr-read" in err


class TestPreFlashMessage:
    def test_includes_ptt_one_combo(self) -> None:
        msg = _pre_flash_message()
        assert "PTT" in msg
        assert "[1]" in msg


class TestPostFlashMessage:
    def test_includes_full_reset(self) -> None:
        msg = _post_flash_message()
        assert "Full Reset" in msg
        assert "[F]" in msg


class TestRenderFlashError:
    def test_recoverable_requires_diagnosis_before_rerun(self) -> None:
        err = FlashError(
            step="SETUP_SEGMENT[FIRMWARE]",
            cause="NAK 0x15 0x02",
            recoverable=True,
        )
        out = _render_flash_error(err)
        assert "SETUP_SEGMENT[FIRMWARE]" in out
        assert "diagnose" in out

    def test_irrecoverable_stops_usb_bluetooth_workflow(self) -> None:
        err = FlashError(
            step="X",
            cause="bootloader corrupt",
            recoverable=False,
        )
        rendered = _render_flash_error(err)
        assert "USB-C/Bluetooth-only" in rendered
        assert "do not attempt another write" in rendered


class TestGmDdrReadWriteAck:
    """`--acknowledge-gm-ddr-read-write` gates a real normal-gm-ddr-read write.

    It is independent of `--yes`, and is rejected anywhere a real KEX write is
    not what is happening, so it cannot be left in a command line and silently
    apply to something else later.
    """

    def test_flag_is_documented(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 0
        # Whitespace is normalised because argparse rewraps help text.
        help_text = " ".join(capsys.readouterr().out.split())
        assert "--acknowledge-gm-ddr-read-write" in help_text
        assert "normal-gm-ddr-read" in help_text
        assert "Firmware Programming Mode entry proven" in help_text
        assert "verified stock restore artifact generated and retained" in help_text
        assert "destroys the GM GPS-mode command" in help_text
        assert "out-of-bounds request that is rejected" in help_text

    @pytest.mark.parametrize(
        "mode_args",
        [
            ["--probe-only", "--port", "unused"],
            ["--probe-target", "--port", "unused"],
            ["--setup-controls-only", "--port", "unused"],
            [
                "--setup-mismatch-repeat-only",
                "--allow-unproven-setup-repeat",
                "--port",
                "unused",
            ],
            ["--dry-run", "unused.KEX"],
            ["--raw", "--port", "unused", "unused.bin"],
        ],
    )
    def test_ack_rejected_outside_real_kex_write(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        mode_args: list[str],
    ) -> None:

        flash_runner = MagicMock()
        probe_runner = MagicMock()
        target_runner = MagicMock()
        setup_runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", flash_runner)
        monkeypatch.setattr(cli, "_run_flash_probe", probe_runner)
        monkeypatch.setattr(cli, "_run_flash_probe_target", target_runner)
        monkeypatch.setattr(cli, "_run_setup_calibration", setup_runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", *mode_args, "--acknowledge-gm-ddr-read-write"],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert (
            "valid only for a real write of the exact normal-gm-ddr-read"
            in capsys.readouterr().err
        )
        flash_runner.assert_not_called()
        probe_runner.assert_not_called()
        target_runner.assert_not_called()
        setup_runner.assert_not_called()

    def test_ack_does_not_skip_the_generic_prompt(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """The dedicated flag is additive. It must not stand in for --yes."""
        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--acknowledge-gm-ddr-read-write",
                "gm-ddr.KEX",
            ],
        )

        main_flash()

        assert runner.call_args.args[0].acknowledge_gm_ddr_read_write is True
        assert runner.call_args.args[0].skip_prompt is False

    def test_ack_defaults_off(self, monkeypatch: MonkeyPatch) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "gm-ddr.KEX"],
        )

        main_flash()

        assert runner.call_args.args[0].acknowledge_gm_ddr_read_write is False

    def test_artifact_is_allowlisted_for_a_real_write(self) -> None:
        """The pinned plaintext hash must be admitted for a real write.

        It must also carry a label naming the patch so the operator sees what
        they are writing.
        """
        label = cli._AUDITED_PLAINTEXT_KEX_SHA256.get(
            cli._NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256
        )
        assert label == "TH-D75 V1.03 normal-gm-ddr-read"

    def test_pinned_hash_matches_the_patch_manifest(self) -> None:
        """The flasher's allowlist entry and the patch manifest must not drift apart.

        If they do, the flasher would admit an artifact the manifest no longer
        produces.
        """
        manifest = load_patch("normal-gm-ddr-read")
        assert manifest.result_kex_sha256 == cli._NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256


class TestGmNorReadWriteAck:
    """The NOR reader has its own exact-artifact gate and fast flash plan."""

    FLAG = "--acknowledge-gm-nor-read-write"

    def test_flag_is_documented(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 0
        # argparse may wrap immediately after a hyphen in long prose.
        help_text = " ".join(capsys.readouterr().out.split()).replace("- ", "-")
        assert self.FLAG in help_text
        assert "normal-gm-nor-read" in help_text
        assert "verified stock restore" in help_text
        assert "one-byte NOR-base delta" in help_text
        assert "bounded gm-nor-check" in help_text
        assert "usb_apply_trigger attest-trigger" in help_text
        assert "one-shot qualify action" in help_text
        assert "ABI-3 byte-exact qualifier" in help_text
        assert "changed-context refusal" in help_text
        assert "command-4 zero-prefix refusal" in help_text
        assert "atomic-991 route canary" in help_text
        assert "above 1FFFFF" in help_text
        assert "replaces the GM GPS-mode command" in help_text

    @pytest.mark.parametrize(
        "mode_args",
        [
            ["--probe-only", "--port", "unused"],
            ["--probe-target", "--port", "unused"],
            ["--setup-controls-only", "--port", "unused"],
            [
                "--setup-mismatch-repeat-only",
                "--allow-unproven-setup-repeat",
                "--port",
                "unused",
            ],
            ["--dry-run", "unused.KEX"],
            ["--raw", "--port", "unused", "unused.bin"],
        ],
    )
    def test_ack_rejected_outside_real_kex_write(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        mode_args: list[str],
    ) -> None:

        flash_runner = MagicMock()
        probe_runner = MagicMock()
        target_runner = MagicMock()
        setup_runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", flash_runner)
        monkeypatch.setattr(cli, "_run_flash_probe", probe_runner)
        monkeypatch.setattr(cli, "_run_flash_probe_target", target_runner)
        monkeypatch.setattr(cli, "_run_setup_calibration", setup_runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", *mode_args, self.FLAG],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert (
            "valid only for a real write of the exact normal-gm-nor-read"
            in capsys.readouterr().err
        )
        flash_runner.assert_not_called()
        probe_runner.assert_not_called()
        target_runner.assert_not_called()
        setup_runner.assert_not_called()

    def test_ack_does_not_skip_the_generic_prompt(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                self.FLAG,
                "gm-nor.KEX",
            ],
        )

        main_flash()

        assert runner.call_args.args[0].acknowledge_gm_nor_read_write is True
        assert runner.call_args.args[0].skip_prompt is False

    def test_ack_defaults_off(self, monkeypatch: MonkeyPatch) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "gm-nor.KEX"],
        )

        main_flash()

        assert runner.call_args.args[0].acknowledge_gm_nor_read_write is False

    def test_exact_hash_label_and_manifest_pin(
        self,
        real_normal_gm_nor_kex_path: Path,
    ) -> None:

        expected = "f619fbb6b6fd91ad5bcdaf85bcc3bcd31483564fc5a5643aad73ce5915f5f30e"
        assert expected == cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256
        assert (
            cli._AUDITED_PLAINTEXT_KEX_SHA256[expected]
            == "TH-D75 V1.03 normal-gm-nor-read"
        )
        assert load_patch("normal-gm-nor-read").result_kex_sha256 == expected
        assert (
            hashlib.sha256(real_normal_gm_nor_kex_path.read_bytes()).hexdigest()
            == expected
        )

    def test_usb_recovery_v18_is_pinned_and_obsolete_variants_stay_excluded(
        self,
    ) -> None:
        """The qualified V18 stays admitted while obsolete builds remain out."""
        expected = "257a93cbefb843c61676e5ca61e03ce4bc72b071658c936757f89477f1fa792a"
        obsolete_v9_telemetry = (
            "488bf816c9baee34d379055e04d25a99170345f51df7cd88d577cc8df3f6c5ab"
        )
        obsolete_apply = (
            "e9c2ae0d07e625bfd45bb66786897025c38d4b68878ae3f8782f8faf325f332e"
        )
        obsolete_recovery = (
            "c99063f58622cfc6ca30b003210c89390d87e13635fa46c34c1c039d7a22cda4"
        )
        obsolete_cleanup_gate = (
            "a402a315b08b2bdf76d6045019af1f35103656a3846f03bc950c661323801e51"
        )
        obsolete_v14 = (
            "9c77fd7186161c7f984b613968d00dee5357681baca8282e9b40c642fc95c3e9"
        )
        obsolete_v17 = (
            "41f3dec1cd5d9b8934d445bf5aaf4aed43769b627afc710b820c5d25914b3e4a"
        )
        manifest = load_patch("normal-gm-nor-read-usb-recover")

        assert expected == cli._NORMAL_GM_NOR_USB_RECOVER_PLAINTEXT_KEX_SHA256
        assert expected in cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY
        assert expected in cli._NORMAL_GM_FAST_PLAINTEXT_KEX_SHA256
        assert (
            cli._AUDITED_PLAINTEXT_KEX_SHA256[expected]
            == "TH-D75 V1.03 normal-gm-nor-read-usb-recover V18"
        )
        assert manifest.source_sha256 == (
            "2eddf487e985861c95fb4212d0f7eabfb57c648eee06f3141819582226fd6ea0"
        )
        assert manifest.result_sha256 == (
            "239128bca8f608398dc23865c336bd48a00484ea598202a000fd9f5647aa92a6"
        )
        assert manifest.result_kex_sha256 == expected
        for rejected in (
            obsolete_v9_telemetry,
            obsolete_apply,
            obsolete_recovery,
            obsolete_cleanup_gate,
            obsolete_v14,
            obsolete_v17,
        ):
            assert rejected not in cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY
            assert rejected not in cli._NORMAL_GM_FAST_PLAINTEXT_KEX_SHA256
            assert rejected not in cli._AUDITED_PLAINTEXT_KEX_SHA256
        assert load_patch("normal-gm-nor-read").result_kex_sha256 == (
            cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256
        )

    def test_azimuth_with_orange_on_black_is_classified_as_azimuth(self) -> None:
        composite = cli._AZIMUTH_ORANGE_ON_BLACK_PLAINTEXT_KEX_SHA256
        # Membership selects the ABI-3 qualifier over gm-nor-check.
        assert composite in cli._RADIO_AUTOMATION_PLAINTEXT_KEX_SHA256_FAMILY
        assert composite in cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY
        assert composite in cli._AUDITED_PLAINTEXT_KEX_SHA256

    def test_azimuth_variant_is_pinned_and_uses_fast_family(
        self,
    ) -> None:

        expected = "6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d"
        manifest = load_patch("normal-gm-nor-read-usb-recover-azimuth")

        assert expected == cli._AZIMUTH_PLAINTEXT_KEX_SHA256
        assert expected in cli._RADIO_AUTOMATION_PLAINTEXT_KEX_SHA256_FAMILY
        assert expected in cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY
        assert expected in cli._NORMAL_GM_FAST_PLAINTEXT_KEX_SHA256
        assert (
            cli._AUDITED_PLAINTEXT_KEX_SHA256[expected]
            == "TH-D75 V1.03.AZM Azimuth automation"
        )
        assert manifest.source_sha256 == (
            "239128bca8f608398dc23865c336bd48a00484ea598202a000fd9f5647aa92a6"
        )
        assert manifest.result_sha256 == (
            "e4ee2338b0483acfc4fea2d7cb7805aacf1fdfe2102b2f2252d19e750dfc1c29"
        )
        assert manifest.result_kex_sha256 == expected

    def test_ack_rejects_mismatched_audited_artifacts_before_io(
        self,
        real_normal_gm_ddr_kex_path: Path,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        stock_path = tmp_path / "stock.KEX"
        _ = stock_path.write_bytes(real_stock_plaintext_kex)
        reference_transport = MagicMock(
            side_effect=AssertionError("mismatched NOR ack opened transport")
        )
        legacy_transport = MagicMock(
            side_effect=AssertionError("mismatched NOR ack opened legacy transport")
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            reference_transport,
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy_transport)

        cases: tuple[tuple[Path, list[str]], ...] = (
            (stock_path, []),
            (
                real_normal_gm_ddr_kex_path,
                ["--acknowledge-gm-ddr-read-write"],
            ),
        )
        for image_path, sibling_ack in cases:
            monkeypatch.setattr(
                sys,
                "argv",
                [
                    "thd75-flash",
                    "--port",
                    "unused",
                    "--yes",
                    "--cleartext",
                    *sibling_ack,
                    self.FLAG,
                    str(image_path),
                ],
            )

            with pytest.raises(SystemExit) as exc_info:
                main_flash()

            assert exc_info.value.code == 2
            assert (
                "valid only for a real write of the exact normal-gm-nor-read"
                in capsys.readouterr().err
            )

        reference_transport.assert_not_called()
        legacy_transport.assert_not_called()

    def test_exact_real_write_requires_ack_before_io_even_with_yes(
        self,
        real_normal_gm_nor_kex_path: Path,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        reference_transport = MagicMock(
            side_effect=AssertionError("unacknowledged NOR write opened transport")
        )
        legacy_transport = MagicMock(
            side_effect=AssertionError(
                "unacknowledged NOR write opened legacy transport"
            )
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            reference_transport,
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy_transport)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                str(real_normal_gm_nor_kex_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "requires --acknowledge-gm-nor-read-write" in err
        assert "one-byte base delta" in err
        assert "bounded gm-nor-check" in err
        assert "offsets above 1FFFFF" in err
        assert "--yes does not satisfy this dedicated gate" in err
        reference_transport.assert_not_called()
        legacy_transport.assert_not_called()

    def test_usb_recovery_write_gate_names_the_one_shot_qualification(
        self,
        real_normal_gm_nor_kex_path: Path,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        """The family gate must not prescribe the base NOR check for V18."""
        monkeypatch.setattr(
            cli,
            "_NORMAL_GM_NOR_USB_RECOVER_PLAINTEXT_KEX_SHA256",
            cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256,
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            MagicMock(side_effect=AssertionError("write gate opened transport")),
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                str(real_normal_gm_nor_kex_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "usb_apply_trigger attest-trigger" in err
        assert "one-shot qualify action" in err

        assert "bounded gm-nor-check" not in err

    def test_azimuth_write_gate_names_live_canaries_before_any_transport(
        self,
        real_normal_gm_nor_kex_path: Path,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        """The dynamic family gate must prescribe Azimuth's live evidence."""
        monkeypatch.setattr(
            cli,
            "_RADIO_AUTOMATION_PLAINTEXT_KEX_SHA256_FAMILY",
            frozenset({cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256}),
        )
        reference_transport = MagicMock(
            side_effect=AssertionError("Azimuth write gate opened reference transport")
        )
        legacy_transport = MagicMock(
            side_effect=AssertionError("Azimuth write gate opened legacy transport")
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            reference_transport,
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy_transport)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--cleartext",
                str(real_normal_gm_nor_kex_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "ABI-3 byte-exact Azimuth automation qualifier" in err
        assert "missing-snapshot" in err
        assert "changed-context" in err
        assert "command-4 zero-prefix" in err
        assert "atomic-991 route" in err
        assert "bounded gm-nor-check" not in err
        reference_transport.assert_not_called()
        legacy_transport.assert_not_called()

    def test_exact_acknowledged_write_uses_six_segment_fast_plan(
        self,
        real_normal_gm_nor_kex_path: Path,
        monkeypatch: MonkeyPatch,
    ) -> None:

        transport = object()
        serial_context = MagicMock()
        serial_context.__enter__.return_value = transport
        serial_constructor = MagicMock(return_value=serial_context)
        session = MagicMock()
        session.flash_segments.return_value = FlashOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            segments_written=3,
            bytes_written=2_621_474,
            elapsed_seconds=0.0,
        )
        session_constructor = MagicMock(return_value=session)
        session_constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
        session_constructor.validate_plan = FlashSession.validate_plan
        listener = object()
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(side_effect=AssertionError("legacy transport was opened")),
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            serial_constructor,
        )
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            flash_ui,
            "RichProgressListener",
            MagicMock(return_value=listener),
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--no-post-hint",
                "--cleartext",
                self.FLAG,
                str(real_normal_gm_nor_kex_path),
            ],
        )

        main_flash()

        serial_constructor.assert_called_once_with(
            "unused",
            baud=576_000,
            options=flash_serial_io.ReferenceSerialOptions(reassert_read_timeout=False),
        )
        flash_call = session.flash_segments.call_args
        descriptors = flash_call.args[0]
        payloads = flash_call.args[1]
        assert [descriptor.flash_start_addr for descriptor in descriptors] == [
            0x6020_0000,
            0x6060_0000,
            0x60E0_0000,
            0x6150_0000,
            0x6020_0062,
            0x6020_0040,
        ]
        assert 0x6160_0000 not in {
            descriptor.flash_start_addr for descriptor in descriptors
        }
        assert len(descriptors) == len(payloads) == 6
        assert set(payloads) == set(range(6))
        assert sum(descriptor.data_length for descriptor in descriptors) == 4_784_162
        run_options = flash_call.args[2]
        assert run_options.always_flash is False
        assert run_options.force_segment_indices == frozenset()
        assert run_options.complete_update_value == 0x1DB0
        assert run_options.complete_update_width == 4

    def test_dry_run_fast_plan_vs_force_all_seven_segments(
        self,
        real_normal_gm_nor_kex_path: Path,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        serial_constructor = MagicMock(
            side_effect=AssertionError("NOR dry-run opened a serial device")
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", serial_constructor)
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            serial_constructor,
        )

        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--dry-run", str(real_normal_gm_nor_kex_path)],
        )
        main_flash()
        fast_output = capsys.readouterr().err
        fast_segments = [
            line for line in fast_output.splitlines() if line.startswith("  Segment ")
        ]
        assert "Audited KEX artifact: TH-D75 V1.03 normal-gm-nor-read" in fast_output
        assert "Fast plan:" in fast_output
        assert "Host omission:" in fast_output
        assert len(fast_segments) == 6
        assert "Segment 3 (original source segment 4)" in fast_output
        assert "start=0x61600000" not in fast_output

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--dry-run",
                "--force-all-segments",
                str(real_normal_gm_nor_kex_path),
            ],
        )
        main_flash()
        force_output = capsys.readouterr().err
        force_segments = [
            line for line in force_output.splitlines() if line.startswith("  Segment ")
        ]
        assert "Force policy: write every segment" in force_output
        assert "Fast plan:" not in force_output
        assert "Host omission:" not in force_output
        assert len(force_segments) == 7
        assert "Segment 3: start=0x61600000" in force_output
        serial_constructor.assert_not_called()


class TestNormalGmFastFlashPlan:
    """The update-only fast plan omits exactly the pinned DATA_0160 source."""

    def test_exact_artifact_prunes_only_source_three_and_preserves_mapping(
        self,
        real_normal_gm_flash_plan: tuple[
            str,
            list[SegmentDescriptor],
            dict[int, bytes],
        ],
    ) -> None:

        rendered_sha256, segments, segment_data = real_normal_gm_flash_plan
        assert rendered_sha256 == cli._NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256
        assert len(segments) == 7
        assert segments[3].flash_start_addr == 0x6160_0000
        assert segments[3].data_length == 10_485_760

        pruned_segments, pruned_data, source_indices = cli._normal_gm_fast_flash_plan(
            rendered_plaintext_sha256=rendered_sha256,
            segments=segments,
            segment_data=segment_data,
        )

        assert source_indices == (0, 1, 2, 4, 5, 6)
        assert set(range(7)).difference(source_indices) == {3}
        assert pruned_segments == [segments[index] for index in source_indices]
        assert set(pruned_data) == set(range(6))
        for plan_index, source_index in enumerate(source_indices):
            assert pruned_data[plan_index] is segment_data[source_index]
        # Original source segment 4 becomes plan segment 3; data and descriptor
        # must move together when the mapping is reindexed.
        assert pruned_segments[3] == segments[4]
        assert pruned_data[3] is segment_data[4]
        assert sum(descriptor.data_length for descriptor in pruned_segments) == (
            4_784_162
        )

    def test_helper_accepts_all_exact_normal_gm_hashes(
        self,
        real_normal_gm_flash_plan: tuple[
            str,
            list[SegmentDescriptor],
            dict[int, bytes],
        ],
    ) -> None:

        _, segments, segment_data = real_normal_gm_flash_plan
        for rendered_sha256 in (
            cli._NORMAL_GM_DDR_PLAINTEXT_KEX_SHA256,
            *cli._NORMAL_GM_NOR_PLAINTEXT_KEX_SHA256_FAMILY,
        ):
            pruned_segments, pruned_data, source_indices = (
                cli._normal_gm_fast_flash_plan(
                    rendered_plaintext_sha256=rendered_sha256,
                    segments=segments,
                    segment_data=segment_data,
                )
            )
            assert source_indices == (0, 1, 2, 4, 5, 6)
            assert len(pruned_segments) == len(pruned_data) == 6

    def test_changed_data_0160_descriptor_fails_closed(
        self,
        real_normal_gm_flash_plan: tuple[
            str,
            list[SegmentDescriptor],
            dict[int, bytes],
        ],
        capsys: CaptureFixture[str],
    ) -> None:

        rendered_sha256, segments, segment_data = real_normal_gm_flash_plan
        changed_segments = list(segments)
        changed_segments[3] = replace(
            segments[3],
            erase_wait_seconds=segments[3].erase_wait_seconds + 1,
        )

        with pytest.raises(SystemExit) as exc_info:
            _ = cli._normal_gm_fast_flash_plan(
                rendered_plaintext_sha256=rendered_sha256,
                segments=changed_segments,
                segment_data=segment_data,
            )

        assert exc_info.value.code == 2
        assert "refuses changed DATA_0160 descriptor" in capsys.readouterr().err

    def test_changed_data_0160_payload_fails_closed(
        self,
        real_normal_gm_flash_plan: tuple[
            str,
            list[SegmentDescriptor],
            dict[int, bytes],
        ],
        capsys: CaptureFixture[str],
    ) -> None:

        rendered_sha256, segments, segment_data = real_normal_gm_flash_plan
        changed_data = dict(segment_data)
        payload = segment_data[3]
        changed_data[3] = bytes((payload[0] ^ 0x01,)) + payload[1:]

        with pytest.raises(SystemExit) as exc_info:
            _ = cli._normal_gm_fast_flash_plan(
                rendered_plaintext_sha256=rendered_sha256,
                segments=segments,
                segment_data=changed_data,
            )

        assert exc_info.value.code == 2
        assert "refuses changed DATA_0160 payload" in capsys.readouterr().err

    @pytest.mark.parametrize("payload_index_fault", ["missing", "extra"])
    def test_inexact_payload_index_set_fails_closed(
        self,
        real_normal_gm_flash_plan: tuple[
            str,
            list[SegmentDescriptor],
            dict[int, bytes],
        ],
        capsys: CaptureFixture[str],
        payload_index_fault: str,
    ) -> None:

        rendered_sha256, segments, segment_data = real_normal_gm_flash_plan
        changed_data = dict(segment_data)
        if payload_index_fault == "missing":
            del changed_data[6]
        else:
            changed_data[7] = b""

        with pytest.raises(SystemExit) as exc_info:
            _ = cli._normal_gm_fast_flash_plan(
                rendered_plaintext_sha256=rendered_sha256,
                segments=segments,
                segment_data=changed_data,
            )

        assert exc_info.value.code == 2
        assert "payloads for exactly source segments 0..6" in (capsys.readouterr().err)


class TestSkipUnchangedSegments:
    """Matching segments are skipped by default via the loader's SETUP answer.

    This uses the loader's own SETUP equality answer. It matches OpenWood,
    whose ``program_segment`` defaults
    ``skip_if_current=True``, and it is where nearly all the wall-clock goes:
    over USB CDC the transfer is bounded by per-packet ACK round trips, not by
    the nominal baud, so rewriting already-correct segments costs minutes for
    nothing. Skipping adds no traffic; SETUP is sent per segment either way.
    Dry-run can model the vendor force policy, but hardware writes are locked to
    the successful skip-current profile.
    """

    def test_override_flag_is_documented(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 0
        help_text = " ".join(capsys.readouterr().out.split())
        assert "--force-all-segments" in help_text
        assert "Dry-run only" in help_text
        assert "#AF=1" in help_text
        assert "skip matching segments" in help_text

    def test_skipping_is_the_default(self, monkeypatch: MonkeyPatch) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys, "argv", ["thd75-flash", "--port", "unused", "some.KEX"]
        )

        main_flash()

        assert runner.call_args.args[0].force_all_segments is False

    def test_dry_run_force_flag_reaches_the_runner(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--dry-run", "--force-all-segments", "some.KEX"],
        )

        main_flash()

        assert runner.call_args.args[0].force_all_segments is True
        assert runner.call_args.args[0].dry_run is True

    def test_real_write_rejects_force_flag_before_port_resolution(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:

        port_resolver = MagicMock(
            side_effect=AssertionError("force policy reached USB-port resolution")
        )
        runner = MagicMock(
            side_effect=AssertionError("force policy reached flash runner")
        )
        monkeypatch.setattr(cli, "_require_fldm_usb_port", port_resolver)
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "--force-all-segments", "some.KEX"],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "--force-all-segments is valid only with --dry-run" in (
            capsys.readouterr().err
        )
        port_resolver.assert_not_called()
        runner.assert_not_called()

    def test_direct_runner_rejects_force_flag_before_transport_open(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:

        reference_transport = MagicMock(
            side_effect=AssertionError("force policy opened reference transport")
        )
        legacy_transport = MagicMock(
            side_effect=AssertionError("force policy opened legacy transport")
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            reference_transport,
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy_transport)

        with pytest.raises(SystemExit) as exc_info:
            cli._run_flash(
                cli._FlashRequest(
                    input_path=Path("unread.KEX"),
                    port="unused",
                    baud_ladder_text=None,
                    skip_prompt=True,
                    dry_run=False,
                    show_post_hint=False,
                    chunk_size=256,
                    raw=False,
                    flash_addr=None,
                    cleartext_unlock=True,
                    cleartext_baud=576_000,
                    force_all_segments=True,
                    reference_transport=True,
                )
            )

        assert exc_info.value.code == 2
        assert "proven skip-current policy" in capsys.readouterr().err
        reference_transport.assert_not_called()
        legacy_transport.assert_not_called()


class TestStockImageDataQualification:
    FLAG = "--qualification-rewrite-stock-image-data"

    def test_help_marks_the_flag_as_hardware_qualification_only(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 0
        help_text = " ".join(capsys.readouterr().out.split())
        assert self.FLAG in help_text
        assert "HARDWARE QUALIFICATION ONLY" in help_text
        assert "exact audited stock V1.03 KEX" in help_text
        assert "Requires a new --wire-trace path" in help_text
        assert "does not imply --yes" in help_text

    @pytest.mark.parametrize(
        ("extra_args", "error_text"),
        [
            (["--dry-run", "--wire-trace", "new.trace"], "valid only for a real write"),
            (
                ["--raw", "--wire-trace", "new.trace"],
                "valid only for a real write",
            ),
            (
                ["--force-all-segments", "--wire-trace", "new.trace"],
                "conflicts with --force-all-segments",
            ),
            ([], "requires --wire-trace with a new evidence path"),
        ],
    )
    def test_argument_gates_fail_before_port_resolution(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        extra_args: list[str],
        error_text: str,
    ) -> None:

        port_resolver = MagicMock(
            side_effect=AssertionError("qualification gate reached USB-port resolution")
        )
        runner = MagicMock(
            side_effect=AssertionError("qualification gate reached flash runner")
        )
        monkeypatch.setattr(cli, "_require_fldm_usb_port", port_resolver)
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                self.FLAG,
                *extra_args,
                "some.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert error_text in capsys.readouterr().err
        port_resolver.assert_not_called()
        runner.assert_not_called()

    def test_existing_trace_is_rejected_before_port_resolution(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:

        trace_path = tmp_path / "retained.trace"
        _ = trace_path.write_text("prior evidence\n", encoding="utf-8")
        port_resolver = MagicMock(
            side_effect=AssertionError("existing trace reached USB-port resolution")
        )
        monkeypatch.setattr(cli, "_require_fldm_usb_port", port_resolver)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                self.FLAG,
                "--wire-trace",
                str(trace_path),
                "some.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "refuses to replace existing --wire-trace evidence" in (
            capsys.readouterr().err
        )
        assert trace_path.read_text(encoding="utf-8") == "prior evidence\n"
        port_resolver.assert_not_called()

    def test_flag_is_authorization_but_does_not_imply_yes(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        trace_path = tmp_path / "qualification.trace"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                self.FLAG,
                "--wire-trace",
                str(trace_path),
                "some.KEX",
            ],
        )

        main_flash()

        assert runner.call_args.args[0].qualification_rewrite_stock_image_data is True
        assert runner.call_args.args[0].skip_prompt is False
        assert runner.call_args.args[0].reference_transport is True
        assert runner.call_args.args[0].wire_trace_path == trace_path

    def test_nonstock_artifact_fails_after_parse_before_prompt_or_transport(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:

        image_path = tmp_path / "service-9r.KEX"
        _ = image_path.write_bytes(real_9r_plaintext_kex)
        trace_path = tmp_path / "qualification.trace"
        prompt = MagicMock(
            side_effect=AssertionError("nonstock qualification reached prompt")
        )
        reference_transport = MagicMock(
            side_effect=AssertionError("nonstock qualification opened transport")
        )
        monkeypatch.setattr("builtins.input", prompt)
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            reference_transport,
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--cleartext",
                self.FLAG,
                "--wire-trace",
                str(trace_path),
                str(image_path),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "requires the exact audited stock V1.03 rendered KEX hash" in err
        assert cli._OFFICIAL_V103_PLAINTEXT_KEX_SHA256 in err
        prompt.assert_not_called()
        reference_transport.assert_not_called()
        assert not trace_path.exists()

    def test_post_parse_validator_pins_layout_payload_and_target(
        self,
        real_stock_plaintext_kex: bytes,
        capsys: CaptureFixture[str],
    ) -> None:

        image = kex.parse_kex_bytes(real_stock_plaintext_kex)
        segments = [SegmentDescriptor.from_kex_block(block) for block in image.blocks]
        segment_data = {
            index: intel_hex.parse(block.records).data
            for index, block in enumerate(image.blocks)
        }

        target = cli._stock_image_data_qualification_target(
            rendered_plaintext_sha256=cli._OFFICIAL_V103_PLAINTEXT_KEX_SHA256,
            segments=segments,
            segment_data=segment_data,
            chunk_size=256,
        )
        assert target == (
            "segment 1 IMAGE_DATA: 360448 bytes, 1408 packets, "
            "payload_sha256="
            "cd86abd837cd8cdf2b781148eec52d9cb39ce11f8b6b7d13e2f380669d652fb2"
        )

        with pytest.raises(SystemExit):
            _ = cli._stock_image_data_qualification_target(
                rendered_plaintext_sha256=cli._OFFICIAL_V103_PLAINTEXT_KEX_SHA256,
                segments=segments[:-1],
                segment_data=segment_data,
                chunk_size=256,
            )
        assert "requires the exact 7-segment stock V1.03 layout" in (
            capsys.readouterr().err
        )

        wrong_layout = list(segments)
        wrong_layout[1] = replace(segments[1], erase_length=393_215)
        with pytest.raises(SystemExit):
            _ = cli._stock_image_data_qualification_target(
                rendered_plaintext_sha256=cli._OFFICIAL_V103_PLAINTEXT_KEX_SHA256,
                segments=wrong_layout,
                segment_data=segment_data,
                chunk_size=256,
            )
        assert "erase_length=393216" in capsys.readouterr().err

        wrong_payloads = dict(segment_data)
        wrong_payloads[1] = bytes([segment_data[1][0] ^ 0x01]) + segment_data[1][1:]
        with pytest.raises(SystemExit):
            _ = cli._stock_image_data_qualification_target(
                rendered_plaintext_sha256=cli._OFFICIAL_V103_PLAINTEXT_KEX_SHA256,
                segments=segments,
                segment_data=wrong_payloads,
                chunk_size=256,
            )
        assert "requires retained IMAGE_DATA payload SHA-256" in (
            capsys.readouterr().err
        )

    def test_exact_stock_qualification_propagates_only_segment_one(
        self,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:

        image_path = tmp_path / "stock.KEX"
        _ = image_path.write_bytes(real_stock_plaintext_kex)
        trace_path = tmp_path / "qualification.trace"
        transport = object()
        serial_context = MagicMock()
        serial_context.__enter__.return_value = transport
        serial_constructor = MagicMock(return_value=serial_context)
        session = MagicMock()
        session.flash_segments.return_value = FlashOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            segments_written=1,
            bytes_written=360_448,
            elapsed_seconds=0.0,
        )
        session_constructor = MagicMock(return_value=session)
        session_constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
        session_constructor.validate_plan = FlashSession.validate_plan
        listener = object()
        monkeypatch.setattr(
            flash_serial_io,
            "SerialIO",
            MagicMock(side_effect=AssertionError("legacy transport was opened")),
        )
        monkeypatch.setattr(
            flash_serial_io,
            "ReferenceSerialIO",
            serial_constructor,
        )
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            flash_ui,
            "RichProgressListener",
            MagicMock(return_value=listener),
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--no-post-hint",
                "--cleartext",
                self.FLAG,
                "--wire-trace",
                str(trace_path),
                str(image_path),
            ],
        )

        main_flash()

        serial_constructor.assert_called_once_with(
            "unused",
            baud=576_000,
            options=flash_serial_io.ReferenceSerialOptions(reassert_read_timeout=False),
        )
        flash_call = session.flash_segments.call_args
        run_options = flash_call.args[2]
        assert run_options.always_flash is False
        assert run_options.force_segment_indices == frozenset({1})
        assert run_options.complete_update_width == 4
        assert run_options.cleartext_unlock is True
        assert run_options.cleartext_baud == 576_000
        trace_text = trace_path.read_text(encoding="utf-8")
        assert "#   qualification        : stock-selective-image-data" in trace_text
        assert "#   forced_segments      : 1" in trace_text
        assert (
            "#   qualification_target : segment 1 IMAGE_DATA: 360448 bytes, "
            "1408 packets, payload_sha256="
            "cd86abd837cd8cdf2b781148eec52d9cb39ce11f8b6b7d13e2f380669d652fb2"
            in trace_text
        )


class TestReferenceTransportSelection:
    """Real writes default to the direct-open hardware-proven transport."""

    def test_real_write_default_is_on(self, monkeypatch: MonkeyPatch) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys, "argv", ["thd75-flash", "--port", "unused", "some.KEX"]
        )

        main_flash()

        assert runner.call_args.args[0].reference_transport is True

    def test_flag_reaches_the_runner(self, monkeypatch: MonkeyPatch) -> None:

        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--cleartext",
                "--reference-transport",
                "some.KEX",
            ],
        )

        main_flash()

        assert runner.call_args.args[0].reference_transport is True

    @pytest.mark.parametrize("probe_flag", ["--probe-only", "--probe-target"])
    def test_baud_ladder_probe_modes_are_refused(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        probe_flag: str,
    ) -> None:
        """Those modes walk the ladder, which the reference transport refuses."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                probe_flag,
                "--reference-transport",
                "--port",
                "unused",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "--reference-transport cannot be combined" in err
        assert "baud ladder" in err

    def test_encrypted_unlock_path_is_refused(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        """Without ``--cleartext`` the session ladders, so fail before opening."""
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "--reference-transport", "some.KEX"],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "--reference-transport requires --cleartext" in capsys.readouterr().err

    def test_setup_calibration_opens_the_reference_transport_at_576000(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """The cheapest hardware A/B available: no NOR-write verb is sent."""
        legacy = MagicMock(side_effect=AssertionError("legacy transport was opened"))
        reference = MagicMock()
        reference.return_value.__enter__.return_value = object()
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy)
        monkeypatch.setattr(flash_serial_io, "ReferenceSerialIO", reference)
        session = MagicMock()
        session.calibrate_setup_controls_only.return_value = SetupCalibrationOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            setup_results=(0, 0, 0),
        )
        monkeypatch.setattr(
            flash_session,
            "FlashSession",
            MagicMock(return_value=session),
        )

        cli._run_setup_calibration(
            "/dev/cu.usbmodem-test",
            mismatch_repeat=False,
            reference_transport=True,
        )

        reference.assert_called_once_with(
            "/dev/cu.usbmodem-test",
            baud=576_000,
            options=flash_serial_io.ReferenceSerialOptions(reassert_read_timeout=False),
        )

    def test_setup_calibration_default_opens_the_normal_transport(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Absent the flag, nothing about the existing transport changes."""
        legacy = MagicMock()
        legacy.return_value.__enter__.return_value = object()
        reference = MagicMock(
            side_effect=AssertionError("reference transport opened without the flag"),
        )
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy)
        monkeypatch.setattr(flash_serial_io, "ReferenceSerialIO", reference)
        session = MagicMock()
        session.calibrate_setup_controls_only.return_value = SetupCalibrationOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            setup_results=(0, 0, 0),
        )
        monkeypatch.setattr(
            flash_session,
            "FlashSession",
            MagicMock(return_value=session),
        )

        cli._run_setup_calibration("/dev/cu.usbmodem-test", mismatch_repeat=False)

        legacy.assert_called_once_with(
            "/dev/cu.usbmodem-test",
            baud=576_000,
            timeout=1.0,
        )

    def test_flash_opens_the_reference_transport_at_the_cleartext_baud(
        self,
        real_9r_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The load-bearing difference, end to end through ``main_flash``.

        The default path opens at 9600 and lets the session raise the rate,
        and on macOS ``Serial.baudrate = 576000`` reconfigures a live CDC port
        (``tcsetattr`` to B38400, then ``IOSSIOSPEED``). Opening at the
        operating baud leaves the session's request nothing to do.
        """
        image_path = tmp_path / "service-9r.KEX"
        _ = image_path.write_bytes(real_9r_plaintext_kex)
        transport = object()
        legacy = MagicMock(side_effect=AssertionError("legacy transport was opened"))
        reference_context = MagicMock()
        reference_context.__enter__.return_value = transport
        reference = MagicMock(return_value=reference_context)
        session = MagicMock()
        session.flash_segments.return_value = FlashOutcome(
            target=TargetInfo(
                raw_payload=b"\x00" * 17,
                target_mask_bytes=b"\x00" * 8,
                opaque_bytes_8_15=b"\x00" * 8,
                trailing_status=0,
            ),
            segments_written=7,
            bytes_written=2_621_440,
            elapsed_seconds=0.0,
        )
        session_constructor = MagicMock(return_value=session)
        session_constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
        session_constructor.validate_plan = FlashSession.validate_plan
        monkeypatch.setattr(flash_serial_io, "SerialIO", legacy)
        monkeypatch.setattr(flash_serial_io, "ReferenceSerialIO", reference)
        monkeypatch.setattr(flash_session, "FlashSession", session_constructor)
        monkeypatch.setattr(
            flash_ui, "RichProgressListener", MagicMock(return_value=object())
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--yes",
                "--no-post-hint",
                "--cleartext",
                "--reference-transport",
                "--acknowledge-service-9r-write",
                str(image_path),
            ],
        )

        main_flash()

        reference.assert_called_once_with(
            "unused",
            baud=576_000,
            options=flash_serial_io.ReferenceSerialOptions(reassert_read_timeout=False),
        )
        session.flash_segments.assert_called_once()
        assert session.flash_segments.call_args.args[2].cleartext_baud == 576_000


class TestWireTraceInputAlias:
    """A wire trace opens with truncation, so it must never alias the input."""

    @staticmethod
    def _alias(kind: str, image: Path, tmp_path: Path) -> Path:
        """Return a trace path that reaches ``image`` in the named way."""
        if kind == "same":
            return image
        alias = tmp_path / f"trace-{kind}.trace"
        if kind == "symlink":
            alias.symlink_to(image)
        else:
            alias.hardlink_to(image)
        return alias

    @pytest.mark.parametrize("kind", ["same", "symlink", "hardlink"])
    def test_alias_is_rejected_before_port_resolution(
        self,
        kind: str,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image = tmp_path / "input.KEX"
        _ = image.write_bytes(b"input artifact")
        trace = self._alias(kind, image, tmp_path)
        port_resolver = MagicMock(
            side_effect=AssertionError("trace alias reached USB-port resolution")
        )
        monkeypatch.setattr(cli, "_require_fldm_usb_port", port_resolver)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "--wire-trace", str(trace), str(image)],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "refuses to overwrite the input image" in capsys.readouterr().err
        assert image.read_bytes() == b"input artifact"
        port_resolver.assert_not_called()

    @pytest.mark.parametrize("kind", ["same", "symlink", "hardlink"])
    def test_direct_run_flash_rejects_an_alias_before_reading_the_image(
        self,
        kind: str,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image = tmp_path / "input.KEX"
        _ = image.write_bytes(b"input artifact")
        trace = self._alias(kind, image, tmp_path)

        with pytest.raises(SystemExit) as exc_info:
            cli._run_flash(
                cli._FlashRequest(
                    input_path=image,
                    port="/dev/cu.usbmodem-test",
                    baud_ladder_text=None,
                    skip_prompt=True,
                    dry_run=False,
                    show_post_hint=False,
                    chunk_size=256,
                    raw=False,
                    flash_addr=None,
                    cleartext_unlock=True,
                    wire_trace_path=trace,
                )
            )

        assert exc_info.value.code == 2
        assert "refuses to overwrite the input image" in capsys.readouterr().err
        assert image.read_bytes() == b"input artifact"

    def test_a_new_trace_path_is_not_an_alias(self, tmp_path: Path) -> None:
        image = tmp_path / "input.KEX"
        _ = image.write_bytes(b"input artifact")
        assert not cli._names_same_file(tmp_path / "new.trace", image)
