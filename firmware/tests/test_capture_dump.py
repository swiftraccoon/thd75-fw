"""Host-capture preflight regression tests."""

from __future__ import annotations

import io
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, ClassVar
from unittest.mock import patch

import capture_dump
import pytest
import serial

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self, override
else:
    from collections.abc import Callable
    from typing import TypeVar

    _OverrideFunc = TypeVar("_OverrideFunc", bound=Callable[..., object])

    def override(method: _OverrideFunc, /) -> _OverrideFunc:
        """Return *method* unchanged; type checkers read typing_extensions.

        ``typing.override`` exists only on Python 3.12+, so this runtime
        identity decorator lets the standalone tests use ``@override`` while
        the type checkers read the ``typing_extensions`` declaration above.
        """
        return method


class _FakeServiceSerial:
    """Exact in-memory raw CAT link; no serial device is opened."""

    instances: ClassVar[list[_FakeServiceSerial]] = []
    corrupt_second_pass: bool = False
    acknowledge_already_active_entry: bool = False
    reject_entry_response: bool = False
    short_entry_write: bool = False
    reject_first_identity: bool = False
    reject_second_identity: bool = False
    reject_firmware: bool = False
    corrupt_sixteen_byte_read: bool = False
    fail_entry_flush: bool = False
    short_9r_write: bool = False
    fail_close: bool = False

    def __init__(self, **kwargs: object) -> None:
        super().__init__()
        self.kwargs = kwargs
        timeout = kwargs.get("timeout", 1.0)
        if not isinstance(timeout, (int, float)):
            msg = "fake timeout must be numeric"
            raise TypeError(msg)
        self.response_timeout = float(timeout)
        self.writes: list[bytes] = []
        self._response = bytearray()
        self._read_counts: dict[tuple[int, int], int] = {}
        self._identity_count = 0
        type(self).instances.append(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        del exc_type, exc_val, exc_tb
        self.close()

    def close(self) -> None:
        if self.fail_close:
            msg = "close failed"
            raise serial.SerialException(msg)

    def reset_input_buffer(self) -> None:
        self._response.clear()

    def flush(self) -> None:
        if self.fail_entry_flush and self.writes[-1] == capture_dump.SERVICE_ENTER:
            type(self).fail_entry_flush = False
            msg = "entry flush failed"
            raise serial.SerialException(msg)

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        control = self._control_write(data)
        if control is not None:
            return control
        text = data.decode("ascii")
        if not text.startswith("9R ") or not text.endswith("\r"):
            msg = f"unexpected command {data!r}"
            raise AssertionError(msg)
        return self._service_9r_write(data, text)

    def _control_write(self, data: bytes) -> int | None:
        """Answer the exact ID/FV/service verbs; return None for a 9R command."""
        if data == capture_dump.NORMAL_CAT_ID:
            self._identity_count += 1
            reject = (self.reject_first_identity and self._identity_count == 1) or (
                self.reject_second_identity and self._identity_count == 2
            )
            response = b"ID TH-D74\r" if reject else capture_dump.NORMAL_CAT_ID_RESPONSE
            self._response.extend(response)
            return len(data)
        if data == capture_dump.NORMAL_CAT_FV:
            response = (
                b"FV 1.02\r"
                if self.reject_firmware
                else capture_dump.NORMAL_CAT_FV_RESPONSE
            )
            self._response.extend(response)
            return len(data)
        if data == capture_dump.SERVICE_ENTER:
            return self._service_enter_write(data)
        if data == capture_dump.SERVICE_EXIT:
            self._response.extend(data)
            return len(data)
        return None

    def _service_enter_write(self, data: bytes) -> int:
        """Reproduce the stock 0G entry outcomes selected by the test flags."""
        if self.short_entry_write:
            return len(data) - 1
        if self.reject_entry_response:
            self._response.extend(b"?\r")
            return len(data)
        if self.acknowledge_already_active_entry:
            self._response.extend(
                capture_dump.SERVICE_ENTER_ALREADY_ACTIVE_RESPONSE,
            )
        return len(data)

    def _service_9r_write(self, data: bytes, text: str) -> int:
        """Reproduce a bounded 9R read, its rejection, and the corruption flags."""
        if self.short_9r_write:
            return len(data) - 1
        offset_text, length_text = text[3:-1].split(",")
        offset = int(offset_text, 16)
        encoded_length = int(length_text, 16)
        length = 256 if encoded_length == 0 else encoded_length
        if offset + length > capture_dump.SERVICE_WINDOW_LENGTH:
            self._response.extend(b"N\r")
            return len(data)
        read_key = (offset, length)
        count = self._read_counts.get(read_key, 0)
        self._read_counts[read_key] = count + 1
        payload = bytes((offset + index) & 0xFF for index in range(length))
        if self.corrupt_sixteen_byte_read and offset == 0 and length == 16:
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        # The automatic gate performs the first maximum-length offset-zero
        # read, pass 1 the second, and pass 2 the third.
        if (
            self.corrupt_second_pass
            and count >= 2
            and offset == 0
            and length == capture_dump.SERVICE_MAX_READ
        ):
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        response = f"9R {offset:06X},".encode() + payload.hex().upper().encode() + b"\r"
        self._response.extend(response)
        return len(data)

    def read(self, count: int, *, timeout: float | None = None) -> bytes:
        del timeout
        result = bytes(self._response[:count])
        del self._response[:count]
        return result


class _FakeGmSerial:
    """Normal-CAT GM link with exact live-patch and low-NOR responses."""

    instances: ClassVar[list[_FakeGmSerial]] = []
    corrupt_second_pass: bool = False
    corrupt_sixteen_byte_read: bool = False
    corrupt_patch_attestation: bool = False
    corrupt_base_probe: bool = False
    short_gm_error: bytes | None = None
    stale_on_open: bytes = b""

    def __init__(self, **kwargs: object) -> None:
        super().__init__()
        self.kwargs = kwargs
        timeout = kwargs.get("timeout", 1.0)
        if not isinstance(timeout, (int, float)):
            msg = "fake timeout must be numeric"
            raise TypeError(msg)
        self.response_timeout = float(timeout)
        self.writes: list[bytes] = []
        self._response = bytearray(self.stale_on_open)
        self._read_counts: dict[tuple[int, int], int] = {}
        self._gm_response_pending = False
        self.gm_response_read_sizes: list[int] = []
        self.reset_calls = 0
        self.quiet_reads = 0
        type(self).instances.append(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        del exc_type, exc_val, exc_tb

    def close(self) -> None:
        return None

    def reset_input_buffer(self) -> None:
        self.reset_calls += 1
        self._response.clear()

    def flush(self) -> None:
        return None

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        control = self._control_write(data)
        if control is not None:
            return control
        text = data.decode("ascii")
        if not text.startswith("GM ") or not text.endswith("\r"):
            msg = f"unexpected normal-CAT command {data!r}"
            raise AssertionError(msg)
        offset_text, length_text = text[3:-1].split(",")
        offset = int(offset_text, 16)
        encoded_length = int(length_text, 16)
        length = 256 if encoded_length == 0 else encoded_length
        payload = self._gm_payload(offset, length)
        read_key = (offset, length)
        count = self._read_counts.get(read_key, 0)
        self._read_counts[read_key] = count + 1
        payload = self._apply_corruption(
            payload, offset=offset, length=length, count=count
        )
        response = f"GM {offset:06X},".encode() + payload.hex().upper().encode() + b"\r"
        self._response.extend(response)
        self._gm_response_pending = True
        return len(data)

    def _control_write(self, data: bytes) -> int | None:
        """Answer ID/FV, reject service verbs, or queue the short-error reply."""
        if data == capture_dump.NORMAL_CAT_ID:
            self._response.extend(capture_dump.NORMAL_CAT_ID_RESPONSE)
            return len(data)
        if data == capture_dump.NORMAL_CAT_FV:
            self._response.extend(capture_dump.NORMAL_CAT_FV_RESPONSE)
            return len(data)
        if data in (capture_dump.SERVICE_ENTER, capture_dump.SERVICE_EXIT):
            msg = f"normal-GM mode sent service verb {data!r}"
            raise AssertionError(msg)
        if self.short_gm_error is not None:
            self._response.extend(self.short_gm_error)
            self._gm_response_pending = True
            return len(data)
        return None

    def _gm_payload(self, offset: int, length: int) -> bytes:
        """Return the exact base-probe, patch-attestation, or low-NOR bytes."""
        if offset == capture_dump.GM_NOR_BASE_PROBE[0] and length == len(
            capture_dump.GM_NOR_BASE_PROBE[1]
        ):
            return capture_dump.GM_NOR_BASE_PROBE[1]
        for address, expected in capture_dump.GM_NOR_PATCH_ATTESTATIONS:
            if offset == address and length == len(expected):
                return expected
        if offset < 0 or offset + length > capture_dump.GM_NOR_LENGTH:
            msg = f"host transmitted unsafe GM range 0x{offset:06X}+{length}"
            raise AssertionError(msg)
        return bytes((offset + index) & 0xFF for index in range(length))

    def _apply_corruption(
        self, payload: bytes, *, offset: int, length: int, count: int
    ) -> bytes:
        """Flip the first payload byte for whichever corruption flag is set."""
        if (
            self.corrupt_patch_attestation
            and offset == capture_dump.GM_NOR_PATCH_ATTESTATIONS[0][0]
        ):
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        if self.corrupt_base_probe and offset == capture_dump.GM_NOR_BASE_PROBE[0]:
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        if self.corrupt_sixteen_byte_read and offset == 0 and length == 16:
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        # The gate performs the first maximum read, pass 1 the second, and
        # pass 2 the third.
        if (
            self.corrupt_second_pass
            and offset == 0
            and length == capture_dump.GM_MAX_READ
            and count >= 2
        ):
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        return payload

    def read(self, count: int, *, timeout: float | None = None) -> bytes:
        del timeout
        if self._gm_response_pending and self._response:
            self.gm_response_read_sizes.append(count)
        if not self._response and count == 1:
            self.quiet_reads += 1
        result = bytes(self._response[:count])
        del self._response[:count]
        if not self._response:
            self._gm_response_pending = False
        return result


class CaptureHeaderTests(unittest.TestCase):
    """Validate defaults and corruption bounds before any file is written."""

    def test_default_baud_matches_payload(self) -> None:
        """The CLI default must match ``dumper/src/main.rs::BAUD``."""
        args = capture_dump._parse_args(["--port", "loopback"])
        assert args.baud is None
        assert (
            capture_dump._resolve_baud(args.mode, args.transport, args.baud) == 115200
        )

    def test_accepts_low_nor_candidate_range(self) -> None:
        """The candidate two-MiB range fits exactly within NOR."""
        end = capture_dump._validate_dump_range(capture_dump.NOR_BASE, 0x0020_0000)
        assert end == 1612709888

    def test_rejects_empty_dump(self) -> None:
        """A zero length is a corrupt header, not a successful capture."""
        with pytest.raises(capture_dump.CaptureError, match="empty"):
            _ = capture_dump._validate_dump_range(capture_dump.NOR_BASE, 0)

    def test_rejects_range_past_nor(self) -> None:
        """Corrupted length bytes cannot initiate an unbounded capture."""
        with pytest.raises(capture_dump.CaptureError, match="outside"):
            _ = capture_dump._validate_dump_range(capture_dump.NOR_BASE, 0x0200_0001)

    def test_rejects_nonpositive_or_nonfinite_timeout(self) -> None:
        for value in ("0", "-1", "nan", "inf"):
            with self.subTest(value=value), pytest.raises(SystemExit):
                _ = capture_dump._parse_args(
                    ["--port", "loopback", "--timeout", value],
                )

    def test_every_9r_mode_requires_explicit_cat_preflight(self) -> None:
        for mode in ("9r-baseline", "9r-patched-check", "9r-dump"):
            with self.subTest(mode=mode), pytest.raises(SystemExit):
                _ = capture_dump._parse_args(["--port", "loopback", "--mode", mode])
            arguments = [
                "--port",
                "loopback",
                "--mode",
                mode,
                "--acknowledge-cat-preflight",
            ]
            if mode == "9r-baseline":
                arguments.append("--acknowledge-stock-v103-restored")
            args = capture_dump._parse_args(arguments)
            assert args.acknowledge_cat_preflight

    def test_gm_nor_modes_require_both_exact_acknowledgements(self) -> None:
        for mode in ("gm-nor-check", "gm-nor-dump"):
            with self.subTest(mode=mode):
                with pytest.raises(SystemExit):
                    _ = capture_dump._parse_args(["--mode", mode])
                with pytest.raises(SystemExit):
                    _ = capture_dump._parse_args(
                        ["--mode", mode, "--acknowledge-gm-nor-read"],
                    )
                args = capture_dump._parse_args(
                    [
                        "--mode",
                        mode,
                        "--acknowledge-cat-preflight",
                        "--acknowledge-gm-nor-read",
                    ],
                )
                assert args.acknowledge_cat_preflight
                assert args.acknowledge_gm_nor_read

    def test_gm_nor_ack_is_exclusive_and_modes_are_usb_only(self) -> None:
        with pytest.raises(SystemExit):
            _ = capture_dump._parse_args(
                ["--port", "loopback", "--acknowledge-gm-nor-read"],
            )
        with pytest.raises(SystemExit):
            _ = capture_dump._parse_args(
                [
                    "--mode",
                    "gm-nor-check",
                    "--acknowledge-cat-preflight",
                    "--acknowledge-gm-nor-read",
                    "--transport",
                    "bluetooth",
                ],
            )

    def test_gm_nor_modes_pin_the_usb_cat_baud(self) -> None:
        for mode in ("gm-nor-check", "gm-nor-dump"):
            with self.subTest(mode=mode):
                assert capture_dump._resolve_baud(mode, "usb", None) == 115200
                assert capture_dump._resolve_baud(mode, "usb", 115200) == 115200
                with pytest.raises(
                    capture_dump.CaptureError,
                    match="require the audited USB CAT setting",
                ):
                    _ = capture_dump._resolve_baud(mode, "usb", 9_600)

    def test_gm_nor_help_and_runtime_pin_full_artifact_hashes(self) -> None:
        with (
            patch.object(
                sys,
                "stdout",
                new_callable=io.StringIO,
            ) as help_output,
            pytest.raises(SystemExit),
        ):
            _ = capture_dump._parse_args(["--help"])
        help_text = help_output.getvalue()
        assert capture_dump.GM_NOR_RAW_SHA256 in help_text
        assert capture_dump.GM_NOR_KEX_SHA256 in help_text

        with (
            patch.object(capture_dump, "_resolve_port", return_value="loopback"),
            patch.object(
                capture_dump,
                "_capture_gm_nor_check",
                return_value=bytes(range(256)),
            ),
            patch.object(
                sys,
                "stderr",
                new_callable=io.StringIO,
            ) as runtime_output,
            patch.object(sys, "stdout", new_callable=io.StringIO),
        ):
            result = capture_dump.main(
                [
                    "--mode",
                    "gm-nor-check",
                    "--acknowledge-cat-preflight",
                    "--acknowledge-gm-nor-read",
                ],
            )
        assert result == 0
        assert capture_dump.GM_NOR_RAW_SHA256 in runtime_output.getvalue()
        assert capture_dump.GM_NOR_KEX_SHA256 in runtime_output.getvalue()

    def test_stock_baseline_requires_specific_restore_attestation(self) -> None:
        with pytest.raises(SystemExit):
            _ = capture_dump._parse_args(
                [
                    "--mode",
                    "9r-baseline",
                    "--acknowledge-cat-preflight",
                ],
            )
        args = capture_dump._parse_args(
            [
                "--mode",
                "9r-baseline",
                "--acknowledge-cat-preflight",
                "--acknowledge-stock-v103-restored",
            ],
        )
        assert args.acknowledge_stock_v103_restored

    def test_cat_preflight_acknowledgement_is_9r_only(self) -> None:
        with pytest.raises(SystemExit):
            _ = capture_dump._parse_args(
                ["--port", "loopback", "--acknowledge-cat-preflight"],
            )

    def test_usb_service_mode_can_defer_port_to_vid_pid_discovery(self) -> None:
        args = capture_dump._parse_args(
            [
                "--mode",
                "9r-baseline",
                "--acknowledge-cat-preflight",
                "--acknowledge-stock-v103-restored",
                "--transport",
                "usb",
            ],
        )
        assert args.port is None

    def test_usb_discovery_requires_exactly_one_d75(self) -> None:
        patcher = patch.object(capture_dump, "_enumerate_serial_ports")
        enumerate_ports = patcher.start()
        self.addCleanup(patcher.stop)
        enumerate_ports.return_value = [
            ("/dev/cu.other", 0x1234, 0x5678),
            (
                "/dev/cu.usbmodem2101",
                capture_dump.USB_VID,
                capture_dump.USB_PID,
            ),
        ]
        assert capture_dump._discover_usb_port() == "/dev/cu.usbmodem2101"

        enumerate_ports.return_value = []
        with pytest.raises(capture_dump.CaptureError, match="2166:9023"):
            _ = capture_dump._discover_usb_port()

        enumerate_ports.return_value = [
            (
                "/dev/cu.usbmodem1101",
                capture_dump.USB_VID,
                capture_dump.USB_PID,
            ),
            (
                "/dev/cu.usbmodem2101",
                capture_dump.USB_VID,
                capture_dump.USB_PID,
            ),
        ]
        with pytest.raises(capture_dump.CaptureError, match="multiple"):
            _ = capture_dump._discover_usb_port()

    def test_explicit_usb_port_still_requires_exact_d75_vid_pid(self) -> None:
        patcher = patch.object(capture_dump, "_enumerate_serial_ports")
        enumerate_ports = patcher.start()
        self.addCleanup(patcher.stop)
        enumerate_ports.return_value = [
            ("/dev/cu.TH-D75", None, None),
            (
                "/dev/cu.usbmodem2101",
                capture_dump.USB_VID,
                capture_dump.USB_PID,
            ),
        ]
        with pytest.raises(capture_dump.CaptureError, match="not an enumerated"):
            _ = capture_dump._resolve_port(
                "9r-baseline",
                "usb",
                "/dev/cu.TH-D75",
            )
        assert (
            capture_dump._resolve_port("9r-baseline", "usb", "/dev/cu.usbmodem2101")
            == "/dev/cu.usbmodem2101"
        )

    def test_python_service_bluetooth_always_fails_before_open(self) -> None:
        for platform in ("darwin", "linux"):
            with (
                self.subTest(platform=platform),
                patch.object(sys, "platform", platform),
                pytest.raises(capture_dump.CaptureError, match="not qualified"),
            ):
                _ = capture_dump._resolve_port(
                    "9r-baseline",
                    "bluetooth",
                    "loopback",
                )

    def test_missing_patched_gate_fails_before_usb_enumeration(self) -> None:
        patcher = patch.object(capture_dump, "_enumerate_serial_ports")
        enumerate_ports = patcher.start()
        self.addCleanup(patcher.stop)
        result = capture_dump.main(
            [
                "--mode",
                "9r-patched-check",
                "--acknowledge-cat-preflight",
            ],
        )
        assert result == 1
        enumerate_ports.assert_not_called()


class NormalGmNorProtocolTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        _FakeGmSerial.instances.clear()
        _FakeGmSerial.corrupt_second_pass = False
        _FakeGmSerial.corrupt_sixteen_byte_read = False
        _FakeGmSerial.corrupt_patch_attestation = False
        _FakeGmSerial.corrupt_base_probe = False
        _FakeGmSerial.short_gm_error = None
        _FakeGmSerial.stale_on_open = b""

    def test_exact_request_reply_shape_and_efficient_full_read(self) -> None:
        assert capture_dump.GM_NOR_BASE_PROBE == (2554016, b"`")
        expected_attestations = (
            (2286280, bytes.fromhex("01 EC 02 C0 47 4D 00 00")),
            (2288640, bytes.fromhex("10 B5 14 00 40 F0 0F FE 02 20 20 70 10 BD")),
            (2553948, bytes.fromhex("80 26 76 04")),
            (2554016, bytes.fromhex("60 26 36 06 01 99 89 19 02 A8 00 9A A1 F7 8D FD")),
        )
        assert expected_attestations == capture_dump.GM_NOR_PATCH_ATTESTATIONS
        assert capture_dump._build_gm_request(2096896, 256) == b"GM 1FFF00,00\r"
        payload = bytes(range(256))
        response = b"GM 1FFF00," + payload.hex().upper().encode() + b"\r"
        assert len(response) == capture_dump.GM_MAX_RESPONSE
        assert (
            capture_dump._parse_gm_response(response, offset=2096896, length=256)
            == payload
        )

        link = _FakeGmSerial()
        assert capture_dump._read_gm(link, offset=0, length=256) == payload
        assert link.writes == [b"GM 000000,00\r"]
        # Two bounded serial reads (error prefix, then body), not 523
        # one-byte calls.
        assert link.gm_response_read_sizes == [2, 521]

    def test_short_gm_errors_fail_without_waiting_for_a_success_body(self) -> None:
        for response in (b"N\r", b"?\r"):
            with self.subTest(response=response):
                _FakeGmSerial.short_gm_error = response
                link = _FakeGmSerial()
                with pytest.raises(capture_dump.CaptureError, match="failed with"):
                    _ = capture_dump._read_gm(link, offset=0, length=256)
                assert link.gm_response_read_sizes == [2]
                _FakeGmSerial.short_gm_error = None

    def test_range_and_attestation_allowlist_fail_before_write(self) -> None:
        link = _FakeGmSerial()
        unsafe = (
            (0x1FFFFF, 2, False),
            (0x200000, 1, False),
            (0xFFFFFF, 1, False),
            (0x200000, 1, True),
            (0x26F8A0, 2, True),
        )
        for offset, length, attestation in unsafe:
            with (
                self.subTest(
                    offset=offset,
                    length=length,
                    attestation=attestation,
                ),
                pytest.raises(capture_dump.CaptureError),
            ):
                _ = capture_dump._read_gm(
                    link,
                    offset=offset,
                    length=length,
                    patch_attestation=attestation,
                )
        assert link.writes == []

    @patch.object(serial, "Serial", _FakeGmSerial)
    def test_check_attests_patch_and_repeats_without_service_verbs(self) -> None:
        result = capture_dump._capture_gm_nor_check(
            port="loopback",
            baud=115_200,
            timeout=1.0,
            transport="usb",
            verbose=False,
        )
        assert result == bytes(range(256))
        link = _FakeGmSerial.instances[-1]
        assert link.kwargs["exclusive"]
        assert not link.kwargs["rtscts"]
        assert link.reset_calls == 0
        assert link.writes[:3] == [b"ID\r", b"FV\r", b"GM 26F8A0,01\r"]
        gm_commands = [command for command in link.writes if command.startswith(b"GM ")]
        assert gm_commands[:5] == [
            b"GM 26F8A0,01\r",
            b"GM 22E2C8,08\r",
            b"GM 22EC00,0E\r",
            b"GM 26F85C,04\r",
            b"GM 26F8A0,10\r",
        ]
        assert gm_commands[-3:] == [b"GM 000000,10\r"] * 3
        for index, command in enumerate(link.writes):
            if command.startswith(b"GM "):
                assert link.writes[index + 1] == b"ID\r"
        assert not any(
            command.startswith((b"0G", b"0E", b"9R")) for command in link.writes
        )
        assert not any(b"FFFFFF" in command for command in link.writes)
        # Clean-open quiet, post-FV quiet, and one post-ID quiet per GM.
        assert link.quiet_reads == 2 + len(gm_commands)

    @patch.object(serial, "Serial", _FakeGmSerial)
    def test_patch_mismatch_stops_before_any_low_nor_read(self) -> None:
        _FakeGmSerial.corrupt_patch_attestation = True
        with pytest.raises(capture_dump.CaptureError, match="attestation mismatch"):
            _ = capture_dump._capture_gm_nor_check(
                port="loopback",
                baud=115_200,
                timeout=1.0,
                transport="usb",
                verbose=False,
            )
        gm_commands = [
            command
            for command in _FakeGmSerial.instances[-1].writes
            if command.startswith(b"GM ")
        ]
        assert gm_commands == [b"GM 26F8A0,01\r", b"GM 22E2C8,08\r"]

    @patch.object(serial, "Serial", _FakeGmSerial)
    def test_base_mismatch_and_stale_open_stop_before_low_nor(self) -> None:
        _FakeGmSerial.corrupt_base_probe = True
        with pytest.raises(capture_dump.CaptureError, match="base probe mismatch"):
            _ = capture_dump._capture_gm_nor_check(
                port="loopback",
                baud=115_200,
                timeout=1.0,
                transport="usb",
                verbose=False,
            )
        assert [
            command
            for command in _FakeGmSerial.instances[-1].writes
            if command.startswith(b"GM ")
        ] == [b"GM 26F8A0,01\r"]

        _FakeGmSerial.corrupt_base_probe = False
        _FakeGmSerial.stale_on_open = b"X"
        with pytest.raises(capture_dump.CaptureError, match="was not quiet"):
            _ = capture_dump._capture_gm_nor_check(
                port="loopback",
                baud=115_200,
                timeout=1.0,
                transport="usb",
                verbose=False,
            )
        assert _FakeGmSerial.instances[-1].writes == []

    def test_bulk_checkpoint_cadence_is_exact(self) -> None:
        assert [
            completed
            for completed in range(
                capture_dump.GM_MAX_READ,
                capture_dump.GM_NOR_LENGTH + 1,
                capture_dump.GM_MAX_READ,
            )
            if capture_dump._gm_checkpoint_due(completed)
        ] == [262144, 524288, 786432, 1048576, 1310720, 1572864, 1835008, 2097152]

    @patch.object(serial, "Serial", _FakeGmSerial)
    def test_two_pass_dump_matches_and_compares_exact_chunks(self) -> None:
        with (
            TemporaryDirectory() as directory,
            patch.object(capture_dump, "GM_NOR_LENGTH", 512),
            patch.object(capture_dump, "GM_CHECKPOINT_INTERVAL", 256),
        ):
            output = Path(directory) / "bootloader.bin"
            result = capture_dump._capture_gm_nor_dump(
                capture_dump._DumpRequest(
                    port="loopback",
                    baud=115_200,
                    timeout=1.0,
                    transport="usb",
                    output=output,
                    verbose=False,
                ),
            )
            assert result.length == 512
            assert output.read_bytes() == bytes(range(256)) * 2
            link = _FakeGmSerial.instances[-1]
            assert link.writes.count(b"GM 000000,00\r") == 3
            assert link.writes.count(b"GM 000100,00\r") == 2
            assert not any(
                command.startswith((b"0G", b"0E", b"9R")) for command in link.writes
            )
            assert link.gm_response_read_sizes.count(523) == 0
            assert link.gm_response_read_sizes.count(521) == 5

    @patch.object(serial, "Serial", _FakeGmSerial)
    def test_two_pass_mismatch_removes_partial_and_publishes_nothing(self) -> None:
        _FakeGmSerial.corrupt_second_pass = True
        with (
            TemporaryDirectory() as directory,
            patch.object(capture_dump, "GM_NOR_LENGTH", 512),
            patch.object(capture_dump, "GM_CHECKPOINT_INTERVAL", 256),
        ):
            output = Path(directory) / "bootloader.bin"
            with pytest.raises(capture_dump.CaptureError, match="passes differ"):
                _ = capture_dump._capture_gm_nor_dump(
                    capture_dump._DumpRequest(
                        port="loopback",
                        baud=115_200,
                        timeout=1.0,
                        transport="usb",
                        output=output,
                        verbose=False,
                    ),
                )
            assert not output.exists()
            assert list(Path(directory).iterdir()) == []

    @patch.object(serial, "Serial", _FakeGmSerial)
    def test_dump_never_overwrites_existing_or_racing_output(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "bootloader.bin"
            _ = output.write_bytes(b"existing")
            with pytest.raises(capture_dump.CaptureError, match="overwrite"):
                _ = capture_dump._capture_gm_nor_dump(
                    capture_dump._DumpRequest(
                        port="loopback",
                        baud=115_200,
                        timeout=1.0,
                        transport="usb",
                        output=output,
                        verbose=False,
                    ),
                )
            assert output.read_bytes() == b"existing"
            assert _FakeGmSerial.instances == []

        with (
            TemporaryDirectory() as directory,
            patch.object(capture_dump, "GM_NOR_LENGTH", 256),
            patch.object(capture_dump, "GM_CHECKPOINT_INTERVAL", 256),
        ):
            output = Path(directory) / "bootloader.bin"

            def competing_publish(_source: Path, destination: Path) -> None:
                _ = Path(destination).write_bytes(b"competitor")
                msg = "destination appeared"
                raise FileExistsError(msg)

            with (
                patch.object(os, "link", side_effect=competing_publish),
                pytest.raises(capture_dump.CaptureError, match="verified"),
            ):
                _ = capture_dump._capture_gm_nor_dump(
                    capture_dump._DumpRequest(
                        port="loopback",
                        baud=115_200,
                        timeout=1.0,
                        transport="usb",
                        output=output,
                        verbose=False,
                    ),
                )
            assert output.read_bytes() == b"competitor"
            assert list(Path(directory).iterdir()) == [output]


class Service9RProtocolTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        _FakeServiceSerial.instances.clear()
        _FakeServiceSerial.corrupt_second_pass = False
        _FakeServiceSerial.acknowledge_already_active_entry = False
        _FakeServiceSerial.reject_entry_response = False
        _FakeServiceSerial.short_entry_write = False
        _FakeServiceSerial.reject_first_identity = False
        _FakeServiceSerial.reject_second_identity = False
        _FakeServiceSerial.reject_firmware = False
        _FakeServiceSerial.corrupt_sixteen_byte_read = False
        _FakeServiceSerial.fail_entry_flush = False
        _FakeServiceSerial.short_9r_write = False
        _FakeServiceSerial.fail_close = False

    def test_exact_maximum_request_and_response(self) -> None:
        request = capture_dump._build_9r_request(0x1FFF00, 256)
        assert request == b"9R 1FFF00,00\r"
        assert len(request) == 13
        payload = bytes(range(256))
        response = b"9R 1FFF00," + payload.hex().upper().encode() + b"\r"
        assert len(response) == 523
        assert (
            capture_dump._parse_9r_response(response, offset=2096896, length=256)
            == payload
        )

    def test_rejects_overrun_and_lowercase_response(self) -> None:
        with pytest.raises(capture_dump.CaptureError, match="exceeds"):
            _ = capture_dump._build_9r_request(0x1FFFFF, 2)
        with pytest.raises(capture_dump.CaptureError, match="uppercase"):
            _ = capture_dump._parse_9r_response(
                b"9R 000000,ab\r",
                offset=0,
                length=1,
            )

    @patch.object(serial, "Serial", _FakeServiceSerial)
    def test_stock_baseline_sends_only_exact_allowlisted_commands(self) -> None:
        result = capture_dump._capture_9r_baseline(
            port="loopback",
            baud=115_200,
            timeout=1.0,
            transport="usb",
            verbose=False,
        )
        assert result == bytes(range(256))
        link = _FakeServiceSerial.instances[-1]
        assert link.writes == [
            b"ID\r",
            b"FV\r",
            b"0G KENWOOD\r",
            b"9R 000000,01\r",
            b"9R 000000,01\r",
            b"9R 000000,00\r",
            b"0E\r",
            b"ID\r",
        ]
        assert not any(command.startswith(b"9E") for command in link.writes)
        assert not link.kwargs["rtscts"]

    def test_entry_requires_clean_silent_transition(self) -> None:
        _FakeServiceSerial.acknowledge_already_active_entry = True
        already_active = _FakeServiceSerial()
        with pytest.raises(capture_dump.CaptureError, match="already in service"):
            _ = capture_dump._run_service_session(
                already_active,
                lambda _active: b"unused",
            )
        assert already_active.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
            capture_dump.SERVICE_EXIT,
            capture_dump.NORMAL_CAT_ID,
        ]

        _FakeServiceSerial.acknowledge_already_active_entry = False
        invalid = _FakeServiceSerial()
        _FakeServiceSerial.reject_entry_response = True
        with pytest.raises(capture_dump.CaptureError, match="silent"):
            _ = capture_dump._run_service_session(invalid, lambda _active: b"unused")

    def test_short_entry_write_does_not_attempt_service_exit(self) -> None:
        _FakeServiceSerial.short_entry_write = True
        link = _FakeServiceSerial()
        with pytest.raises(capture_dump.CaptureError, match="short write"):
            _ = capture_dump._run_service_session(link, lambda _active: b"unused")
        assert link.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
        ]

    def test_entry_flush_failure_sends_nothing_further_and_requires_power_cycle(
        self,
    ) -> None:
        _FakeServiceSerial.fail_entry_flush = True
        link = _FakeServiceSerial()
        with pytest.raises(
            capture_dump._AmbiguousWriteError, match="Fully power-cycle"
        ):
            _ = capture_dump._run_service_session(link, lambda _active: b"unused")
        assert link.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
        ]

    def test_short_9r_write_sends_no_exit_and_requires_power_cycle(self) -> None:
        _FakeServiceSerial.short_9r_write = True
        link = _FakeServiceSerial()
        with pytest.raises(
            capture_dump._AmbiguousWriteError, match="Fully power-cycle"
        ):
            _ = capture_dump._run_service_session(
                link,
                lambda active: capture_dump._read_9r(
                    active,
                    offset=0,
                    length=1,
                ),
            )
        assert link.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
            b"9R 000000,01\r",
        ]

    def test_interrupt_after_completed_entry_still_runs_exact_cleanup(self) -> None:
        link = _FakeServiceSerial()
        write_exact = capture_dump._write_exact

        def interrupt_after_entry(
            active: _FakeServiceSerial,
            command: bytes,
            *,
            completion: capture_dump._WriteCompletion | None = None,
        ) -> None:
            write_exact(active, command, completion=completion)
            if command == capture_dump.SERVICE_ENTER:
                raise KeyboardInterrupt

        with (
            patch.object(
                capture_dump,
                "_write_exact",
                side_effect=interrupt_after_entry,
            ),
            pytest.raises(KeyboardInterrupt),
        ):
            _ = capture_dump._run_service_session(link, lambda _active: b"unused")
        assert link.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
            capture_dump.SERVICE_EXIT,
            capture_dump.NORMAL_CAT_ID,
        ]

    def test_failed_pre_entry_identity_sends_no_service_command(self) -> None:
        _FakeServiceSerial.reject_first_identity = True
        link = _FakeServiceSerial()
        with pytest.raises(
            capture_dump._PreEntryProofError, match="power-cycle"
        ) as caught:
            _ = capture_dump._run_service_session(link, lambda _active: b"unused")
        assert isinstance(caught.value.cause, capture_dump.CaptureError)
        assert "identity response" in str(caught.value.cause)
        assert link.writes == [capture_dump.NORMAL_CAT_ID]

    def test_wrong_firmware_version_blocks_service_entry(self) -> None:
        _FakeServiceSerial.reject_firmware = True
        link = _FakeServiceSerial()
        with pytest.raises(
            capture_dump._PreEntryProofError, match="power-cycle"
        ) as caught:
            _ = capture_dump._run_service_session(link, lambda _active: b"unused")
        assert "FV 1.03" in str(caught.value.cause)
        assert link.writes == [capture_dump.NORMAL_CAT_ID, capture_dump.NORMAL_CAT_FV]

    def test_response_timeout_is_one_absolute_deadline(self) -> None:
        class SlowLink(_FakeServiceSerial):
            def __init__(self) -> None:
                super().__init__()
                self.response_timeout = 1.0
                self.timeouts: list[float] = []

            @override
            def read(self, count: int, *, timeout: float | None = None) -> bytes:
                del count
                if timeout is None:
                    msg = "deadline read requires a timeout"
                    raise TypeError(msg)
                self.timeouts.append(timeout)
                return b"A"

        link = SlowLink()
        with (
            patch(
                "capture_dump.time.monotonic",
                side_effect=(0.0, 0.0, 0.4, 1.1),
            ),
            pytest.raises(capture_dump.CaptureError, match="timed out"),
        ):
            _ = capture_dump._read_cr_line(link, max_length=10)
        assert link.timeouts == [1.0, 0.6]

    def test_failed_post_exit_identity_is_fatal(self) -> None:
        _FakeServiceSerial.reject_second_identity = True
        link = _FakeServiceSerial()
        with pytest.raises(capture_dump.CaptureError, match="identity response"):
            _ = capture_dump._run_service_session(link, lambda _active: b"result")
        assert link.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
            capture_dump.SERVICE_EXIT,
            capture_dump.NORMAL_CAT_ID,
        ]

    def test_failed_entry_response_still_exits_and_rechecks_normal_cat(self) -> None:
        _FakeServiceSerial.reject_entry_response = True
        link = _FakeServiceSerial()
        with pytest.raises(capture_dump.CaptureError, match="entry response"):
            _ = capture_dump._run_service_session(link, lambda _active: b"unused")
        assert link.writes == [
            capture_dump.NORMAL_CAT_ID,
            capture_dump.NORMAL_CAT_FV,
            capture_dump.SERVICE_ENTER,
            capture_dump.SERVICE_EXIT,
            capture_dump.NORMAL_CAT_ID,
        ]

    def test_non_capture_error_and_cleanup_failure_are_both_preserved(self) -> None:
        for operation_error in (OSError("disk full"), KeyboardInterrupt()):
            with self.subTest(error_type=type(operation_error).__name__):
                _FakeServiceSerial.reject_second_identity = True
                link = _FakeServiceSerial()

                def fail(
                    _active: object,
                    *,
                    error: BaseException = operation_error,
                ) -> bytes:
                    raise error

                with pytest.raises(capture_dump._ServiceCleanupError) as caught:
                    _ = capture_dump._run_service_session(link, fail)
                failure = caught.value
                assert failure.operation_error is operation_error
                assert isinstance(failure.cleanup_error, capture_dump.CaptureError)
                assert failure.__cause__ is operation_error
                assert type(operation_error).__name__ in str(failure)
                assert "service cleanup also failed" in str(failure)
                assert "power-cycle the radio before any retry" in str(failure)
                assert link.writes[-2:] == [
                    capture_dump.SERVICE_EXIT,
                    capture_dump.NORMAL_CAT_ID,
                ]
                _FakeServiceSerial.reject_second_identity = False

    def test_non_capture_error_is_unchanged_when_cleanup_succeeds(self) -> None:
        operation_error = OSError("disk full")
        link = _FakeServiceSerial()

        def fail(_active: object) -> bytes:
            raise operation_error

        with pytest.raises(OSError, match="disk full") as caught:
            _ = capture_dump._run_service_session(link, fail)
        assert caught.value is operation_error
        assert link.writes[-2:] == [
            capture_dump.SERVICE_EXIT,
            capture_dump.NORMAL_CAT_ID,
        ]

    def test_bluetooth_refused_for_unbounded_teardown_before_open(self) -> None:
        with (
            patch.object(serial, "Serial") as serial_constructor,
            pytest.raises(
                capture_dump.CaptureError,
                match="canceled native blocking write can make bounded teardown impossible",
            ),
        ):
            _ = capture_dump._open_service_link(
                port="loopback",
                baud=9_600,
                timeout=1.0,
                transport="bluetooth",
            )
        serial_constructor.assert_not_called()

    @patch.object(serial, "Serial", _FakeServiceSerial)
    def test_transport_close_failure_is_controlled_and_preserved(self) -> None:
        _FakeServiceSerial.fail_close = True
        with pytest.raises(capture_dump._LinkCloseError) as caught:
            _ = capture_dump._capture_9r_baseline(
                port="loopback",
                baud=115_200,
                timeout=1.0,
                transport="usb",
                verbose=False,
            )
        assert caught.value.operation_error is None
        assert "fully power-cycle" in str(caught.value)

        _FakeServiceSerial.corrupt_sixteen_byte_read = True
        with pytest.raises(capture_dump._LinkCloseError) as combined:
            _ = capture_dump._capture_9r_patched_check(
                port="loopback",
                baud=115_200,
                timeout=1.0,
                transport="usb",
                verbose=False,
            )
        assert isinstance(combined.value.operation_error, capture_dump.CaptureError)
        assert "transport close also failed" in str(combined.value)

    @patch.object(serial, "Serial", _FakeServiceSerial)
    def test_two_pass_dump_matches_with_exclusive_usb_link(self) -> None:
        with (
            TemporaryDirectory() as directory,
            patch.object(
                capture_dump,
                "SERVICE_WINDOW_LENGTH",
                512,
            ),
        ):
            output = Path(directory) / "dump.bin"
            result = capture_dump._capture_9r_dump(
                capture_dump._DumpRequest(
                    port="loopback",
                    baud=115_200,
                    timeout=1.0,
                    transport="usb",
                    output=output,
                    verbose=False,
                ),
            )
            assert result.length == 512
            assert output.read_bytes() == bytes(range(256)) * 2
            link = _FakeServiceSerial.instances[-1]
            assert not link.kwargs["rtscts"]
            assert link.kwargs["exclusive"]
            assert link.writes[0] == capture_dump.NORMAL_CAT_ID
            assert link.writes[1] == capture_dump.NORMAL_CAT_FV
            assert link.writes[2] == capture_dump.SERVICE_ENTER
            assert link.writes[-2] == capture_dump.SERVICE_EXIT
            assert link.writes[-1] == capture_dump.NORMAL_CAT_ID
            check_prefix = [
                b"ID\r",
                b"FV\r",
                b"0G KENWOOD\r",
                b"9R 000000,01\r",
                b"9R 000000,10\r",
                b"9R 000000,00\r",
                b"9R 0001FF,01\r",
                b"9R 0001FF,02\r",
                b"9R 000200,01\r",
                b"0E\r",
                b"ID\r",
                b"ID\r",
                b"FV\r",
                b"0G KENWOOD\r",
            ]
            assert link.writes[: len(check_prefix)] == check_prefix
            assert link.writes.count(b"9R 000000,00\r") == 3
            assert link.writes.count(b"9R 000100,00\r") == 2

    @patch.object(serial, "Serial", _FakeServiceSerial)
    def test_dump_stops_before_bulk_reads_when_automatic_check_fails(self) -> None:
        _FakeServiceSerial.corrupt_sixteen_byte_read = True
        with (
            TemporaryDirectory() as directory,
            patch.object(capture_dump, "SERVICE_WINDOW_LENGTH", 512),
        ):
            output = Path(directory) / "dump.bin"
            with pytest.raises(capture_dump.CaptureError, match="reads disagree"):
                _ = capture_dump._capture_9r_dump(
                    capture_dump._DumpRequest(
                        port="loopback",
                        baud=115_200,
                        timeout=1.0,
                        transport="usb",
                        output=output,
                        verbose=False,
                    ),
                )
            assert not output.exists()
            assert list(Path(directory).iterdir()) == []
            assert _FakeServiceSerial.instances[-1].writes == [
                b"ID\r",
                b"FV\r",
                b"0G KENWOOD\r",
                b"9R 000000,01\r",
                b"9R 000000,10\r",
                b"9R 000000,00\r",
                b"0E\r",
                b"ID\r",
            ]

    @patch.object(serial, "Serial", _FakeServiceSerial)
    def test_patched_check_pins_small_reads_and_both_rejections(self) -> None:
        result = capture_dump._capture_9r_patched_check(
            port="loopback",
            baud=115_200,
            timeout=1.0,
            transport="usb",
            verbose=False,
        )
        assert result == bytes(range(256))
        assert _FakeServiceSerial.instances[-1].writes == [
            b"ID\r",
            b"FV\r",
            b"0G KENWOOD\r",
            b"9R 000000,01\r",
            b"9R 000000,10\r",
            b"9R 000000,00\r",
            b"9R 1FFFFF,01\r",
            b"9R 1FFFFF,02\r",
            b"9R 200000,01\r",
            b"0E\r",
            b"ID\r",
        ]

    @patch.object(serial, "Serial", _FakeServiceSerial)
    def test_mismatch_deletes_partial_output_and_still_exits_service(self) -> None:
        _FakeServiceSerial.corrupt_second_pass = True
        with (
            TemporaryDirectory() as directory,
            patch.object(
                capture_dump,
                "SERVICE_WINDOW_LENGTH",
                256,
            ),
        ):
            output = Path(directory) / "dump.bin"
            with pytest.raises(capture_dump.CaptureError, match="passes differ"):
                _ = capture_dump._capture_9r_dump(
                    capture_dump._DumpRequest(
                        port="loopback",
                        baud=115_200,
                        timeout=1.0,
                        transport="usb",
                        output=output,
                        verbose=False,
                    ),
                )
            assert not output.exists()
            assert list(Path(directory).iterdir()) == []
            assert _FakeServiceSerial.instances[-1].writes[-2:] == [
                capture_dump.SERVICE_EXIT,
                capture_dump.NORMAL_CAT_ID,
            ]


if __name__ == "__main__":
    _ = unittest.main()
