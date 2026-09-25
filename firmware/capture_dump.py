#!/usr/bin/env python3
r"""Capture TH-D75 NOR bytes with one of the audited host protocols.

``d75d`` retains the existing custom-payload stream receiver. It is offline-only
until that payload has an allowed USB/Bluetooth transport.

``gm-nor-check`` and ``gm-nor-dump`` use only normal-mode CAT over the exact
TH-D75 USB endpoint.  They are tied to the hash-pinned ``normal-gm-nor-read``
artifact, attest its live instruction bytes, and expose no arbitrary address
argument.  Check mode validates bounded reads of the low-NOR candidate window.
Dump mode repeats that gate before reading exactly two MiB twice, comparing
every second-pass chunk directly with the first and publishing only an exact
match.

``9r-baseline``, ``9r-patched-check``, and ``9r-dump`` use exact raw service CAT
commands against the stock parser/transport. They never import the currently
shifted sibling Rust service API. Each mode requires an explicit front-panel
CAT-preflight acknowledgement and exact read-only ``ID`` checks before service
entry and after exact service exit. Baseline adds three ``9R`` reads;
patched-check validates small reads and both bounds. Dump mode requires the same
explicit acknowledgement, completes that check (including exact service exit
and normal-CAT reproving) before entering a second service session for any bulk
reads, reads the two-MiB pre-main NOR candidate range twice, and refuses the
result unless both passes match. Its D75 contents and internal partition
boundaries remain unknown until captured.

Usage::

    firmware/capture_dump.py --mode 9r-baseline \\
        --acknowledge-cat-preflight \\
        --acknowledge-stock-v103-restored \\
        --transport usb

    firmware/capture_dump.py --mode 9r-dump --allow-patched-9r \\
        --acknowledge-cat-preflight \\
        --transport usb --output dump.bin

    firmware/capture_dump.py --mode gm-nor-dump \\
        --acknowledge-cat-preflight --acknowledge-gm-nor-read \\
        --transport usb --output bootloader.bin
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import math
import os
import struct
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import serial  # pyserial
from serial.tools import list_ports as _serial_list_ports

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType
    from typing import IO, Protocol

    from typing_extensions import Self

    class _SerialLink(Protocol):
        response_timeout: float

        def __enter__(self) -> Self: ...
        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: TracebackType | None,
        ) -> None: ...
        def read(self, count: int, *, timeout: float) -> bytes: ...
        def write(self, data: bytes) -> int: ...
        def flush(self) -> None: ...
        def reset_input_buffer(self) -> None: ...


#: Magic prefix the dumper emits at the start of every stream.
MAGIC: bytes = b"D75D"

#: On-wire header length: magic + base_addr:u32 + length:u32.
HEADER_LEN: int = len(MAGIC) + 4 + 4

#: Compile-time default in ``dumper/src/main.rs``.
DEFAULT_BAUD: int = 115_200

USB_CAT_BAUD: int = 115_200
USB_VID: int = 0x2166
USB_PID: int = 0x9023
# The official Operating Tips says SPP virtual-COM line coding is ignored and
# any host baud selection is acceptable.  Keep 9600 only as a conventional
# application-side default; it is not a Bluetooth wire-rate requirement.
BLUETOOTH_CAT_BAUD: int = 9_600
NORMAL_CAT_ID: bytes = b"ID\r"
NORMAL_CAT_ID_RESPONSE: bytes = b"ID TH-D75\r"
NORMAL_CAT_FV: bytes = b"FV\r"
NORMAL_CAT_FV_RESPONSE: bytes = b"FV 1.03\r"
SERVICE_ENTER: bytes = b"0G KENWOOD\r"
SERVICE_ENTER_ALREADY_ACTIVE_RESPONSE: bytes = b"0G\r"
SERVICE_EXIT: bytes = b"0E\r"
SERVICE_WINDOW_LENGTH: int = 0x0020_0000
SERVICE_MAX_READ: int = 256
SERVICE_MAX_RESPONSE: int = 523

# Exact audited ``normal-gm-nor-read`` artifact identity.  A running radio
# cannot report its KEX hash, so the operator acknowledgement is supplemented
# by exact reads of every live patch window before any low-NOR capture.
GM_NOR_RAW_SHA256: str = (
    "2eddf487e985861c95fb4212d0f7eabfb57c648eee06f3141819582226fd6ea0"
)
GM_NOR_KEX_SHA256: str = (
    "f619fbb6b6fd91ad5bcdaf85bcc3bcd31483564fc5a5643aad73ce5915f5f30e"
)
GM_NOR_LENGTH: int = 0x0020_0000
GM_MAX_READ: int = 256
GM_MAX_RESPONSE: int = 523
GM_QUIET_SECONDS: float = 0.5
GM_CHECKPOINT_INTERVAL: int = 0x0004_0000

# The first GM command in either mode must prove the NOR-base immediate before
# any dereference in the unknown low-NOR candidate window.
GM_NOR_BASE_PROBE: tuple[int, bytes] = (0x26F8A0, b"\x60")

# These four exact reads are the only GM reads permitted above the low 2 MiB.
# They attest the unchanged dispatch-table entry and every modified live code
# window in the exact normal-GM NOR artifact.
GM_NOR_PATCH_ATTESTATIONS: tuple[tuple[int, bytes], ...] = (
    (0x22E2C8, bytes.fromhex("01 EC 02 C0 47 4D 00 00")),
    (
        0x22EC00,
        bytes.fromhex("10 B5 14 00 40 F0 0F FE 02 20 20 70 10 BD"),
    ),
    (0x26F85C, bytes.fromhex("80 26 76 04")),
    (
        0x26F8A0,
        bytes.fromhex("60 26 36 06 01 99 89 19 02 A8 00 9A A1 F7 8D FD"),
    ),
)

#: Bounds carried by the dumper protocol. Rejecting an implausible header
#: avoids turning four corrupted length bytes into an unbounded file capture.
NOR_BASE: int = 0x6000_0000
NOR_LENGTH: int = 0x0200_0000


@dataclass(frozen=True, slots=True)
class _DumpRequest:
    """Connection settings and destination for a two-pass NOR capture."""

    port: str
    baud: int
    timeout: float
    transport: str
    output: Path
    verbose: bool


def _require_patched_9r_acknowledgement(args: argparse.Namespace) -> None:
    """Require ``--allow-patched-9r`` before any patched-handler service mode.

    Args:
        args: The parsed command-line arguments.

    Raises:
        CaptureError: If a patched 9R mode was selected without the explicit
            acknowledgement.

    """
    if args.mode in ("9r-patched-check", "9r-dump") and not args.allow_patched_9r:
        msg = (
            f"{args.mode} requires --allow-patched-9r after the "
            "untouched-stock baseline and a separately audited "
            "modified-main handler; 9r-dump runs the complete patched "
            "small-read/bounds check before any bulk reads"
        )
        raise CaptureError(msg)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns process exit code."""
    args = _parse_args(argv)
    try:
        _require_patched_9r_acknowledgement(args)
        if args.mode in ("gm-nor-check", "gm-nor-dump"):
            print(
                "acknowledged exact normal-gm-nor-read artifact: raw SHA-256 "
                f"{GM_NOR_RAW_SHA256}; plaintext KEX SHA-256 "
                f"{GM_NOR_KEX_SHA256}",
                file=sys.stderr,
            )
        port = _resolve_port(args.mode, args.transport, args.port)
        baud = _resolve_baud(args.mode, args.transport, args.baud)
        if args.mode == "gm-nor-check":
            checked = _capture_gm_nor_check(
                port=port,
                baud=baud,
                timeout=args.timeout,
                transport=args.transport,
                verbose=args.verbose,
            )
            print(
                "normal-GM NOR checks passed: live patch attested; "
                "1/16/64/256-byte prefix agreement, last-byte read, repeat, "
                "ID checkpoint, and quiet windows passed; first-block "
                f"SHA-256={hashlib.sha256(checked).hexdigest()}",
            )
            return 0
        if args.mode == "gm-nor-dump":
            captured = _capture_gm_nor_dump(
                _DumpRequest(
                    port=port,
                    baud=baud,
                    timeout=args.timeout,
                    transport=args.transport,
                    output=args.output,
                    verbose=args.verbose,
                ),
            )
        elif args.mode == "9r-baseline":
            baseline = _capture_9r_baseline(
                port=port,
                baud=baud,
                timeout=args.timeout,
                transport=args.transport,
                verbose=args.verbose,
            )
            print(
                "attested-stock V1.03 service 9R baseline passed: 258 data "
                "bytes checked; no file created; 256-byte response SHA-256="
                f"{hashlib.sha256(baseline).hexdigest()}",
            )
            return 0
        elif args.mode == "9r-patched-check":
            checked = _capture_9r_patched_check(
                port=port,
                baud=baud,
                timeout=args.timeout,
                transport=args.transport,
                verbose=args.verbose,
            )
            print(
                "patched 9R checks passed: 1/16/256-byte reads and both "
                f"bounds; first-block SHA-256={hashlib.sha256(checked).hexdigest()}",
            )
            return 0
        elif args.mode == "9r-dump":
            captured = _capture_9r_dump(
                _DumpRequest(
                    port=port,
                    baud=baud,
                    timeout=args.timeout,
                    transport=args.transport,
                    output=args.output,
                    verbose=args.verbose,
                ),
            )
        else:
            captured = _capture(
                port=port,
                baud=baud,
                timeout=args.timeout,
                output=args.output,
                verbose=args.verbose,
            )
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"captured {captured.length:,} bytes from 0x{captured.base_addr:08X} "
        f"in {captured.elapsed_seconds:.1f}s "
        f"({captured.length / captured.elapsed_seconds / 1024:.1f} KiB/s) "
        f"→ {captured.path}",
    )
    return 0


class CaptureError(RuntimeError):
    """Capture failed: bad magic, short read, or serial error."""


class _AmbiguousWriteError(CaptureError):
    """An outbound CAT command may have reached the parser only in part."""

    def __init__(self, command: bytes, detail: str) -> None:
        super().__init__(
            f"outbound command {command!r} has uncertain completion ({detail}); "
            "no further bytes will be sent on this connection. Fully "
            "power-cycle the radio before any retry",
        )


class _PreEntryProofError(CaptureError):
    """The USB endpoint did not prove the expected CAT parser before entry."""

    def __init__(self, cause: BaseException) -> None:
        self.cause = cause
        super().__init__(
            f"pre-entry CAT proof failed ({type(cause).__name__}: {cause}); "
            "USB identity does not prove normal CAT rather than FLDM, so the "
            "endpoint/parser state is unproven. Disconnect and fully "
            "power-cycle the radio before any retry",
        )


class _ServiceCleanupError(CaptureError):
    """A service operation and/or the required normal-CAT proof failed."""

    def __init__(
        self,
        operation_error: BaseException | None,
        cleanup_error: BaseException,
    ) -> None:
        self.operation_error = operation_error
        self.cleanup_error = cleanup_error
        cleanup_text = f"{type(cleanup_error).__name__}: {cleanup_error}"
        if operation_error is None:
            detail = f"service cleanup failed: {cleanup_text}"
        else:
            operation_text = f"{type(operation_error).__name__}: {operation_error}"
            detail = f"{operation_text}; service cleanup also failed: {cleanup_text}"
        super().__init__(
            f"{detail}; normal CAT restoration is unproven; power-cycle the "
            "radio before any retry",
        )


class _LinkCloseError(CaptureError):
    """Closing the host transport failed, possibly alongside another error."""

    def __init__(
        self,
        operation_error: BaseException | None,
        close_error: BaseException,
    ) -> None:
        self.operation_error = operation_error
        self.close_error = close_error
        close_text = f"{type(close_error).__name__}: {close_error}"
        if operation_error is None:
            detail = f"closing the service transport failed: {close_text}"
        else:
            operation_text = f"{type(operation_error).__name__}: {operation_error}"
            detail = f"{operation_text}; transport close also failed: {close_text}"
        super().__init__(
            f"{detail}; disconnect the host cable/connection and fully "
            "power-cycle the radio before any retry",
        )


class _Captured:
    """Result of a successful capture session."""

    def __init__(
        self, *, path: Path, base_addr: int, length: int, elapsed_seconds: float
    ) -> None:
        super().__init__()
        self.path = path
        self.base_addr = base_addr
        self.length = length
        self.elapsed_seconds = elapsed_seconds


class _WriteCompletion:
    """Mutable completion marker closed over the post-write signal window."""

    def __init__(self) -> None:
        super().__init__()
        self.completed = False


class _PySerialLink:
    """Narrow pyserial adapter with fail-closed write-count semantics."""

    def __init__(self, raw: serial.Serial, *, response_timeout: float) -> None:
        super().__init__()
        self._raw = raw
        self.response_timeout = response_timeout

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        del exc_type, exc_tb
        try:
            self._raw.close()
        except BaseException as close_error:
            combined = _LinkCloseError(exc_val, close_error)
            if exc_val is not None:
                raise combined from exc_val
            raise combined from close_error

    def read(self, count: int, *, timeout: float) -> bytes:
        self._raw.timeout = timeout
        return self._raw.read(count)

    def write(self, data: bytes) -> int:
        written = self._raw.write(data)
        # The pyserial stub permits None. Treat it as a zero-byte short write;
        # never infer that the command completed.
        return 0 if written is None else written

    def flush(self) -> None:
        self._raw.flush()

    def reset_input_buffer(self) -> None:
        self._raw.reset_input_buffer()


def _resolve_baud(mode: str, transport: str, requested: int | None) -> int:
    """Resolve an explicit baud or a documented host-side default.

    Bluetooth SPP and USB CDC are virtual serial links whose line coding is
    ignored by the radio.  The returned Bluetooth value is therefore a host
    API setting, not an asserted SPP wire rate.
    """
    if requested is not None:
        if requested <= 0:
            msg = f"baud must be positive, got {requested}"
            raise CaptureError(msg)
        if mode in ("gm-nor-check", "gm-nor-dump") and requested != USB_CAT_BAUD:
            msg = (
                "normal-GM NOR modes require the audited USB CAT setting "
                f"{USB_CAT_BAUD}; got {requested}"
            )
            raise CaptureError(
                msg,
            )
        return requested
    if mode == "d75d":
        return DEFAULT_BAUD
    return BLUETOOTH_CAT_BAUD if transport == "bluetooth" else USB_CAT_BAUD


def _enumerate_serial_ports() -> list[tuple[str, int | None, int | None]]:
    """Return immutable serial identity data for deterministic validation."""
    try:
        ports = _serial_list_ports.comports()
    except (OSError, serial.SerialException) as exc:
        msg = f"enumerating serial devices: {exc}"
        raise CaptureError(msg) from exc
    return [(port.device, port.vid, port.pid) for port in ports]


def _discover_usb_port(*, requested: str | None = None) -> str:
    """Resolve a TH-D75 USB endpoint; VID/PID does not prove radio mode."""
    matches = sorted(
        device
        for device, vid, pid in _enumerate_serial_ports()
        if vid == USB_VID and pid == USB_PID
    )
    if requested is not None:
        if requested not in matches:
            msg = (
                f"explicit USB port {requested!r} is not an enumerated TH-D75 "
                "USB endpoint with VID:PID 2166:9023; Bluetooth serial nodes "
                "such as /dev/cu.TH-D75 are not USB-C"
            )
            raise CaptureError(
                msg,
            )
        return requested
    if not matches:
        msg = (
            "no TH-D75 USB endpoint with VID:PID 2166:9023 was found; "
            "power the radio on normally, set Menu 980 to COM + AF/IF Output, "
            "and connect it directly with a USB-C data cable"
        )
        raise CaptureError(msg)
    if len(matches) != 1:
        raise CaptureError(
            "multiple TH-D75 USB endpoints matched VID:PID 2166:9023: "
            + ", ".join(matches)
            + "; select one explicitly with --port"
        )
    return matches[0]


def _resolve_port(mode: str, transport: str, requested: str | None) -> str:
    """Use an explicit path or discover the one evidence-backed USB endpoint."""
    if mode != "d75d" and transport == "bluetooth":
        msg = (
            "service-mode Bluetooth is not qualified in this Python receiver "
            "on any platform. The sibling thd75-repl project's baseline "
            "also refuses native IOBluetooth because a canceled blocking "
            "write can make bounded service teardown impossible. Use the "
            "exclusive USB-C baseline; do not use a pyserial Bluetooth node"
        )
        raise CaptureError(msg)
    if mode == "d75d":
        if requested is None:
            msg = (
                "--mode d75d requires an explicit --port because the retained "
                "payload has no authorized USB/Bluetooth enumeration contract"
            )
            raise CaptureError(msg)
        return requested
    port = _discover_usb_port(requested=requested)
    if requested is None:
        print(
            f"auto-discovered TH-D75 USB endpoint {port} (VID:PID 2166:9023; "
            "radio mode still requires the operator attestation and CAT proof)",
            file=sys.stderr,
        )
    return port


def _open_service_link(
    *,
    port: str,
    baud: int,
    timeout: float,
    transport: str,
) -> _SerialLink:
    """Open normal CAT as 8N1 with no asserted hardware flow-control claim."""
    if transport == "bluetooth":
        msg = (
            "service-mode Bluetooth is unqualified in this Python receiver; "
            "the sibling thd75-repl project's fixed baseline also refuses "
            "Bluetooth because a canceled native blocking write can make "
            "bounded teardown impossible. Use exclusive USB-C"
        )
        raise CaptureError(msg)
    try:
        raw = serial.Serial(
            port=port,
            baudrate=baud,
            timeout=timeout,
            write_timeout=timeout,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            # The official SPP documentation specifies no CTS/RTS contract,
            # and virtual RFCOMM ports do not expose physical modem lines.
            # A sibling implementation's RTS/CTS requirement conflicts with
            # another local implementation that explicitly disables it, so
            # do not promote either claim into a radio fact.
            rtscts=False,
            dsrdtr=False,
            xonxoff=False,
            # Prevent a second local serial client from interleaving CAT bytes
            # on platforms supported by this USB-only service path.
            exclusive=True,
        )
    except (OSError, serial.SerialException) as exc:
        msg = f"opening {port}: {exc}"
        raise CaptureError(msg) from exc
    return _PySerialLink(raw, response_timeout=timeout)


def _write_exact(
    link: _SerialLink,
    command: bytes,
    *,
    completion: _WriteCompletion | None = None,
) -> None:
    """Write one CAT command and classify every partial outcome as ambiguous."""
    state = completion if completion is not None else _WriteCompletion()

    def _write_and_flush() -> None:
        written = link.write(command)
        if written != len(command):
            raise _AmbiguousWriteError(
                command,
                f"short write {written}/{len(command)} bytes",
            )
        link.flush()
        # Set the caller-visible marker inside the protected region. If an
        # interrupt lands after this assignment, cleanup is safe because the
        # full CR-terminated command and flush both completed.
        state.completed = True

    try:
        _write_and_flush()
    except _AmbiguousWriteError:
        raise
    except BaseException as exc:
        if state.completed:
            raise
        raise _AmbiguousWriteError(
            command,
            f"{type(exc).__name__}: {exc}",
        ) from exc


def _reset_input_buffer(link: _SerialLink) -> None:
    """Discard stale CAT bytes or convert the transport failure cleanly."""
    try:
        link.reset_input_buffer()
    except (OSError, serial.SerialException) as exc:
        msg = f"discarding stale CAT input: {exc}"
        raise CaptureError(msg) from exc


def _read_cr_line(link: _SerialLink, *, max_length: int) -> bytes:
    """Read one CR-terminated CAT response with a strict size ceiling."""
    deadline = time.monotonic() + link.response_timeout
    response = bytearray()
    while len(response) < max_length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            msg = f"timed out waiting for CR ({len(response)} response bytes)"
            raise CaptureError(
                msg,
            )
        try:
            byte = link.read(1, timeout=remaining)
        except (OSError, serial.SerialException) as exc:
            msg = f"reading CAT response: {exc}"
            raise CaptureError(msg) from exc
        if not byte:
            msg = f"timed out waiting for CR ({len(response)} response bytes)"
            raise CaptureError(
                msg,
            )
        response.extend(byte)
        if response.endswith(b"\r"):
            return bytes(response)
    msg = f"CAT response exceeds {max_length} bytes without CR"
    raise CaptureError(msg)


def _read_optional_cr_line(link: _SerialLink, *, max_length: int) -> bytes:
    r"""Read zero bytes or one complete, bounded CR-terminated response.

    The stock V1.03 ``0G`` handler is deliberately asymmetric: entering
    service mode from normal mode produces no CAT response, while issuing the
    same command when service mode is already active returns ``0G\r``.  An
    empty first read is therefore meaningful only at service entry.  Once any
    byte arrives, a complete line is mandatory.
    """
    deadline = time.monotonic() + link.response_timeout
    try:
        first = link.read(1, timeout=link.response_timeout)
    except (OSError, serial.SerialException) as exc:
        msg = f"reading optional CAT response: {exc}"
        raise CaptureError(msg) from exc
    if not first:
        return b""
    if first == b"\r":
        return first

    response = bytearray(first)
    while len(response) < max_length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            msg = (
                "timed out after a partial service-entry response "
                f"({bytes(response)!r})"
            )
            raise CaptureError(
                msg,
            )
        try:
            byte = link.read(1, timeout=remaining)
        except (OSError, serial.SerialException) as exc:
            msg = f"reading optional CAT response: {exc}"
            raise CaptureError(msg) from exc
        if not byte:
            msg = (
                "timed out after a partial service-entry response "
                f"({bytes(response)!r})"
            )
            raise CaptureError(
                msg,
            )
        response.extend(byte)
        if response.endswith(b"\r"):
            return bytes(response)
    msg = f"service-entry response exceeds {max_length} bytes without CR"
    raise CaptureError(
        msg,
    )


def _exchange_line(
    link: _SerialLink,
    command: bytes,
    *,
    max_response: int,
) -> bytes:
    _write_exact(link, command)
    return _read_cr_line(link, max_length=max_response)


def _build_9r_request(offset: int, length: int) -> bytes:
    r"""Build exact ``9R OOOOOO,LL\r`` bytes for a 1..256-byte read."""
    if not 0 <= offset < SERVICE_WINDOW_LENGTH:
        msg = f"9R offset 0x{offset:X} is outside the low 2 MiB"
        raise CaptureError(msg)
    if not 1 <= length <= SERVICE_MAX_READ:
        msg = f"9R length must be 1..256, got {length}"
        raise CaptureError(msg)
    if offset + length > SERVICE_WINDOW_LENGTH:
        msg = f"9R range 0x{offset:06X}+{length} exceeds 0x200000"
        raise CaptureError(
            msg,
        )
    encoded_length = 0 if length == SERVICE_MAX_READ else length
    return f"9R {offset:06X},{encoded_length:02X}\r".encode("ascii")


def _parse_9r_response(response: bytes, *, offset: int, length: int) -> bytes:
    """Validate echoed offset, exact uppercase hex length, and terminating CR."""
    if response in (b"?\r", b"N\r"):
        msg = f"9R request at 0x{offset:06X} failed with {response!r}"
        raise CaptureError(msg)
    prefix = f"9R {offset:06X},".encode("ascii")
    expected_length = len(prefix) + 2 * length + 1
    if len(response) != expected_length:
        msg = (
            f"9R response at 0x{offset:06X} is {len(response)} bytes; "
            f"expected {expected_length}"
        )
        raise CaptureError(
            msg,
        )
    if not response.startswith(prefix) or not response.endswith(b"\r"):
        msg = f"9R response has wrong echo/framing at 0x{offset:06X}: {response!r}"
        raise CaptureError(
            msg,
        )
    encoded = response[len(prefix) : -1]
    if any(byte not in b"0123456789ABCDEF" for byte in encoded):
        msg = f"9R response contains non-uppercase-hex data at 0x{offset:06X}"
        raise CaptureError(
            msg,
        )
    return bytes.fromhex(encoded.decode("ascii"))


def _read_9r(link: _SerialLink, *, offset: int, length: int) -> bytes:
    request = _build_9r_request(offset, length)
    response = _exchange_line(
        link,
        request,
        max_response=SERVICE_MAX_RESPONSE,
    )
    return _parse_9r_response(response, offset=offset, length=length)


def _read_exact_cat_response(link: _SerialLink, *, count: int) -> bytes:
    """Read one known-length CAT response without per-character serial calls."""
    deadline = time.monotonic() + link.response_timeout
    response = bytearray()
    while len(response) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            msg = (
                f"timed out reading exact CAT response ({len(response)}/{count} bytes)"
            )
            raise CaptureError(
                msg,
            )
        try:
            # Read the two-byte prefix separately so the radio's complete
            # short error replies (``N\r`` / ``?\r``) fail immediately rather
            # than waiting for the full success-response timeout.
            prefix_remaining = max(0, 2 - len(response))
            requested = prefix_remaining or count - len(response)
            chunk = link.read(requested, timeout=remaining)
        except (OSError, serial.SerialException) as exc:
            msg = f"reading exact CAT response: {exc}"
            raise CaptureError(msg) from exc
        if not chunk:
            msg = (
                f"timed out reading exact CAT response ({len(response)}/{count} bytes)"
            )
            raise CaptureError(
                msg,
            )
        response.extend(chunk)
        if bytes(response) in (b"?\r", b"N\r"):
            return bytes(response)
    return bytes(response)


def _require_cat_quiet(
    link: _SerialLink,
    *,
    duration: float = GM_QUIET_SECONDS,
) -> None:
    """Require a bounded no-byte window; any stale/delayed byte is fatal."""
    try:
        unexpected = link.read(1, timeout=duration)
    except (OSError, serial.SerialException) as exc:
        msg = f"checking CAT quiet window: {exc}"
        raise CaptureError(msg) from exc
    if unexpected:
        msg = f"CAT link was not quiet; received unexpected byte {unexpected!r}"
        raise CaptureError(
            msg,
        )


def _build_gm_request(
    offset: int,
    length: int,
    *,
    patch_attestation: bool = False,
) -> bytes:
    """Build one bounded low-NOR or exact live-patch ``GM`` request.

    The boolean does not waive bounds.  It switches to a finite allowlist of
    exact main-image attestation reads; arbitrary offsets above two MiB remain
    impossible through this builder.
    """
    if not 1 <= length <= GM_MAX_READ:
        msg = f"GM length must be 1..256, got {length}"
        raise CaptureError(msg)
    if patch_attestation:
        allowed = {
            (GM_NOR_BASE_PROBE[0], len(GM_NOR_BASE_PROBE[1])),
            *(
                (address, len(expected))
                for address, expected in GM_NOR_PATCH_ATTESTATIONS
            ),
        }
        if (offset, length) not in allowed:
            msg = (
                "GM request is not an exact live-patch attestation: "
                f"0x{offset:06X}+{length}"
            )
            raise CaptureError(
                msg,
            )
    elif offset < 0 or offset + length > GM_NOR_LENGTH:
        msg = (
            f"GM low-NOR range 0x{offset:06X}+{length} exceeds "
            f"0x000000..0x{GM_NOR_LENGTH - 1:06X}"
        )
        raise CaptureError(
            msg,
        )
    encoded_length = 0 if length == GM_MAX_READ else length
    return f"GM {offset:06X},{encoded_length:02X}\r".encode("ascii")


def _parse_gm_response(response: bytes, *, offset: int, length: int) -> bytes:
    """Validate exact normal-GM echo, uppercase data, size, and framing."""
    if response in (b"?\r", b"N\r"):
        msg = f"GM request at 0x{offset:06X} failed with {response!r}"
        raise CaptureError(msg)
    prefix = f"GM {offset:06X},".encode("ascii")
    expected_length = len(prefix) + 2 * length + 1
    if len(response) != expected_length:
        msg = (
            f"GM response at 0x{offset:06X} is {len(response)} bytes; "
            f"expected {expected_length}"
        )
        raise CaptureError(
            msg,
        )
    if not response.startswith(prefix) or not response.endswith(b"\r"):
        msg = f"GM response has wrong echo/framing at 0x{offset:06X}: {response!r}"
        raise CaptureError(
            msg,
        )
    encoded = response[len(prefix) : -1]
    if any(byte not in b"0123456789ABCDEF" for byte in encoded):
        msg = f"GM response contains non-uppercase-hex data at 0x{offset:06X}"
        raise CaptureError(
            msg,
        )
    return bytes.fromhex(encoded.decode("ascii"))


def _read_gm(
    link: _SerialLink,
    *,
    offset: int,
    length: int,
    patch_attestation: bool = False,
) -> bytes:
    """Perform one exact-length, non-pipelined normal-GM exchange."""
    request = _build_gm_request(
        offset,
        length,
        patch_attestation=patch_attestation,
    )
    _write_exact(link, request)
    response = _read_exact_cat_response(
        link,
        count=10 + 2 * length + 1,
    )
    return _parse_gm_response(response, offset=offset, length=length)


def _read_gm_checked(
    link: _SerialLink,
    *,
    offset: int,
    length: int,
    patch_attestation: bool = False,
) -> bytes:
    """Read once, then prove exact ID and 500 ms quiet; never retry."""
    data = _read_gm(
        link,
        offset=offset,
        length=length,
        patch_attestation=patch_attestation,
    )
    _checkpoint_normal_cat(link)
    return data


def _checkpoint_normal_cat(link: _SerialLink) -> None:
    """Checkpoint command consumption with exact ID and a quiet window."""
    _prove_normal_cat(link)
    _require_cat_quiet(link)


def _run_gm_nor_check(link: _SerialLink) -> bytes:
    """Attest the live patch, then validate only bounded low-NOR reads."""
    _prove_normal_cat(link)
    _prove_v103_firmware(link)
    _require_cat_quiet(link)

    # This must remain the literal first GM command. It distinguishes the
    # NOR-base immediate from the hardware-qualified DDR variant before any
    # unknown low-NOR byte is dereferenced.
    base_address, base_expected = GM_NOR_BASE_PROBE
    base_actual = _read_gm_checked(
        link,
        offset=base_address,
        length=len(base_expected),
        patch_attestation=True,
    )
    if base_actual != base_expected:
        msg = (
            "normal-GM NOR base probe mismatch at "
            f"0x{base_address:06X}: {base_actual.hex()} != {base_expected.hex()}"
        )
        raise CaptureError(
            msg,
        )

    for address, expected in GM_NOR_PATCH_ATTESTATIONS:
        actual = _read_gm_checked(
            link,
            offset=address,
            length=len(expected),
            patch_attestation=True,
        )
        if actual != expected:
            msg = (
                f"normal-GM NOR patch attestation mismatch at 0x{address:06X}: "
                f"{actual.hex()} != {expected.hex()}"
            )
            raise CaptureError(
                msg,
            )

    one = _read_gm_checked(link, offset=0, length=1)
    sixteen = _read_gm_checked(link, offset=0, length=16)
    sixty_four = _read_gm_checked(link, offset=0, length=64)
    maximum = _read_gm_checked(link, offset=0, length=GM_MAX_READ)
    if maximum[:1] != one or maximum[:16] != sixteen or maximum[:64] != sixty_four:
        msg = "normal-GM NOR 1/16/64/256-byte reads disagree"
        raise CaptureError(msg)

    _ = _read_gm_checked(link, offset=GM_NOR_LENGTH - 1, length=1)
    for cycle in range(3):
        repeated = _read_gm_checked(link, offset=0, length=16)
        if repeated != sixteen:
            msg = f"normal-GM NOR repeated 16-byte read disagrees in cycle {cycle + 1}"
            raise CaptureError(
                msg,
            )
    return maximum


def _prove_normal_cat(link: _SerialLink) -> None:
    """Require the exact hardware-verified read-only D75 identity response."""
    response = _exchange_line(
        link,
        NORMAL_CAT_ID,
        max_response=len(NORMAL_CAT_ID_RESPONSE),
    )
    if response != NORMAL_CAT_ID_RESPONSE:
        msg = f"normal-CAT identity response {response!r} != {NORMAL_CAT_ID_RESPONSE!r}"
        raise CaptureError(
            msg,
        )


def _prove_v103_firmware(link: _SerialLink) -> None:
    """Pin the parser semantics to the hardware-observed V1.03 response."""
    response = _exchange_line(
        link,
        NORMAL_CAT_FV,
        max_response=len(NORMAL_CAT_FV_RESPONSE),
    )
    if response != NORMAL_CAT_FV_RESPONSE:
        msg = f"firmware response {response!r} != {NORMAL_CAT_FV_RESPONSE!r}"
        raise CaptureError(
            msg,
        )


def _write_service_entry(
    link: _SerialLink,
    *,
    completion: _WriteCompletion,
) -> None:
    """Write the complete entry command; returning proves no short write."""
    _write_exact(link, SERVICE_ENTER, completion=completion)


def _read_service_entry_response(link: _SerialLink) -> None:
    """Require the silent transition that proves a clean normal-CAT start."""
    response = _read_optional_cr_line(
        link,
        max_length=len(SERVICE_ENTER_ALREADY_ACTIVE_RESPONSE),
    )
    if response == SERVICE_ENTER_ALREADY_ACTIVE_RESPONSE:
        msg = (
            "service entry returned b'0G\\r', proving the radio was already in "
            "service mode; this is not a clean baseline session. Exact service "
            "exit will be attempted, but fully power-cycle before any retry"
        )
        raise CaptureError(msg)
    if response:
        msg = (
            "service entry response is not the required stock silent "
            f"transition: {response!r}"
        )
        raise CaptureError(
            msg,
        )


def _exit_service(link: _SerialLink) -> None:
    response = _exchange_line(link, SERVICE_EXIT, max_response=len(SERVICE_EXIT))
    if response != SERVICE_EXIT:
        msg = f"service exit response {response!r} != {SERVICE_EXIT!r}"
        raise CaptureError(
            msg,
        )


def _run_service_session(
    link: _SerialLink,
    operation: Callable[[_SerialLink], bytes | _Captured],
) -> bytes | _Captured:
    """Prove normal CAT, run one service operation, exit, and prove CAT again."""
    entry_completion = _WriteCompletion()
    operation_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    result: bytes | _Captured | None = None
    try:
        _prove_normal_cat(link)
        _prove_v103_firmware(link)
        _write_service_entry(link, completion=entry_completion)
        _read_service_entry_response(link)
        result = operation(link)
    # BLE001: BaseException is required so a KeyboardInterrupt during a
    # hardware operation still runs the exact service-exit teardown below; the
    # exception is deferred (not re-raised here) so the finally can decide.
    except BaseException as exc:  # noqa: BLE001
        # Cleanup must still run for filesystem failures and interrupts. If it
        # succeeds, the original exception is re-raised unchanged below.
        operation_error = exc
    finally:
        # Never append an exit command to a possibly partial outbound CAT
        # request. Closing plus a mandatory full power-cycle is the only safe
        # recovery for an ambiguous write. Completed-command read/parse/file
        # failures can and must still take the exact service-exit path.
        if entry_completion.completed and not isinstance(
            operation_error,
            _AmbiguousWriteError,
        ):
            try:
                _exit_service(link)
                _prove_normal_cat(link)
            # BLE001: an interrupt or transport error during teardown must be
            # captured (not re-raised here) so it can be combined with any
            # operation error into a single _ServiceCleanupError below.
            except BaseException as cleanup_exc:  # noqa: BLE001
                cleanup_error = cleanup_exc
    if cleanup_error is not None:
        combined = _ServiceCleanupError(operation_error, cleanup_error)
        if operation_error is not None:
            raise combined from operation_error
        raise combined from cleanup_error
    if operation_error is not None:
        if not entry_completion.completed and not isinstance(
            operation_error,
            _AmbiguousWriteError,
        ):
            raise _PreEntryProofError(operation_error) from operation_error
        raise operation_error
    if result is None:
        msg = "service operation produced no result"
        raise CaptureError(msg)
    return result


def _run_patched_9r_check(link: _SerialLink) -> bytes:
    """Run the complete patched-handler gate on an active service link."""
    one = _read_9r(link, offset=0, length=1)
    sixteen = _read_9r(link, offset=0, length=16)
    maximum = _read_9r(link, offset=0, length=256)
    if maximum[:1] != one or maximum[:16] != sixteen:
        msg = "patched 9R 1/16/256-byte reads disagree"
        raise CaptureError(msg)

    last_offset = SERVICE_WINDOW_LENGTH - 1
    _ = _read_9r(link, offset=last_offset, length=1)
    rejected_requests = (
        f"9R {last_offset:06X},02\r".encode("ascii"),
        f"9R {SERVICE_WINDOW_LENGTH:06X},01\r".encode("ascii"),
    )
    for rejected in rejected_requests:
        response = _exchange_line(link, rejected, max_response=2)
        if response != b"N\r":
            msg = f"patched 9R accepted out-of-range request {rejected!r}: {response!r}"
            raise CaptureError(
                msg,
            )
    return maximum


def _capture_gm_nor_check(
    *,
    port: str,
    baud: int,
    timeout: float,
    transport: str,
    verbose: bool,
) -> bytes:
    """Run the exact normal-CAT NOR-patch and bounded-read gate."""
    if verbose:
        print(
            f"opening {port} @ {baud} baud for normal-GM NOR checks",
            file=sys.stderr,
        )
    with _open_service_link(
        port=port,
        baud=baud,
        timeout=timeout,
        transport=transport,
    ) as link:
        # Do not erase evidence of a stale/delayed reply on a newly opened
        # normal-CAT link. A clean-open quiet window is part of the gate.
        _require_cat_quiet(link)
        return _run_gm_nor_check(link)


def _gm_checkpoint_due(completed: int) -> bool:
    """Return whether a completed bulk chunk requires ID plus quiet."""
    return completed == GM_NOR_LENGTH or completed % GM_CHECKPOINT_INTERVAL == 0


def _require_dump_output(output: Path) -> None:
    """Refuse an existing destination or a missing parent directory."""
    if output.exists():
        msg = f"refusing to overwrite existing output: {output}"
        raise CaptureError(msg)
    if not output.parent.is_dir():
        msg = f"output directory does not exist: {output.parent}"
        raise CaptureError(msg)


def _publish_verified_dump(temporary_path: Path, output: Path) -> None:
    """Atomically publish the verified temporary file to ``output``.

    Both paths share a directory, so ``link(2)`` publishes the verified inode
    atomically and, unlike ``replace(2)``, fails rather than overwriting a
    destination that appeared while the long two-pass capture was running.

    Args:
        temporary_path: The verified ``.part`` temporary file.
        output: The destination path to create.

    """
    os.link(temporary_path, output)
    temporary_path.unlink()


def _gm_dump_first_pass(
    link: _SerialLink, temporary: IO[bytes], *, verbose: bool
) -> bytes:
    """Read the low-NOR window once into ``temporary``; return its SHA-256.

    Args:
        link: An open, quiet normal-CAT link past the patch/bounds gate.
        temporary: The destination temporary file, positioned at its start.
        verbose: Whether to print per-checkpoint progress to stderr.

    Returns:
        The SHA-256 digest of the bytes read in this pass.

    Raises:
        CaptureError: On a short file write or a wrong first-pass length.

    """
    first_hash = hashlib.sha256()
    for offset in range(0, GM_NOR_LENGTH, GM_MAX_READ):
        length = min(GM_MAX_READ, GM_NOR_LENGTH - offset)
        data = _read_gm(link, offset=offset, length=length)
        written = temporary.write(data)
        if written != len(data):
            msg = (
                "short first-pass file write at "
                f"offset 0x{offset:06X}: {written}/{len(data)} bytes"
            )
            raise CaptureError(msg)
        first_hash.update(data)
        completed = offset + length
        if _gm_checkpoint_due(completed):
            _checkpoint_normal_cat(link)
        if verbose and completed % GM_CHECKPOINT_INTERVAL == 0:
            print(
                f"  pass 1: {completed:,}/{GM_NOR_LENGTH:,}",
                file=sys.stderr,
            )

    if temporary.tell() != GM_NOR_LENGTH:
        msg = (
            "first-pass temporary file has wrong length: "
            f"{temporary.tell()}/{GM_NOR_LENGTH} bytes"
        )
        raise CaptureError(msg)
    temporary.flush()
    return first_hash.digest()


def _gm_dump_second_pass(
    link: _SerialLink, temporary: IO[bytes], *, verbose: bool
) -> bytes:
    """Re-read the window, comparing each chunk to ``temporary``; return SHA-256.

    Args:
        link: An open, quiet normal-CAT link past the patch/bounds gate.
        temporary: The first-pass temporary file, positioned at its start.
        verbose: Whether to print per-checkpoint progress to stderr.

    Returns:
        The SHA-256 digest of the bytes read in this pass.

    Raises:
        CaptureError: If the temporary file is short or the two passes differ.

    """
    second_hash = hashlib.sha256()
    for offset in range(0, GM_NOR_LENGTH, GM_MAX_READ):
        length = min(GM_MAX_READ, GM_NOR_LENGTH - offset)
        data = _read_gm(link, offset=offset, length=length)
        expected = temporary.read(length)
        if len(expected) != length:
            msg = f"first-pass temporary file became short at offset 0x{offset:06X}"
            raise CaptureError(msg)
        if data != expected:
            msg = f"normal-GM NOR passes differ at offset 0x{offset:06X}"
            raise CaptureError(msg)
        second_hash.update(data)
        completed = offset + length
        if _gm_checkpoint_due(completed):
            _checkpoint_normal_cat(link)
        if verbose and completed % GM_CHECKPOINT_INTERVAL == 0:
            print(
                f"  pass 2: {completed:,}/{GM_NOR_LENGTH:,}",
                file=sys.stderr,
            )
    return second_hash.digest()


def _finalize_gm_dump(
    temporary: IO[bytes], *, first_digest: bytes, second_digest: bytes
) -> None:
    """Require an exact-length file with matching pass digests, then fsync.

    Args:
        temporary: The re-read temporary file, positioned at end of pass two.
        first_digest: SHA-256 of the first pass.
        second_digest: SHA-256 of the second pass.

    Raises:
        CaptureError: On trailing data past the capture, a digest mismatch, or
            a wrong on-disk size before publish.

    """
    if temporary.read(1):
        msg = (
            "first-pass temporary file contains data beyond the "
            f"exact {GM_NOR_LENGTH}-byte capture"
        )
        raise CaptureError(msg)
    if first_digest != second_digest:
        msg = "normal-GM NOR pass SHA-256 mismatch"
        raise CaptureError(msg)
    temporary.flush()
    if os.fstat(temporary.fileno()).st_size != GM_NOR_LENGTH:
        msg = "verified temporary file has wrong length before publish"
        raise CaptureError(msg)
    os.fsync(temporary.fileno())


def _capture_gm_nor_dump(request: _DumpRequest) -> _Captured:
    """Capture two bounded normal-GM passes; atomically publish only a match."""
    _require_dump_output(request.output)
    if request.verbose:
        print(
            f"opening {request.port} @ {request.baud} baud for two-pass "
            "normal-GM NOR dump",
            file=sys.stderr,
        )
    started = time.monotonic()
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{request.output.name}.",
            suffix=".part",
            dir=request.output.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with _open_service_link(
                port=request.port,
                baud=request.baud,
                timeout=request.timeout,
                transport=request.transport,
            ) as link:
                # Preserve and reject stale input rather than discarding it.
                _require_cat_quiet(link)
                _ = _run_gm_nor_check(link)
                first_digest = _gm_dump_first_pass(
                    link, temporary, verbose=request.verbose
                )
                _ = temporary.seek(0)
                second_digest = _gm_dump_second_pass(
                    link, temporary, verbose=request.verbose
                )
                _finalize_gm_dump(
                    temporary,
                    first_digest=first_digest,
                    second_digest=second_digest,
                )
                result = _Captured(
                    path=request.output,
                    base_addr=NOR_BASE,
                    length=GM_NOR_LENGTH,
                    elapsed_seconds=time.monotonic() - started,
                )
        _publish_verified_dump(temporary_path, request.output)
        temporary_path = None
    except OSError as exc:
        msg = f"writing verified normal-GM NOR output: {exc}"
        raise CaptureError(msg) from exc
    else:
        return result
    finally:
        if temporary_path is not None:
            # Preserve the primary capture error. The hidden partial is never
            # promoted to the requested output.
            with contextlib.suppress(OSError):
                temporary_path.unlink(missing_ok=True)


def _capture_9r_baseline(
    *,
    port: str,
    baud: int,
    timeout: float,
    transport: str,
    verbose: bool,
) -> bytes:
    """Run the exact untouched-stock one/one/256-byte service baseline."""
    if verbose:
        print(f"opening {port} @ {baud} baud for raw 9R baseline", file=sys.stderr)
    with _open_service_link(
        port=port,
        baud=baud,
        timeout=timeout,
        transport=transport,
    ) as link:
        _reset_input_buffer(link)

        def baseline(active: _SerialLink) -> bytes:
            first = _read_9r(active, offset=0, length=1)
            duplicate = _read_9r(active, offset=0, length=1)
            maximum = _read_9r(active, offset=0, length=256)
            if first != duplicate or maximum[:1] != first:
                msg = "duplicate/maximum stock 9R reads disagree"
                raise CaptureError(msg)
            return maximum

        result = _run_service_session(link, baseline)
    if not isinstance(result, bytes):
        msg = "internal baseline result type mismatch"
        raise CaptureError(msg)
    return result


def _capture_9r_patched_check(
    *,
    port: str,
    baud: int,
    timeout: float,
    transport: str,
    verbose: bool,
) -> bytes:
    """Validate the patched direct-NOR read path before a full capture."""
    if verbose:
        print(f"opening {port} @ {baud} baud for patched 9R checks", file=sys.stderr)
    with _open_service_link(
        port=port,
        baud=baud,
        timeout=timeout,
        transport=transport,
    ) as link:
        _reset_input_buffer(link)

        result = _run_service_session(link, _run_patched_9r_check)
    if not isinstance(result, bytes):
        msg = "internal patched-check result type mismatch"
        raise CaptureError(msg)
    return result


def _9r_dump_first_pass(
    active: _SerialLink, temporary: IO[bytes], *, verbose: bool
) -> bytes:
    """Read the 2-MiB service window once into ``temporary``; return SHA-256.

    Args:
        active: An active, gated service-mode link.
        temporary: The destination temporary file, positioned at its start.
        verbose: Whether to print per-256-KiB progress to stderr.

    Returns:
        The SHA-256 digest of the bytes read in this pass.

    """
    first_hash = hashlib.sha256()
    for offset in range(0, SERVICE_WINDOW_LENGTH, SERVICE_MAX_READ):
        data = _read_9r(active, offset=offset, length=SERVICE_MAX_READ)
        _ = temporary.write(data)
        first_hash.update(data)
        if verbose and offset and offset % 0x40000 == 0:
            print(
                f"  pass 1: {offset:,}/{SERVICE_WINDOW_LENGTH:,}",
                file=sys.stderr,
            )
    return first_hash.digest()


def _9r_dump_second_pass(
    active: _SerialLink, temporary: IO[bytes], *, verbose: bool
) -> bytes:
    """Re-read the window, comparing each chunk to ``temporary``; return SHA-256.

    Args:
        active: An active, gated service-mode link.
        temporary: The first-pass temporary file, positioned at its start.
        verbose: Whether to print per-256-KiB progress to stderr.

    Returns:
        The SHA-256 digest of the bytes read in this pass.

    Raises:
        CaptureError: If any second-pass chunk differs from the first pass.

    """
    second_hash = hashlib.sha256()
    for offset in range(0, SERVICE_WINDOW_LENGTH, SERVICE_MAX_READ):
        data = _read_9r(active, offset=offset, length=SERVICE_MAX_READ)
        expected = temporary.read(SERVICE_MAX_READ)
        if data != expected:
            msg = f"9R passes differ at offset 0x{offset:06X}"
            raise CaptureError(msg)
        second_hash.update(data)
        if verbose and offset and offset % 0x40000 == 0:
            print(
                f"  pass 2: {offset:,}/{SERVICE_WINDOW_LENGTH:,}",
                file=sys.stderr,
            )
    return second_hash.digest()


def _capture_9r_dump(request: _DumpRequest) -> _Captured:
    """Capture two exact 2-MiB passes and atomically keep only a match."""
    _require_dump_output(request.output)
    if request.verbose:
        print(
            f"opening {request.port} @ {request.baud} baud for two-pass 9R dump",
            file=sys.stderr,
        )
    started = time.monotonic()
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{request.output.name}.",
            suffix=".part",
            dir=request.output.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with _open_service_link(
                port=request.port,
                baud=request.baud,
                timeout=request.timeout,
                transport=request.transport,
            ) as link:
                _reset_input_buffer(link)

                # Do not assume that successful out-of-range rejections leave
                # an unproven service session suitable for bulk reads. Complete
                # the gate's exact exit and normal-CAT proof, then enter a fresh
                # service session for the two capture passes.
                checked = _run_service_session(link, _run_patched_9r_check)
                if not isinstance(checked, bytes):
                    msg = "internal patched-check result type mismatch"
                    raise CaptureError(msg)

                def two_passes(active: _SerialLink) -> _Captured:
                    first_digest = _9r_dump_first_pass(
                        active, temporary, verbose=request.verbose
                    )
                    temporary.flush()
                    _ = temporary.seek(0)
                    second_digest = _9r_dump_second_pass(
                        active, temporary, verbose=request.verbose
                    )
                    if first_digest != second_digest:
                        msg = "9R pass SHA-256 mismatch"
                        raise CaptureError(msg)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    return _Captured(
                        path=request.output,
                        base_addr=NOR_BASE,
                        length=SERVICE_WINDOW_LENGTH,
                        elapsed_seconds=time.monotonic() - started,
                    )

                result = _run_service_session(link, two_passes)
            if not isinstance(result, _Captured):
                msg = "internal dump result type mismatch"
                raise CaptureError(msg)
        _publish_verified_dump(temporary_path, request.output)
        temporary_path = None
    except OSError as exc:
        msg = f"writing verified dump output: {exc}"
        raise CaptureError(msg) from exc
    else:
        return result
    finally:
        if temporary_path is not None:
            # Preserve the primary capture error. A leftover `.part` file is
            # visibly named and never promoted to the requested output.
            with contextlib.suppress(OSError):
                temporary_path.unlink(missing_ok=True)


def _validate_dump_range(base_addr: int, length: int) -> int:
    """Return end address after validating a header-announced NOR range."""
    if length == 0:
        msg = "header announced an empty dump"
        raise CaptureError(msg)
    end_addr = base_addr + length
    if base_addr < NOR_BASE or end_addr > NOR_BASE + NOR_LENGTH:
        msg = (
            f"header range 0x{base_addr:08X}..0x{end_addr:08X} is outside "
            f"TH-D75 NOR window 0x{NOR_BASE:08X}.."
            f"0x{NOR_BASE + NOR_LENGTH:08X}"
        )
        raise CaptureError(msg)
    return end_addr


def _capture(
    *,
    port: str,
    baud: int,
    timeout: float,
    output: Path,
    verbose: bool,
) -> _Captured:
    """Open ``port`` at ``baud``; read header; stream payload to ``output``."""
    if verbose:
        print(f"opening {port} @ {baud} baud", file=sys.stderr)
    with serial.Serial(port=port, baudrate=baud, timeout=timeout) as link:
        header = _read_exact(link, HEADER_LEN)
        if header[: len(MAGIC)] != MAGIC:
            msg = (
                f"bad magic: got {header[: len(MAGIC)]!r}, expected "
                f"{MAGIC!r} (is the dumper actually running? did you "
                "set the right baud?)"
            )
            raise CaptureError(msg)
        base_addr: int
        length: int
        (base_addr, length) = struct.unpack("<II", header[len(MAGIC) :])
        _ = _validate_dump_range(base_addr, length)
        if verbose:
            print(
                f"header: base=0x{base_addr:08X} length={length:,} bytes",
                file=sys.stderr,
            )
        start = time.monotonic()
        bytes_written = _stream_to_file(link, output, length, verbose=verbose)
        elapsed = time.monotonic() - start
    if bytes_written != length:
        msg = f"short read: got {bytes_written:,} bytes, header announced {length:,}"
        raise CaptureError(msg)
    return _Captured(
        path=output,
        base_addr=base_addr,
        length=length,
        elapsed_seconds=elapsed,
    )


def _read_exact(link: serial.Serial, count: int) -> bytes:
    """Read exactly ``count`` bytes or raise."""
    buf = bytearray()
    while len(buf) < count:
        chunk = link.read(count - len(buf))
        if not chunk:
            msg = f"timed out reading header ({len(buf)}/{count} bytes)"
            raise CaptureError(msg)
        buf.extend(chunk)
    return bytes(buf)


def _stream_to_file(
    link: serial.Serial,
    output: Path,
    expected: int,
    *,
    verbose: bool,
) -> int:
    """Stream up to ``expected`` bytes from ``link`` to ``output``; return written."""
    chunk_size = 4096
    written = 0
    next_progress = 1024 * 256  # report every 256 KiB
    with output.open("wb") as out:
        while written < expected:
            to_read = min(chunk_size, expected - written)
            chunk = link.read(to_read)
            if not chunk:
                break
            _ = out.write(chunk)
            written += len(chunk)
            if verbose and written >= next_progress:
                print(f"  {written:,}/{expected:,} bytes", file=sys.stderr)
                next_progress += 1024 * 256
    return written


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="capture_dump",
        description=(
            "Receive the existing D75D stream, baseline untouched-stock raw "
            "service 9R, or perform a strict two-pass capture through either "
            "the audited patched 9R handler or exact normal-GM NOR artifact."
        ),
        epilog=(
            "Exact normal-gm-nor-read artifact pins:\n"
            f"  raw SHA-256:           {GM_NOR_RAW_SHA256}\n"
            f"  plaintext KEX SHA-256: {GM_NOR_KEX_SHA256}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument(
        "--mode",
        choices=(
            "d75d",
            "gm-nor-check",
            "gm-nor-dump",
            "9r-baseline",
            "9r-patched-check",
            "9r-dump",
        ),
        default="d75d",
        help="Host protocol (default: legacy d75d stream receiver)",
    )
    _ = parser.add_argument(
        "--port",
        help=(
            "Explicit serial port. Audited USB CAT modes default to exact "
            "VID:PID 2166:9023 discovery; legacy d75d requires an explicit path."
        ),
    )
    _ = parser.add_argument(
        "--baud",
        type=int,
        default=None,
        help=(
            "Explicit host serial setting. Defaults: d75d/USB CAT 115200, "
            "Bluetooth SPP 9600; the official manual says virtual USB/SPP "
            "baud selection is not a radio wire-rate requirement."
        ),
    )
    _ = parser.add_argument(
        "--transport",
        choices=("usb", "bluetooth"),
        default="usb",
        help=(
            "CAT transport. Service-mode Bluetooth fails closed in this Python "
            "receiver on every platform. The sibling fixed baseline also "
            "refuses native IOBluetooth until canceled-write teardown is "
            "bounded and re-audited. USB disables unproven flow control "
            "(default: usb)"
        ),
    )
    _ = parser.add_argument(
        "--acknowledge-cat-preflight",
        action="store_true",
        help=(
            "Required for every audited CAT mode. Confirms Menu 980 is COM + AF/IF "
            "Output; Menus 405/590 PC Output are Off; KISS and DV/DR are "
            "inactive; and DV Gateway state/interface were recorded with the "
            "selected CAT interface not consumed. Also confirms every other "
            "CAT/MCP client is closed and the unused radio transport is "
            "disconnected."
        ),
    )
    _ = parser.add_argument(
        "--acknowledge-stock-v103-restored",
        action="store_true",
        help=(
            "Required for 9r-baseline. Confirms official stock V1.03 was "
            "freshly restored, the radio was fully power-cycled afterward, "
            "and no modified main firmware has been written since. The FV "
            "query confirms version only, not byte identity."
        ),
    )
    _ = parser.add_argument(
        "--allow-patched-9r",
        action="store_true",
        help=(
            "Required for 9r-patched-check/9r-dump. Confirms untouched-stock "
            "baseline and the separately audited modified-main 9R handler are "
            "already present. 9r-dump always repeats the complete patched "
            "small-read/bounds check before its first bulk read."
        ),
    )
    _ = parser.add_argument(
        "--acknowledge-gm-nor-read",
        action="store_true",
        help=(
            "Required for gm-nor-check/gm-nor-dump. Confirms the radio was "
            "flashed with exact normal-gm-nor-read raw SHA-256 "
            f"{GM_NOR_RAW_SHA256} and plaintext KEX SHA-256 "
            f"{GM_NOR_KEX_SHA256}, then fully power-cycled into normal mode; "
            "also confirms every other CAT/MCP client is closed. Live patch "
            "bytes are still attested before any low-NOR read."
        ),
    )
    _ = parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("dump.bin"),
        help="Output file (default: dump.bin)",
    )
    _ = parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Absolute deadline for each complete CAT response (default: 10)",
    )
    _ = parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print progress to stderr",
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite positive number")
    gm_modes = ("gm-nor-check", "gm-nor-dump")
    service_modes = ("9r-baseline", "9r-patched-check", "9r-dump")
    audited_cat_modes = (*gm_modes, *service_modes)
    if args.mode in gm_modes and not args.acknowledge_gm_nor_read:
        parser.error(
            f"--mode {args.mode} requires --acknowledge-gm-nor-read",
        )
    if args.mode not in gm_modes and args.acknowledge_gm_nor_read:
        parser.error(
            "--acknowledge-gm-nor-read is valid only with "
            "--mode gm-nor-check or gm-nor-dump",
        )
    if args.mode in gm_modes and args.transport != "usb":
        parser.error(f"--mode {args.mode} is USB-only")
    if args.mode in audited_cat_modes and not args.acknowledge_cat_preflight:
        parser.error(
            f"--mode {args.mode} requires --acknowledge-cat-preflight",
        )
    if args.mode not in audited_cat_modes and args.acknowledge_cat_preflight:
        parser.error(
            "--acknowledge-cat-preflight is valid only with an audited CAT mode",
        )
    if args.mode == "9r-baseline" and not args.acknowledge_stock_v103_restored:
        parser.error(
            "--mode 9r-baseline requires --acknowledge-stock-v103-restored",
        )
    if args.mode != "9r-baseline" and args.acknowledge_stock_v103_restored:
        parser.error(
            "--acknowledge-stock-v103-restored is valid only with --mode 9r-baseline",
        )
    if args.mode not in ("9r-patched-check", "9r-dump") and args.allow_patched_9r:
        parser.error(
            "--allow-patched-9r is valid only with --mode 9r-patched-check or 9r-dump",
        )
    return args


if __name__ == "__main__":
    sys.exit(main())
