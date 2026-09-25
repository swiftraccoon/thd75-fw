"""Tests for the exclusive FLDM serial-device boundary."""

from __future__ import annotations

import os
import pty
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
import serial

from thd75_fw.flash.protocol import Frame, ResponseReader, build_frame
from thd75_fw.flash.serial_io import (
    ReferenceSerialIO,
    ReferenceSerialOptions,
    SerialCloseError,
    SerialIO,
)
from thd75_fw.flash.session import FlashError

if TYPE_CHECKING:
    from collections.abc import Generator

    from _pytest.monkeypatch import MonkeyPatch


class _DtrFailingPort:
    def __init__(self, *, close_error: BaseException | None = None) -> None:
        super().__init__()
        self.is_open = True
        self.close_error = close_error
        self.close_calls = 0
        self.write_calls = 0

    @property
    def dtr(self) -> bool:
        return False

    @dtr.setter
    def dtr(self, enabled: bool) -> None:
        assert enabled is True
        msg = "simulated DTR assertion failure"
        raise OSError(msg)

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self.is_open = False

    def write(self, data: bytes) -> int:
        self.write_calls += 1
        return len(data)


def test_open_is_exclusive_before_any_loader_io(monkeypatch: MonkeyPatch) -> None:
    raw = MagicMock()
    raw.is_open = True
    constructor = MagicMock(return_value=raw)
    monkeypatch.setattr(serial, "Serial", constructor)

    transport = SerialIO("/dev/cu.usbmodem-test", baud=9600, timeout=1.0)

    assert constructor.call_args.kwargs["exclusive"] is True
    raw.write.assert_not_called()
    transport.close()


def test_busy_exclusive_open_refuses_before_transport_exists(
    monkeypatch: MonkeyPatch,
) -> None:
    constructor = MagicMock(side_effect=serial.SerialException("device busy"))
    monkeypatch.setattr(serial, "Serial", constructor)

    with pytest.raises(serial.SerialException, match="device busy"):
        _ = SerialIO("/dev/cu.usbmodem-test", baud=9600, timeout=1.0)

    assert constructor.call_args.kwargs["exclusive"] is True


@pytest.mark.parametrize("close_also_fails", [False, True])
def test_dtr_initialization_failure_closes_and_preserves_both_errors(
    monkeypatch: MonkeyPatch,
    *,
    close_also_fails: bool,
) -> None:
    raw = _DtrFailingPort(
        close_error=(
            OSError("simulated init-cleanup close failure")
            if close_also_fails
            else None
        )
    )
    monkeypatch.setattr(
        serial,
        "Serial",
        MagicMock(return_value=raw),
    )

    expected_error = SerialCloseError if close_also_fails else OSError
    with pytest.raises(expected_error) as exc_info:
        _ = SerialIO("/dev/cu.usbmodem-test", baud=9600, timeout=1.0)

    assert raw.close_calls == 1
    assert raw.write_calls == 0
    assert "simulated DTR assertion failure" in str(exc_info.value)
    if close_also_fails:
        assert "simulated init-cleanup close failure" in str(exc_info.value)
        assert isinstance(exc_info.value, SerialCloseError)
        assert isinstance(exc_info.value.operation_error, OSError)


def _leave_context(
    transport: SerialIO | ReferenceSerialIO,
    operation_error: BaseException | None,
) -> None:
    """Exit ``transport``'s context, raising ``operation_error`` inside it first."""
    with transport:
        if operation_error is not None:
            raise operation_error


@pytest.mark.parametrize("operation_fails", [False, True])
def test_context_preserves_close_failure_and_prior_operation(
    monkeypatch: MonkeyPatch,
    *,
    operation_fails: bool,
) -> None:
    raw = MagicMock()
    raw.is_open = True
    raw.close.side_effect = OSError("simulated close failure")
    monkeypatch.setattr(
        serial,
        "Serial",
        MagicMock(return_value=raw),
    )
    transport = SerialIO("/dev/cu.usbmodem-test", baud=9600, timeout=1.0)
    operation_error = FlashError(
        step="QUERY_TARGET",
        cause="simulated operation failure",
        recoverable=True,
    )

    with pytest.raises(SerialCloseError) as exc_info:
        _leave_context(transport, operation_error if operation_fails else None)

    error = exc_info.value
    assert isinstance(error.close_error, OSError)
    assert error.operation_error is (operation_error if operation_fails else None)
    assert "simulated close failure" in str(error)
    assert "MANDATORY: disconnect USB and fully power-cycle" in str(error)
    if operation_fails:
        assert "QUERY_TARGET" in str(error)
        assert "simulated operation failure" in str(error)


# ─── SerialIO.read against a real pyserial port ────────────────────────────
#
# These bind pyserial to a PTY from ``pty.openpty()``. No radio and no
# ``/dev/cu.*`` are involved, but the code under test is the shipping
# ``serialposix.Serial.read`` with its real ``select``/timeout loop, which is
# the whole subject: whether a reply costs a round trip or a fixed timeout.
#
# The port timeout is deliberately generous relative to a PTY round trip
# (microseconds), so "returned promptly" and "waited out the timeout" are
# separated by orders of magnitude and the assertions cannot flake on a loaded
# machine.
_PORT_TIMEOUT = 1.0

#: What a real D75 V1.03 loader sends to acknowledge a framed command.
_FRAMED_ACK = build_frame(Frame(header=0, verb=0x06, payload=b""), xor_key=0)


@contextmanager
def _pty_transport(
    timeout: float = _PORT_TIMEOUT,
) -> Generator[tuple[int, SerialIO], None, None]:
    """Yield ``(writer_fd, transport)`` for a SerialIO bound to a PTY.

    ``__init__`` is bypassed because its one un-fakeable step is the DTR
    assertion, and ``TIOCMBIS`` on a PTY fails with ``ENOTTY``. Everything
    ``read`` depends on is the port object, which is a genuine
    ``serial.Serial``. The constructor's own behaviour (exclusive open, DTR
    failure cleanup) is covered by the mock-based tests above.
    """
    controller, device = pty.openpty()
    port = serial.Serial(
        port=os.ttyname(device),
        baudrate=115200,
        timeout=timeout,
    )
    os.close(device)
    transport = SerialIO.__new__(SerialIO)
    transport._port = port
    try:
        yield controller, transport
    finally:
        transport.close()
        os.close(controller)


def test_read_returns_a_single_ack_byte_without_waiting_for_the_timeout() -> None:
    """The loader's cleartext acknowledgement is one byte; it must cost one."""
    with _pty_transport() as (writer, transport):
        _ = os.write(writer, b"\x06")
        start = time.monotonic()
        data = transport.read(1)
        elapsed = time.monotonic() - start

    assert data == b"\x06"
    assert elapsed < _PORT_TIMEOUT / 4, (
        f"a one-byte ACK took {elapsed:.3f}s of a {_PORT_TIMEOUT}s port "
        "timeout; the read is paying the timeout instead of the round trip"
    )


def test_read_of_a_whole_reply_costs_a_round_trip_not_a_timeout() -> None:
    """The regression this file exists to pin.

    Asking for a round number the loader never sends (the old ``read(256)``)
    leaves pyserial parked in ``select`` until the port timeout, once per
    reply. Asking for the reply's actual length returns as it lands.
    """
    with _pty_transport() as (writer, transport):
        _ = os.write(writer, _FRAMED_ACK)
        start = time.monotonic()
        data = transport.read(len(_FRAMED_ACK))
        exact_elapsed = time.monotonic() - start

        _ = os.write(writer, _FRAMED_ACK)
        start = time.monotonic()
        overshoot = transport.read(256)
        overshoot_elapsed = time.monotonic() - start

    assert data == _FRAMED_ACK
    assert exact_elapsed < _PORT_TIMEOUT / 4

    # Same bytes, same port: the only difference is the requested count.
    assert overshoot == _FRAMED_ACK
    assert overshoot_elapsed >= _PORT_TIMEOUT / 2, (
        "over-requesting is expected to cost the port timeout; if this ever "
        "stops being true the exact-count contract can be relaxed"
    )


def test_read_waits_for_a_reply_fragmented_across_arrivals() -> None:
    """A frame split in transit must come back whole, not as its first byte.

    USB-CDC can deliver a nine-byte reply as a one-byte head and an eight-byte
    tail. Requesting the full count makes the kernel wait for the tail instead
    of handing back a fragment the caller has to re-enter for.
    """
    tail_delay = 0.05
    with _pty_transport() as (writer, transport):
        _ = os.write(writer, _FRAMED_ACK[:1])
        timer = threading.Timer(
            tail_delay,
            lambda: os.write(writer, _FRAMED_ACK[1:]),
        )
        timer.start()
        try:
            start = time.monotonic()
            data = transport.read(len(_FRAMED_ACK))
            elapsed = time.monotonic() - start
        finally:
            timer.join()

    assert data == _FRAMED_ACK, "read returned a fragment, not the whole frame"
    assert elapsed >= tail_delay * 0.8, (
        "read returned before the tail was written, so it cannot have waited for it"
    )
    assert elapsed < _PORT_TIMEOUT / 2


def test_read_returns_empty_when_the_timeout_expires_with_no_data() -> None:
    """Silence is reported as ``b""`` after the timeout, not as an error."""
    timeout = 0.1
    with _pty_transport(timeout=timeout) as (_writer, transport):
        start = time.monotonic()
        data = transport.read(9)
        elapsed = time.monotonic() - start

    assert data == b""
    assert elapsed >= timeout * 0.8, (
        f"returned empty after only {elapsed:.3f}s of a {timeout}s timeout"
    )


def test_read_returns_a_short_result_when_the_timeout_beats_the_rest() -> None:
    """A partial arrival is handed back at the deadline, not discarded.

    ``ResponseReader`` reassembles across reads, so the caller's next request
    completes the frame. Dropping the fragment here would desynchronise it.
    """
    timeout = 0.1
    with _pty_transport(timeout=timeout) as (writer, transport):
        _ = os.write(writer, _FRAMED_ACK[:4])
        data = transport.read(len(_FRAMED_ACK))

    assert data == _FRAMED_ACK[:4]


@pytest.mark.parametrize("max_bytes", [0, -1, -256])
def test_read_of_a_non_positive_count_consumes_nothing(max_bytes: int) -> None:
    """Zero means zero. A stolen byte desynchronises the whole session.

    Replies are classified by their first byte (unframed ACK/BUSY/NAK versus
    the ``SYNC`` that opens a framed reply), so a byte consumed by a caller
    that asked for none is not recoverable: every subsequent response is read
    one byte out of phase.
    """
    with _pty_transport() as (writer, transport):
        _ = os.write(writer, b"\x06")
        start = time.monotonic()
        data = transport.read(max_bytes)
        elapsed = time.monotonic() - start
        # The waiting ACK must still be there for the next real read.
        follow_up = transport.read(1)

    assert data == b""
    assert elapsed < _PORT_TIMEOUT / 4, "a no-op read must not touch the port"
    assert follow_up == b"\x06", f"read({max_bytes}) consumed the pending ACK byte"


# ─── ReferenceSerialIO ─────────────────────────────────────────────────────
#
# ``ReferenceSerialIO`` reproduces the port of the reference client
# (``ref/openwood/fldm.py``) so a hardware run can attribute a failure to the
# transport or rule it out. This comment used to say that client "is confirmed
# to complete a full macOS flash in about a minute"; that is UNVERIFIED (no
# timing is recorded anywhere in this repo, and openwood is a TH-D74 client).
# The value here is a second independent implementation to differ against.
# These tests pin what makes it a reproduction rather than an approximation:
# the exact construction keywords, the buffer resets, the drain, the
# exact-count reads, and the refusal to reconfigure a live port.

#: The exact keyword set ``FLDMLoader.__init__`` builds its port with.
#: Membership is as load-bearing as the values: no ``exclusive`` means no
#: ``flock(LOCK_EX | LOCK_NB)``, and no ``rtscts``/``dsrdtr`` means pyserial's
#: own defaults apply rather than ours.
_REFERENCE_PORT_KWARGS = {
    "port": "/dev/cu.usbmodem-test",
    "baudrate": 576_000,
    "bytesize": 8,
    "parity": "N",
    "stopbits": 1,
    "timeout": 0.25,
    "write_timeout": 1,
}

#: The reference's read timeout, restated here so a change to the class has to
#: be a change to this file too.
_REFERENCE_READ_TIMEOUT = 0.25

#: Upper bound for the PTY reader thread used by the write/flush smoke test.
_PTY_READER_TIMEOUT = 2.0


class _FakeReferencePort:
    """Stand-in for ``serial.Serial`` with scripted reads and flush failures.

    ``reads`` is a sequence of arrivals. Each ``read`` pulls the next arrival
    when nothing is buffered and then returns at most the requested count,
    which is what a real port does and what makes a short return - the thing
    the caller must reassemble across - reproducible.
    """

    def __init__(
        self,
        *,
        reads: tuple[bytes, ...] = (),
        reset_input_error: BaseException | None = None,
        flush_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        super().__init__()
        self.is_open = True
        self.baudrate = 0
        self.calls: list[str] = []
        self.written = bytearray()
        self.read_requests: list[int] = []
        self.control_line_writes: list[tuple[str, bool]] = []
        self.close_calls = 0
        #: Writes to ``timeout``. Each one runs ``_reconfigure_port`` on a real
        #: open port, which is the reference behaviour being reproduced.
        self.timeout_writes = 0
        #: ``timeout_writes`` sampled at the top of each ``read``, so a test
        #: can assert the write happened *before* the read rather than merely
        #: at some point during the session.
        self.timeout_writes_at_read: list[int] = []
        self._timeout: float | None = None
        self._arrivals = list(reads)
        self._inbox = bytearray()
        self._reset_input_error = reset_input_error
        self._flush_error = flush_error
        self._close_error = close_error

    # ``dtr`` and ``rts`` exist only to catch an assignment. The reference
    # never writes either; pyserial asserts both at open on its own, so an
    # explicit write here would be a divergence, not a safeguard.
    @property
    def dtr(self) -> bool:
        return True

    @dtr.setter
    def dtr(self, enabled: bool) -> None:
        self.control_line_writes.append(("dtr", enabled))

    @property
    def rts(self) -> bool:
        return True

    @rts.setter
    def rts(self, enabled: bool) -> None:
        self.control_line_writes.append(("rts", enabled))

    def write(self, data: bytes) -> int:
        self.calls.append("write")
        self.written.extend(data)
        return len(data)

    def flush(self) -> None:
        self.calls.append("flush")
        if self._flush_error is not None:
            raise self._flush_error

    @property
    def timeout(self) -> float | None:
        return self._timeout

    @timeout.setter
    def timeout(self, value: float | None) -> None:
        self._timeout = value
        self.timeout_writes += 1

    def read(self, size: int) -> bytes:
        self.read_requests.append(size)
        self.timeout_writes_at_read.append(self.timeout_writes)
        if not self._inbox and self._arrivals:
            self._inbox.extend(self._arrivals.pop(0))
        chunk = bytes(self._inbox[:size])
        del self._inbox[:size]
        return chunk

    def reset_input_buffer(self) -> None:
        self.calls.append("reset_input_buffer")
        if self._reset_input_error is not None:
            raise self._reset_input_error

    def reset_output_buffer(self) -> None:
        self.calls.append("reset_output_buffer")

    def close(self) -> None:
        self.close_calls += 1
        if self._close_error is not None:
            raise self._close_error
        self.is_open = False


def _install_fake_port(
    monkeypatch: MonkeyPatch,
    port: _FakeReferencePort,
) -> MagicMock:
    """Bind ``serial.Serial`` to ``port`` and hand back the constructor."""
    constructor = MagicMock(return_value=port)
    monkeypatch.setattr(serial, "Serial", constructor)
    return constructor


def test_reference_open_matches_the_reference_port_construction(
    monkeypatch: MonkeyPatch,
) -> None:
    """Equality, not a subset: an extra keyword is a divergence too."""
    port = _FakeReferencePort()
    constructor = _install_fake_port(monkeypatch, port)

    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    assert constructor.call_args.args == ()
    assert constructor.call_args.kwargs == _REFERENCE_PORT_KWARGS
    assert transport.baud == 576_000
    transport.close()


def test_reference_open_takes_no_lock_and_writes_no_control_line(
    monkeypatch: MonkeyPatch,
) -> None:
    """Three differences from ``SerialIO``, all of them omissions.

    ``SerialIO`` passes ``exclusive=True`` (a ``flock``), spells out
    ``rtscts``/``dsrdtr``, and writes ``dtr`` after open. The reference does
    none of it, and pyserial already asserts DTR and RTS at open, so the
    explicit write only adds an ioctl that can fail on a device where
    ``TIOCMBIS`` returns ``ENOTTY``.
    """
    port = _FakeReferencePort()
    constructor = _install_fake_port(monkeypatch, port)

    _ = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    assert "exclusive" not in constructor.call_args.kwargs
    assert "rtscts" not in constructor.call_args.kwargs
    assert "dsrdtr" not in constructor.call_args.kwargs
    assert port.control_line_writes == []


def test_reference_open_resets_input_then_output_buffers(
    monkeypatch: MonkeyPatch,
) -> None:
    """Pyserial's ``open()`` flushes input only; the output side is ours.

    Anything a previous session left queued for transmission would otherwise
    be prepended to the first unlock byte of this one.
    """
    port = _FakeReferencePort()
    _ = _install_fake_port(monkeypatch, port)

    _ = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    assert port.calls == ["reset_input_buffer", "reset_output_buffer"]


def test_reference_write_calls_write_then_flush(
    monkeypatch: MonkeyPatch,
) -> None:
    """Match OpenWood's literal ``write`` then ``flush`` send ordering."""
    port = _FakeReferencePort()
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)
    port.calls.clear()

    written = transport.write(_FRAMED_ACK)

    assert written == len(_FRAMED_ACK)
    assert bytes(port.written) == _FRAMED_ACK
    assert port.calls == ["write", "flush"]


def test_reference_write_propagates_flush_failure_after_writing(
    monkeypatch: MonkeyPatch,
) -> None:
    """A failed tcdrain must not be mistaken for a completed transmission."""
    port = _FakeReferencePort(flush_error=OSError("simulated tcdrain failure"))
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)
    port.calls.clear()

    with pytest.raises(OSError, match="simulated tcdrain failure"):
        _ = transport.write(_FRAMED_ACK)

    assert bytes(port.written) == _FRAMED_ACK
    assert port.calls == ["write", "flush"]


def test_reference_read_requests_the_exact_outstanding_count(
    monkeypatch: MonkeyPatch,
) -> None:
    """The reference's ``_recv_exact`` asks for what is missing, never a ceiling."""
    port = _FakeReferencePort(reads=(_FRAMED_ACK,))
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    data = transport.read(len(_FRAMED_ACK))

    assert data == _FRAMED_ACK
    assert port.read_requests == [len(_FRAMED_ACK)]


@pytest.mark.parametrize("max_bytes", [0, -1])
def test_reference_read_of_a_non_positive_count_touches_nothing(
    monkeypatch: MonkeyPatch,
    max_bytes: int,
) -> None:
    """Zero means zero; a stolen byte desynchronises the whole session."""
    port = _FakeReferencePort(reads=(b"\x06",))
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    assert transport.read(max_bytes) == b""
    assert port.read_requests == []
    assert port.timeout_writes == 0, "a no-op read reconfigured the port"
    assert transport.read(1) == b"\x06", "the pending ACK byte was consumed"


def test_reference_read_reasserts_the_timeout_first_like_recv_exact(
    monkeypatch: MonkeyPatch,
) -> None:
    """``_recv_exact`` writes the ceiling before every read, so this does too.

    The write is not about the timeout - the port already holds that value.
    It is about the ``_reconfigure_port`` the setter runs, which at a baud
    macOS termios does not know (576000 is one) re-applies the rate through
    ``IOSSIOSPEED`` on every call, because ``_set_special_baudrate`` sits
    outside that function's "did anything change" guard. Reproduced so the
    differential test actually removes that difference; nothing here claims
    the ioctl matters.
    """
    port = _FakeReferencePort(reads=(b"\x06", b"\x06", b"\x06"))
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    for _ in range(3):
        assert transport.read(1) == b"\x06"

    assert port.timeout == 0.25, "the re-asserted ceiling is not the reference's"
    # One write strictly before each read, never batched or skipped.
    assert port.timeout_writes_at_read == [1, 2, 3]


def test_reference_read_can_skip_the_reassertion(
    monkeypatch: MonkeyPatch,
) -> None:
    """The ioctl-per-read is reproducible, and also switchable.

    Read semantics are identical either way - the port timeout is already the
    value being written - so this is the lever to pull if that ioctl ever
    turns out to be the problem rather than the cure.
    """
    port = _FakeReferencePort(reads=(b"\x06",))
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO(
        "/dev/cu.usbmodem-test",
        baud=576_000,
        options=ReferenceSerialOptions(reassert_read_timeout=False),
    )

    assert transport.read(1) == b"\x06"
    assert port.timeout_writes == 0


def test_reference_reads_reassemble_a_frame_fragmented_across_reads(
    monkeypatch: MonkeyPatch,
) -> None:
    """A reply split across USB transfers must decode as one whole frame.

    Each read returns only what has landed, so a caller that asks for the
    whole reply still gets a short result. ``ResponseReader`` holds the
    partial and the caller re-enters; that loop is the reference's
    ``_recv_exact``. Drive it here and prove the frame comes back out intact.

    The loop deliberately asks for the frame length every time rather than
    consulting the decoder for an outstanding count. Reassembly is a property
    of the transport plus the reader, and it has to hold whatever sizing
    policy the caller uses.
    """
    fragments = (_FRAMED_ACK[:1], _FRAMED_ACK[1:4], _FRAMED_ACK[4:])
    assert b"".join(fragments) == _FRAMED_ACK, "fragments must cover the frame"
    port = _FakeReferencePort(reads=fragments)
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)
    reader = ResponseReader(xor_key=0)

    decoded: list[object] = []
    reads: list[bytes] = []
    for _ in range(len(fragments) + 2):
        if decoded:
            break
        chunk = transport.read(len(_FRAMED_ACK))
        reads.append(chunk)
        decoded.extend(reader.feed(chunk))

    assert len(reads) > 1, "the frame arrived in one read; nothing was reassembled"
    assert all(len(chunk) < len(_FRAMED_ACK) for chunk in reads), (
        "a read returned the whole frame, so no fragment was ever held"
    )
    assert b"".join(reads) == _FRAMED_ACK, "the reads did not cover the frame"
    assert len(decoded) == 1
    frame = decoded[0]
    assert isinstance(frame, Frame)
    assert frame.verb == 0x06
    assert frame.payload == b""
    assert not reader.has_partial(), "a fragment was left behind"


def test_reference_set_baud_at_the_open_baud_is_a_no_op(
    monkeypatch: MonkeyPatch,
) -> None:
    """The port is already there, so honouring the request is doing nothing."""
    port = _FakeReferencePort()
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    transport.set_baud(576_000)

    assert transport.baud == 576_000
    assert transport.baud_reconfigurations == 0
    assert port.baudrate == 0, "a no-op request rewrote the live port"


def test_reference_set_baud_refuses_to_reconfigure_a_live_port(
    monkeypatch: MonkeyPatch,
) -> None:
    """The difference this class exists to isolate.

    On macOS ``Serial.baudrate = 576000`` runs ``_reconfigure_port``, which
    finds no ``termios.B576000``, applies ``tcsetattr(TCSANOW, ..., B38400)``
    because the computed attributes now differ, and only then the real rate
    through the ``IOSSIOSPEED`` ioctl - a transition down to 38400 and back
    up, on a live CDC device, mid-session.

    The reference never *moves* the rate. It does re-apply the one it opened
    with, on every read, because ``_recv_exact`` writes ``timeout`` and that
    setter re-runs ``_reconfigure_port`` (see
    ``test_reference_read_reasserts_the_timeout_first_like_recv_exact``). The
    distinction is the whole point: re-asserting is not the same as moving,
    and only moving passes through B38400. Failing closed beats silently
    reproducing it.
    """
    port = _FakeReferencePort()
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    with pytest.raises(ValueError, match="refusing to reconfigure a live port"):
        transport.set_baud(19_200)

    assert port.baudrate == 0
    assert transport.baud == 576_000
    assert transport.baud_reconfigurations == 0


def test_reference_set_baud_reconfigures_when_strictness_is_waived(
    monkeypatch: MonkeyPatch,
) -> None:
    """``strict_baud=False`` restores ``SerialIO``'s behaviour, and counts it."""
    port = _FakeReferencePort()
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO(
        "/dev/cu.usbmodem-test",
        baud=576_000,
        options=ReferenceSerialOptions(strict_baud=False),
    )

    transport.set_baud(19_200)

    assert port.baudrate == 19_200
    assert transport.baud == 19_200
    assert transport.baud_reconfigurations == 1


def test_reference_discard_input_flushes_only_the_input_side(
    monkeypatch: MonkeyPatch,
) -> None:
    """Discarding queued input must not also discard a queued frame."""
    port = _FakeReferencePort()
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)
    port.calls.clear()

    transport.discard_input()

    assert port.calls == ["reset_input_buffer"]


@pytest.mark.parametrize("close_also_fails", [False, True])
def test_reference_initialization_failure_closes_and_preserves_both_errors(
    monkeypatch: MonkeyPatch,
    *,
    close_also_fails: bool,
) -> None:
    """The reference would leak the descriptor here; this must not.

    The port is open by the time the buffer resets run, so a failure has to
    close it, and a simultaneous close failure must not erase the cause.
    """
    port = _FakeReferencePort(
        reset_input_error=OSError("simulated buffer reset failure"),
        close_error=(
            OSError("simulated init-cleanup close failure")
            if close_also_fails
            else None
        ),
    )
    _ = _install_fake_port(monkeypatch, port)

    expected_error = SerialCloseError if close_also_fails else OSError
    with pytest.raises(expected_error) as exc_info:
        _ = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)

    assert port.close_calls == 1
    assert bytes(port.written) == b"", "a failed open wrote to the loader"
    assert "simulated buffer reset failure" in str(exc_info.value)
    if close_also_fails:
        assert "simulated init-cleanup close failure" in str(exc_info.value)
        assert isinstance(exc_info.value, SerialCloseError)
        assert isinstance(exc_info.value.operation_error, OSError)


@pytest.mark.parametrize("operation_fails", [False, True])
def test_reference_context_preserves_close_failure_and_prior_operation(
    monkeypatch: MonkeyPatch,
    *,
    operation_fails: bool,
) -> None:
    """Same ``SerialCloseError`` contract as ``SerialIO``, for the same reason."""
    port = _FakeReferencePort(close_error=OSError("simulated close failure"))
    _ = _install_fake_port(monkeypatch, port)
    transport = ReferenceSerialIO("/dev/cu.usbmodem-test", baud=576_000)
    operation_error = FlashError(
        step="QUERY_TARGET",
        cause="simulated operation failure",
        recoverable=True,
    )

    with pytest.raises(SerialCloseError) as exc_info:
        _leave_context(transport, operation_error if operation_fails else None)

    error = exc_info.value
    assert isinstance(error.close_error, OSError)
    assert error.operation_error is (operation_error if operation_fails else None)
    assert "simulated close failure" in str(error)
    assert "MANDATORY: disconnect USB and fully power-cycle" in str(error)
    if operation_fails:
        assert "QUERY_TARGET" in str(error)
        assert "simulated operation failure" in str(error)


# ─── ReferenceSerialIO against a real pyserial port ────────────────────────
#
# Bound to a PTY, as above. Unlike ``SerialIO`` this class can be constructed
# normally here: its open sequence has no step a PTY rejects, which is itself
# part of the parity claim - the DTR write that forces ``SerialIO`` to be
# built by ``__new__`` is one of the things the reference does not do.


@contextmanager
def _pty_reference_transport() -> Generator[tuple[int, ReferenceSerialIO], None, None]:
    """Yield ``(writer_fd, transport)`` for a ReferenceSerialIO bound to a PTY."""
    controller, device = pty.openpty()
    transport = ReferenceSerialIO(
        os.ttyname(device),
        baud=115200,
    )
    os.close(device)
    try:
        yield controller, transport
    finally:
        transport.close()
        os.close(controller)


def test_reference_read_timeout_is_the_reference_quarter_second() -> None:
    """The port timeout is observable, and it is 0.25 s, not ``SerialIO``'s 1 s."""
    with _pty_reference_transport() as (_writer, transport):
        start = time.monotonic()
        data = transport.read(len(_FRAMED_ACK))
        elapsed = time.monotonic() - start

    assert data == b""
    assert elapsed >= _REFERENCE_READ_TIMEOUT * 0.8
    assert elapsed < 0.75, (
        f"a silent read took {elapsed:.3f}s; the reference opens its port with "
        f"timeout={_REFERENCE_READ_TIMEOUT} and every read inherits that ceiling"
    )


def test_reference_read_waits_for_a_reply_fragmented_across_arrivals() -> None:
    """The same reassembly, through the real ``serialposix`` select loop."""
    tail_delay = 0.05
    with _pty_reference_transport() as (writer, transport):
        _ = os.write(writer, _FRAMED_ACK[:1])
        timer = threading.Timer(
            tail_delay,
            lambda: os.write(writer, _FRAMED_ACK[1:]),
        )
        timer.start()
        try:
            data = transport.read(len(_FRAMED_ACK))
        finally:
            timer.join()

    assert data == _FRAMED_ACK, "read returned a fragment, not the whole frame"


def test_reference_write_reaches_a_real_pyserial_port() -> None:
    """Smoke-test the literal write/flush path through ``serialposix``.

    The fake-port test pins the ordering itself. A PTY cannot prove USB CDC
    drain semantics because it does not expose the driver's ``TS_BUSY`` state
    that distinguishes ``tcdrain`` from ``TIOCOUTQ`` on macOS.
    """
    received = bytearray()

    def consume(fd: int) -> None:
        while len(received) < len(_FRAMED_ACK):
            chunk = os.read(fd, len(_FRAMED_ACK) - len(received))
            if not chunk:
                break
            received.extend(chunk)

    with _pty_reference_transport() as (writer, transport):
        reader = threading.Thread(target=consume, args=(writer,), daemon=True)
        reader.start()
        written = transport.write(_FRAMED_ACK)
        reader.join(timeout=_PTY_READER_TIMEOUT)

    assert written == len(_FRAMED_ACK)
    assert not reader.is_alive(), "PTY reader did not receive the flushed frame"
    assert bytes(received) == _FRAMED_ACK


# ─── pending_input against a real pyserial port ────────────────────────────
#
# The streamed data phase (``ack_each_data_packet=0``) reads nothing between
# chunks, so this counter is the session's only way to hear a loader that has
# started rejecting them. It runs once per data packet on a path where a
# per-chunk cost is the thing that decides whether a flash takes a minute or
# an hour, so both halves of its contract are pinned here against a real
# ``serialposix`` port: it must not wait, and it must not consume.

#: What a real D75 V1.03 loader sends to reject a data packet: NAK (0x15)
#: followed by subcode 0x03, "data packet/write rejected".
_CHUNK_NAK = b"\x15\x03"


def test_pending_input_reports_nothing_on_a_quiet_port() -> None:
    """The healthy streamed case, and the one that must stay free.

    A loader that is accepting chunks says nothing at all, so this answer is
    the one returned once per packet for an entire segment.
    """
    with _pty_transport() as (_writer, transport):
        start = time.monotonic()
        waiting = transport.pending_input()
        elapsed = time.monotonic() - start

    assert waiting == 0
    assert elapsed < _PORT_TIMEOUT / 100, (
        f"a waiting-byte check on an idle port took {elapsed:.4f}s; it must "
        f"not wait, or the streamed data phase pays it on every chunk"
    )


def test_pending_input_counts_a_rejection_without_consuming_it() -> None:
    """Detection must not eat the evidence.

    The session drains and decodes these bytes afterwards to name what the
    loader said. If the check consumed them, the failure would be reported as
    an unreadable one.
    """
    with _pty_transport() as (writer, transport):
        _ = os.write(writer, _CHUNK_NAK)
        # A PTY round trip is microseconds, but it is not zero, and this test
        # is about the count rather than the arrival.
        deadline = time.monotonic() + 1.0
        while transport.pending_input() < len(_CHUNK_NAK):
            assert time.monotonic() < deadline, "the PTY never delivered the NAK"

        waiting = transport.pending_input()
        again = transport.pending_input()
        drained = transport.read(len(_CHUNK_NAK))

    assert waiting == len(_CHUNK_NAK)
    assert again == waiting, "a check consumed bytes it was only counting"
    assert drained == _CHUNK_NAK
