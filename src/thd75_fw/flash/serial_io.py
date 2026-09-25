"""Thin pyserial wrapper — the single I/O boundary of the flasher.

Replaceable in tests via duck typing — ``MockRadio`` (see
``tests/fixtures/mock_radio.py``) implements the same methods.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import serial  # pyserial — types-pyserial in dev for stubs

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self


#: Bound on both the kernel write and the drain that follows it.
_WRITE_TIMEOUT_SECONDS: float = 30.0

#: Read timeout the reference flasher opens its port with.
#:
#: The reference client (``ref/openwood/fldm.py``, ``FLDMLoader.__init__``)
#: passes ``timeout=0.25`` and then re-asserts the same ceiling before every
#: read in ``_recv_exact`` (``self._serial_port.timeout = min(left, 0.25)``).
#:
#: That reassignment is not free, and the cost is the interesting part.
#: ``SerialBase.timeout``'s setter calls ``_reconfigure_port()`` whenever the
#: port is open. At a baud termios knows, that resolves to a ``tcgetattr`` and
#: an equality check that matches, so nothing is issued (measured: zero
#: ``tcsetattr``). At a baud it does not know - and macOS has no ``B576000``,
#: pyserial's darwin ``BAUDRATE_CONSTANTS`` is empty, and ``BOTHER`` does not
#: exist there - ``_reconfigure_port`` takes the ``custom_baud`` branch, and
#: ``_set_special_baudrate`` sits *outside* the "did anything change" guard
#: (``serialposix.py``). So at 576000 on macOS the reference re-issues
#: ``IOSSIOSPEED`` before every single read.
#:
#: The reference is the client that works, so this is reproduced rather than
#: optimised away. See ``ReferenceSerialOptions.reassert_read_timeout``.
_REFERENCE_READ_TIMEOUT_SECONDS: float = 0.25

#: Write timeout the reference flasher opens its port with (``write_timeout=1``).
#:
#: This bounds only the ``os.write``/``select`` loop inside ``Serial.write``;
#: it does not bound the ``flush()``/``tcdrain()`` that follows.
_REFERENCE_WRITE_TIMEOUT_SECONDS: float = 1.0


@dataclass(frozen=True, slots=True, kw_only=True)
class ReferenceSerialOptions:
    """Port settings for :class:`ReferenceSerialIO`.

    The defaults are the reference client's own values, so
    ``ReferenceSerialOptions()`` reproduces its port parameter for parameter.

    Attributes:
        timeout: Read timeout, re-asserted before every read when
            ``reassert_read_timeout`` is set.
        write_timeout: Bound on ``Serial.write`` only, not on the drain that
            follows it.
        strict_baud: Refuse a :meth:`ReferenceSerialIO.set_baud` to a different
            rate instead of reconfiguring the live port.
        reassert_read_timeout: Rewrite ``timeout`` before each read, as the
            reference's ``_recv_exact`` does.

    """

    timeout: float = _REFERENCE_READ_TIMEOUT_SECONDS
    write_timeout: float = _REFERENCE_WRITE_TIMEOUT_SECONDS
    strict_baud: bool = True
    reassert_read_timeout: bool = True


#: The reference client's exact port profile, the :class:`ReferenceSerialIO`
#: default.
_REFERENCE_SERIAL_OPTIONS: Final[ReferenceSerialOptions] = ReferenceSerialOptions()


class SerialCloseError(RuntimeError):
    """Closing the FLDM transport failed, optionally after another failure.

    ``contextlib`` normally lets an exception raised by ``__exit__`` mask the
    exception already propagating from the protected operation.  Retaining
    both matters here because the operation identifies the loader stage while
    the close failure means the host cannot attest that the session ended.
    """

    def __init__(
        self,
        *,
        close_error: BaseException,
        operation_error: BaseException | None = None,
    ) -> None:
        """Compose one message that names both failures.

        Args:
            close_error: What closing the transport raised.
            operation_error: The failure already propagating when the close
                was attempted, or ``None`` when the operation itself succeeded.

        """
        self.close_error = close_error
        self.operation_error = operation_error
        close_detail = f"{type(close_error).__name__}: {close_error}"
        if operation_error is None:
            message = f"SerialIO.close failed: {close_detail}"
        else:
            operation_detail = f"{type(operation_error).__name__}: {operation_error}"
            message = (
                f"operation failed ({operation_detail}); SerialIO.close also "
                f"failed ({close_detail})"
            )
        message += (
            "; transport closure is unproven. MANDATORY: disconnect USB and "
            "fully power-cycle the radio before any new FLDM session"
        )
        super().__init__(message)


class SerialIO:
    """Open a serial port, set baud, write, read with timeout, close."""

    def __init__(self, port: str, baud: int, *, timeout: float = 1.0) -> None:
        """Open ``port`` exclusively at ``baud``, 8N1, then assert DTR.

        If asserting DTR fails, the port is closed again before the failure
        propagates, so a failed construction never leaks the exclusive claim.

        Args:
            port: Serial device path.
            baud: Line rate to open the port at.
            timeout: Read timeout in seconds.

        Raises:
            serial.SerialException: If the port cannot be opened, including
                when another process already holds it.
            SerialCloseError: If asserting DTR fails and closing the port
                again fails too; the DTR failure is its ``operation_error``.

        """
        super().__init__()
        self._port = serial.Serial(
            port=port,
            baudrate=baud,
            timeout=timeout,
            # ``inter_byte_timeout`` stays at its default ``None``,
            # but not for the reason previously recorded here. That
            # note claimed a trial value of 0.001 (matching .NET's
            # ReadIntervalTimeout=MAXDWORD) dropped real D75
            # SEND_CHUNK responses because pyserial returned from
            # ``read()`` mid-frame and the ResponseReader had no
            # signal the rest was coming. Both halves are wrong, and
            # they are corrected here rather than left to be
            # rediscovered.
            #
            # The setting is inert on this class. ``serial.Serial``
            # resolves to ``serialposix.Serial``, whose ``read()``
            # never consults ``_inter_byte_timeout``; only
            # ``PosixPollSerial`` does, and it is not the default.
            # ``_reconfigure_port`` does translate the value into
            # termios ``VMIN``/``VTIME``, but the port is opened
            # ``O_NONBLOCK`` and only ``VTIMESerial`` ever clears
            # that, so ``VMIN``/``VTIME`` never gate a read here.
            # ``VTIME`` is in deciseconds besides, so 0.001 truncates
            # to 0 regardless.
            #
            # A mid-frame return is also handled, not fatal.
            # ``ResponseReader`` treats every short buffer as "wait
            # for more" (missing NAK subcode, sub-header framed
            # reply, and a ``parse_frame`` truncation alike), and the
            # session's read loop feeds each further chunk into the
            # same buffer until its own deadline. Reassembly across
            # reads is the design.
            #
            # So this parameter is not what dropped those responses,
            # and this file does not know what did. Leave the default
            # because there is no evidence for changing it, and do not
            # re-derive a mechanism from the old note.
            #
            # WriteTimeout 30 s. The .NET updater sets
            # ``u.WriteTimeout = 5000`` (5 s) because its async
            # SerialPort.DataReceived loop drains ACKs concurrently
            # with writes, so the write side never sits idle for
            # long. In our bounded-pipeline polling model we
            # occasionally drain an ACK between writes, but if the
            # radio briefly stalls (e.g. an erase boundary, sector
            # write delay), the OS write buffer can fill and the
            # next write blocks. 30 s gives the radio plenty of
            # margin to drain before we declare a hang, while still
            # preventing an infinite deadlock on a truly stuck
            # device.
            write_timeout=_WRITE_TIMEOUT_SECONDS,
            # 8N1 with no flow control — these are the System.IO.Ports
            # SerialPort defaults the .NET updater relies on (it sets
            # only DtrEnable, WriteBufferSize, WriteTimeout; everything
            # else inherits SerialPort defaults: DataBits=8, Parity=
            # None, StopBits=One, Handshake=None which means both RTS
            # and XOn/XOff disabled).
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            rtscts=False,
            dsrdtr=False,
            # A second CAT/flasher process can consume replies or inject bytes
            # into the same loader session.  Refuse a busy POSIX device at
            # open time, before any unlock byte is written.
            exclusive=True,
        )
        # Match the .NET updater (TH-D75_V103_e.exe Form1.cs:3950
        # `u.DtrEnable = true`). The FLDM loader appears to gate its
        # response on DTR; without this, the handshake gets no reply
        # on macOS/Linux even with the radio in FLDM mode (the .NET
        # SerialPort wrapper asserts DTR by default after Open(), so
        # the Windows builds didn't need this explicit step).
        #
        # RTS is intentionally NOT asserted — the .NET updater's
        # SerialPort.Handshake defaults to None, which leaves
        # RtsEnable=false. The radio's FLDM loader does not appear
        # to inspect RTS at all; toggling it has no observed effect
        # on macOS hardware tests.
        try:
            self._port.dtr = True
        except BaseException as initialization_error:
            # Exclusive open has already succeeded.  Do not leak that file
            # descriptor/claim if the required DTR assertion fails, and do not
            # let a simultaneous close error erase the initialization cause.
            try:
                self.close()
            except BaseException as close_error:
                raise SerialCloseError(
                    close_error=close_error,
                    operation_error=initialization_error,
                ) from close_error
            raise

    def write(self, data: bytes) -> int:
        """Write a frame and wait, with a deadline, for it to drain.

        The drain is required for frame integrity, not merely for pacing.
        macOS gives a tty a flat 1024-byte output ring (``TTYCLSIZE``) that
        cannot grow, and pyserial opens the port non-blocking and never
        restores blocking mode, so a write that does not fit returns a short
        count instead of blocking. A frame left partly undrained therefore
        pushes the *next* frame over the ring boundary and splits it, and a
        split frame reaches the loader as a truncated command followed by a
        stray tail after a scheduling gap.

        ``flush()`` would do this, but ``flush()`` is ``tcdrain`` and nothing
        bounds it: ``write_timeout`` covers only the ``os.write``/``select``
        inside ``Serial.write``, and the tty's own drain wait is infinite
        unless ``TIOCSDRAINWAIT`` was set, which it is not. A radio that
        stopped draining bulk-OUT without leaving the bus would hang the
        flasher forever mid-segment with no error. Polling ``out_waiting``
        against a deadline keeps the integrity guarantee and keeps the
        failure bounded.
        """
        written = self._port.write(data) or 0
        deadline = time.monotonic() + _WRITE_TIMEOUT_SECONDS
        while self._port.out_waiting:
            if time.monotonic() >= deadline:
                msg = (
                    f"transmit buffer did not drain within "
                    f"{_WRITE_TIMEOUT_SECONDS}s ({self._port.out_waiting} bytes "
                    "still queued); the radio has stopped accepting data"
                )
                raise serial.SerialTimeoutException(msg)
            time.sleep(0.0005)
        return written

    def read(self, max_bytes: int) -> bytes:
        """Return once ``max_bytes`` have arrived, or early on timeout.

        **Ask for exactly the bytes still outstanding.** That is the whole
        contract, and every caller owes it. ``pyserial``'s POSIX ``read(n)``
        loops on ``select`` and returns the moment the *n*-th byte lands;
        every other exit from that loop is the port timeout expiring
        (``serialposix.py`` ``Serial.read``). Requesting more than the loader
        is going to send therefore does not "read whatever is there" — it
        parks in ``select`` until the timeout, then returns the short result.

        That is what made the data phase cost a fixed timeout per reply. The
        callers polled ``read(256)`` while the loader answers with a single
        ACK byte or a nine-byte frame, so every reply waited out the full
        port timeout instead of the radio's actual round trip. Over a
        per-packet-ACK segment that is one timeout per chunk, turning a
        minute-scale flash into an hours-scale one.

        The decoder knows the outstanding count exactly
        (``ResponseReader.bytes_needed``), so the fix is for callers to
        request it and for this method to stay a faithful pass-through:
        ``max_bytes`` bytes, the instant they exist, and the timeout reserved
        for a radio that has genuinely stopped answering.

        A non-positive ``max_bytes`` reads nothing and returns ``b""``. It
        must never consume a byte the caller did not ask for: with an
        unframed ACK and a framed reply distinguished by their first byte,
        one stolen byte desynchronises the response stream for the rest of
        the session.
        """
        if max_bytes <= 0:
            return b""
        data: bytes = self._port.read(max_bytes)
        return data

    def pending_input(self) -> int:
        """Return the count of received bytes waiting, without blocking.

        This exists for the streamed data phase (``ack_each_data_packet=0``),
        which reads nothing while it writes because the loader answers no data
        packet: a read there would cost a port timeout per chunk. The loader
        does still speak when it *rejects* a chunk, and with nobody looking,
        that error frame sits in the receive queue until some later verb's read
        consumes it and gets blamed for it. This is the between-chunk glance
        that lets the session notice it instead: on POSIX a single
        ``ioctl(TIOCINQ)``, which never waits and never consumes a byte.

        Returns:
            Bytes currently buffered by the kernel for this port. Zero means
            the loader has said nothing, which is the healthy streamed case.

        """
        waiting: int = self._port.in_waiting
        return waiting

    def set_baud(self, baud: int) -> None:
        """Reconfigure the open port to ``baud``."""
        self._port.baudrate = baud

    def discard_input(self) -> None:
        """Discard received bytes that have not been read yet."""
        self._port.reset_input_buffer()

    def close(self) -> None:
        """Close the port if it is still open."""
        if self._port.is_open:
            self._port.close()

    def __enter__(self) -> Self:
        """Return this open transport for use in a ``with`` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the port without letting a close failure hide ``exc_val``.

        Raises:
            SerialCloseError: If closing fails; ``exc_val`` becomes its
                ``operation_error``.

        """
        try:
            self.close()
        except BaseException as close_error:
            raise SerialCloseError(
                close_error=close_error,
                operation_error=exc_val,
            ) from close_error


class ReferenceSerialIO:
    """The reference flasher's serial port, reproduced parameter for parameter.

    :class:`SerialIO` is the transport this project has been debugging. This
    one reproduces the reference client's port (``ref/openwood/fldm.py``,
    ``FLDMLoader.__init__`` and ``send_raw``/``_recv_exact``). It exists so a
    hardware run can attribute a failure to the transport or rule it out,
    which is impossible while the two differ in eight places at once.

    This transport shape is now D75 evidence, not just a differential test:
    direct-open OpenWood-compatible sessions completed stock V1.03 restores on
    2026-07-05 and 2026-07-25 (the latter in 233.4 seconds). The native client
    with the literal ordering below completed the same recovery in 204.5
    seconds on 2026-07-26. It preserves the reference client's serial
    construction and ordering literally.

    Everything the reference does, this does, in the same order:

    * open with ``timeout=0.25``, ``write_timeout=1``, 8N1, and *nothing else*
      — no ``exclusive``, no explicit ``dtr``, no ``rtscts``/``dsrdtr``
      keywords, so every remaining line setting is whatever ``pyserial``
      applies at open;
    * ``reset_input_buffer()`` then ``reset_output_buffer()`` immediately
      after open;
    * wait for every write to reach the wire before returning;
    * read exactly the byte count the caller asks for, re-asserting the
      per-call timeout ceiling first, exactly as ``_recv_exact`` does;
    * never change ``baudrate`` to a different rate.

    One departure is deliberate:

    * **Initialization failure closes the port.** The reference would leak the
      descriptor if a buffer reset raised. This class closes it and preserves
      both causes, matching :class:`SerialIO`'s ``SerialCloseError`` contract.

    ``ReferenceSerialOptions.strict_baud`` is the interesting knob, and the
    distinction it draws is narrower than "the reference leaves the port
    alone", which is not true: ``_recv_exact``'s per-read timeout assignment
    re-runs ``_reconfigure_port``, and at 576000 on macOS that re-applies the
    rate through ``IOSSIOSPEED`` every time (see
    :data:`_REFERENCE_READ_TIMEOUT_SECONDS`). What the reference never does is
    move the port to a *different* rate.

    Ours does exactly that: it opens at 9600 and has the session raise the
    rate. ``Serial.baudrate = 576000`` calls ``_reconfigure_port``, which finds
    no ``termios.B576000``, writes ``tcsetattr(TCSANOW, ..., B38400)`` because
    the computed attributes now differ, and only then applies the real rate
    through ``IOSSIOSPEED``. That is a transition down to 38400 and back up,
    on a live CDC device, mid-session. So ``strict_baud`` (the default) raises
    on a request for a different baud rather than silently reproducing it, and
    treats a request for the rate already open as the no-op it is. Callers open
    at the session's operating baud, exactly as the reference does.
    """

    def __init__(
        self,
        port: str,
        baud: int,
        options: ReferenceSerialOptions = _REFERENCE_SERIAL_OPTIONS,
    ) -> None:
        """Open ``port`` exactly as the reference client does, then reset buffers.

        If a buffer reset fails, the port is closed again before the failure
        propagates, so a failed construction never leaks the descriptor.

        Args:
            port: Serial device path.
            baud: Line rate to open the port at: the session's operating baud.
            options: Timeouts and the baud/timeout re-assertion policy; the
                default reproduces the reference client exactly.

        Raises:
            serial.SerialException: If the port cannot be opened.
            SerialCloseError: If a buffer reset fails and closing the port
                again fails too; the reset failure is its ``operation_error``.

        """
        super().__init__()
        self._baud = baud
        self._read_timeout = options.timeout
        self._strict_baud = options.strict_baud
        self._reassert_read_timeout = options.reassert_read_timeout
        self._baud_reconfigurations = 0
        # Keyword-for-keyword the reference's construction. The omissions are
        # as load-bearing as the values: leaving ``exclusive`` unset skips the
        # ``flock(LOCK_EX | LOCK_NB)`` that :class:`SerialIO` takes, and
        # leaving ``rtscts``/``dsrdtr`` unset lands on the same ``False`` by
        # pyserial default. ``bytesize``/``parity``/``stopbits`` are spelled
        # as the reference spells them (``8``, ``"N"``, ``1``) rather than via
        # the ``serial`` module constants they equal, so a diff against
        # ``fldm.py`` stays literal.
        self._port = serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=8,
            parity="N",
            stopbits=1,
            timeout=options.timeout,
            write_timeout=options.write_timeout,
        )
        # pyserial's ``open()`` already does a ``tcflush(TCIFLUSH)``; the
        # reference repeats it and adds the output side, which ``open()``
        # never touches. Anything a previous session left queued for
        # transmission would otherwise be prepended to our first unlock byte.
        try:
            self._port.reset_input_buffer()
            self._port.reset_output_buffer()
        except BaseException as initialization_error:
            # The port is open. Do not leak the descriptor because a buffer
            # reset failed, and do not let a simultaneous close failure erase
            # the initialization cause.
            try:
                self.close()
            except BaseException as close_error:
                raise SerialCloseError(
                    close_error=close_error,
                    operation_error=initialization_error,
                ) from close_error
            raise

    @property
    def baud(self) -> int:
        """Baud the port is currently configured at."""
        return self._baud

    @property
    def baud_reconfigurations(self) -> int:
        """How many times ``baudrate`` was rewritten after open.

        The reference's count is zero for an entire flash. A non-zero value
        here means this transport is no longer reproducing it.
        """
        return self._baud_reconfigurations

    def write(self, data: bytes) -> int:
        """Write a frame and wait for pyserial to drain it.

        This is the reference's literal ``send_raw`` ordering: call
        ``Serial.write`` and then ``Serial.flush``. On POSIX, ``flush`` is
        ``tcdrain`` and waits for both the tty output queue and driver-busy
        state. Polling ``out_waiting`` is not equivalent on macOS because
        ``TIOCOUTQ`` can report an empty queue while the driver is still busy;
        beginning the next read at that point can reconfigure a custom baud
        while transmission remains active.

        ``write_timeout`` bounds only ``Serial.write``. The following drain is
        deliberately unbounded because that is the ordering proven by the
        OpenWood recovery control.
        """
        written = self._port.write(data) or 0
        self._port.flush()
        return written

    def read(self, max_bytes: int) -> bytes:
        """Return once ``max_bytes`` have arrived, or early on timeout.

        This is the reference's ``_recv_exact`` inner call. It reads the exact
        outstanding count with a per-call ceiling of the port timeout, and its
        caller loops until the decoder is satisfied or the caller's own
        deadline passes. A frame fragmented across USB transfers is
        reassembled by that loop; a single call returning short is normal.

        Ask for exactly the bytes still outstanding. ``pyserial``'s POSIX
        ``read(n)`` returns the moment the *n*-th byte lands and otherwise
        parks in ``select`` until the timeout, so a fixed ceiling turns every
        short reply into a full timeout rather than reading "whatever is
        there".

        A non-positive ``max_bytes`` reads nothing and returns ``b""``. It
        must never consume a byte the caller did not ask for: an unframed ACK
        and a framed reply are distinguished by their first byte, so one
        stolen byte desynchronises the response stream for the rest of the
        session. The timeout is not re-asserted on that path either, since no
        read follows it.
        """
        if max_bytes <= 0:
            return b""
        if self._reassert_read_timeout:
            # ``_recv_exact`` writes the ceiling before every read. The value
            # is already what the port holds, so this is not about the timeout
            # at all; it is about the ``_reconfigure_port`` the setter runs,
            # which at a custom baud re-applies the rate through
            # ``IOSSIOSPEED``. Reproduced because a differential test is only
            # a test of the differences it actually removes, not because the
            # ioctl is known to matter. ``reassert_read_timeout=False`` drops
            # it with identical read semantics. See
            # :data:`_REFERENCE_READ_TIMEOUT_SECONDS`.
            self._port.timeout = self._read_timeout
        data: bytes = self._port.read(max_bytes)
        return data

    def pending_input(self) -> int:
        """Return the count of received bytes waiting, without blocking.

        The streamed data phase reads nothing while it writes, so this is the
        session's only chance to notice a loader error frame before some later
        verb's read swallows it and is blamed for it. On POSIX it is a single
        ``ioctl(TIOCINQ)``: no wait state, no byte consumed. The reference
        flasher has no equivalent, because it never checks; that is the gap
        this closes, and it costs the reference-parity comparison nothing
        because a zero return means nothing arrived.

        Returns:
            Bytes currently buffered by the kernel for this port.

        """
        waiting: int = self._port.in_waiting
        return waiting

    def set_baud(self, baud: int) -> None:
        """Honour a baud request without reconfiguring a live reference port.

        Raises:
            ValueError: Under ``strict_baud`` (the default), if ``baud``
                differs from the baud the port was opened at.

        """
        if baud == self._baud:
            return
        if self._strict_baud:
            msg = (
                f"refusing to reconfigure a live port from {self._baud} to "
                f"{baud} baud: the reference flasher opens its port at the "
                "baud the session runs at and only ever re-applies that same "
                "rate, never moves it to another one. On macOS this move is "
                "not cheap either, since a rate termios does not know is "
                "reached by setting B38400 first. Open this transport at the "
                "operating baud, or pass strict_baud=False to accept the "
                "reconfiguration"
            )
            raise ValueError(msg)
        self._port.baudrate = baud
        self._baud = baud
        self._baud_reconfigurations += 1

    def discard_input(self) -> None:
        """Discard buffered input, as at open."""
        self._port.reset_input_buffer()

    def close(self) -> None:
        """Close the port if it is still open."""
        if self._port.is_open:
            self._port.close()

    def __enter__(self) -> Self:
        """Return this open transport for use in a ``with`` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the port without letting a close failure hide ``exc_val``.

        Raises:
            SerialCloseError: If closing fails; ``exc_val`` becomes its
                ``operation_error``.

        """
        try:
            self.close()
        except BaseException as close_error:
            raise SerialCloseError(
                close_error=close_error,
                operation_error=exc_val,
            ) from close_error
