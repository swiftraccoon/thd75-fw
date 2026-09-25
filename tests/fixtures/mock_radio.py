"""In-memory FLDM-like loader for integration tests.

Implements the SerialIO contract via duck typing — FlashSession can't
tell it apart from a real serial port. Knows the FLDM unlock + framed
protocol well enough to drive a full happy-path session and can be
configured with faults to exercise every error path.

Fidelity rules this fixture enforces, so a host-side protocol
regression fails loudly here instead of on the radio:

* every byte written after unlock must parse as a complete frame
  (:class:`MockRadioProtocolError` otherwise, see ``strict_framing``);
* ``BAUD_AND_ACK`` selects a transfer mode from the loader's own
  ``baud_code`` table, and data packets are answered only in the modes
  whose ``ack_each_data_packet`` flag is set;
* ``BEGIN_TRANSFER`` is required by the successful reference sequence for
  every non-skipped segment, including ``$EL=0`` overlays, and answers BUSY
  before its final ACK;
* ``SEND_CHUNK`` must declare its own length, arrive in contiguous
  offset order inside the segment most recently set up, and never
  overrun that segment's ``$DL``;
* ``VERIFY_SEGMENT`` is admitted only for a segment that declared a
  nonzero ``$CL``, and with ``verify_checksum`` set it answers from the
  bytes actually programmed rather than from a fixture switch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from thd75_fw.flash.commands import Verb, response_verb_for
from thd75_fw.flash.handshake import (
    CLEARTEXT_MAGIC,
    MAGIC,
    UNLOCK_REPLY,
    Probe,
    derive_xor_key,
)
from thd75_fw.flash.protocol import (
    Frame,
    FrameError,
    build_frame,
    parse_frame,
    scramble,
)
from thd75_fw.flash.session import _FLDM_BAUD_MODES
from thd75_fw.kex import firmware_checksum

#: Fixed prefix of the SETUP_SEGMENT (0x40) wire descriptor, before the
#: ``$VL``-many ``$VA`` bytes. Field offsets used below come from the
#: vendor-parity descriptor test: ``$SA`` 0..4, ``$DL`` 4..8, ``$EL``
#: 8..12, ``$CB`` 28..30, ``$CA`` 30..32, ``$CS`` 32..36, ``$CL`` 36..40,
#: ``$VL`` 48..52.
_DESCRIPTOR_PREFIX_LEN = 52


class MockRadioFault(Enum):
    """Fault types the mock radio can simulate."""

    NONE = "none"
    HANDSHAKE_TIMEOUT = "handshake_timeout"
    QUERY_TARGET_NAK = "query_target_nak"
    SETUP_SEGMENT_NAK = "setup_segment_nak"
    ERASE_BUSY_FOREVER = "erase_busy_forever"
    WRITE_CHUNK_NAK = "write_chunk_nak"
    VERIFY_FAILED = "verify_failed"
    DISCONNECT_MID_FLASH = "disconnect_mid_flash"


class MockRadioProtocolError(AssertionError):
    """The host sent something a real loader could not have accepted.

    Derives from ``AssertionError`` deliberately: these are test-fixture
    assertions about the *host*, and ``FlashSession`` translates only
    ``OSError``/``TimeoutError``/``FrameError`` into a ``FlashError``, so
    an instance of this class propagates to the test as a failure with the
    offending command still in the traceback.
    """


@dataclass
class MockSegmentWrite:
    """One SETUP_SEGMENT episode, as the loader observed it.

    ``data`` holds the SEND_CHUNK payload bytes reassembled in arrival
    order, so a test can compare a segment's programmed image against its
    source bytes. A segment the host set up and then skipped (``$AF=0``
    with a "current" SETUP result) keeps an empty ``data``.
    """

    flash_start_addr: int
    data_length: int
    erase_length: int
    checksum_length: int
    checksum_start_offset: int
    expected_after_checksum: int
    data: bytearray = field(default_factory=bytearray)
    begin_transfers: int = 0
    end_transfers: int = 0
    verifies: int = 0
    chunk_count: int = 0


@dataclass
class MockRadio:
    r"""In-memory loader simulator. Implements SerialIO via duck typing.

    Fidelity note: ACK/BUSY/NAK responses default to the **bare-byte
    form** (``b"\\x06"``, ``b"\\x11"``, ``b"\\x15 <sub>"``) — the
    cleartext-mode shape openwood documents for D74. Real D75 V1.03
    hardware emits these wrapped in framed replies (``Frame(verb=
    0x06, payload=b"")`` etc.). Both forms are handled by
    ``FlashSession._is_ack`` / ``_is_busy`` / ``_is_nak`` so tests
    pass either way, but the bare form is NOT what a real radio
    sends. Set ``framed_acks=True`` to model real D75 behavior.
    """

    responsive_at_bauds: tuple[int, ...] = (38400,)
    # Exact healthy TH-D75 V1.03 profile observed on hardware. Full
    # flash sessions now enforce this before any erase/write verb; tests
    # that exercise probe diagnostics can still pass a custom payload.
    target_info_payload: bytes = field(
        default_factory=lambda: (
            (0x02).to_bytes(8, "little") + (0x02).to_bytes(8, "little") + b"\x00"
        ),
    )
    fault: MockRadioFault = MockRadioFault.NONE
    erase_busy_iterations: int = 1  # how many 0x11 BUSY before 0x06
    #: When ``True``, ACKs are sent as ``Frame(verb=0x06, payload=
    #: b"")`` and BUSYs as ``Frame(verb=0x11, payload=b"")`` — the
    #: form a real D75 V1.03 radio actually emits on the wire.
    #: Default ``False`` preserves the bare-byte responses existing
    #: tests are written against; new tests covering D75-specific
    #: behavior should set this ``True``.
    framed_acks: bool = False
    #: Exact one-byte SETUP result. ``1`` means update required and is
    #: the normal write-path default; tests use ``0`` for already current
    #: and arbitrary bytes to verify strict response validation.
    setup_result: bytes = b"\x01"
    #: Raise :class:`MockRadioProtocolError` the moment post-unlock input
    #: fails to parse as whole frames, instead of quietly waiting for
    #: bytes that will never arrive. A framing regression then fails at
    #: the write that caused it rather than 30 seconds later in a read
    #: timeout whose message says nothing about framing. Set ``False``
    #: only in a test that deliberately feeds the loader partial or
    #: malformed bytes.
    strict_framing: bool = True
    #: Answer VERIFY_SEGMENT by actually checksumming what was programmed,
    #: rather than always reporting success. Off by default because most
    #: fixtures carry a ``$CA`` that was never computed from their payload;
    #: a test that wants to prove the checksum catches missing bytes sets it
    #: and supplies a descriptor whose ``$CA`` matches its data.
    verify_checksum: bool = False

    # Internal state
    _current_baud: int = 0
    _rx_buf: bytearray = field(default_factory=bytearray)
    _tx_buf: bytearray = field(default_factory=bytearray)
    _unlocked: bool = False
    # XOR key for framed traffic — derived from the probe at unlock time,
    # exactly as a real loader does, so both sides agree without a shared
    # constant.
    _xor_key: int = 0
    _verb_log: list[int] = field(default_factory=list[int])
    _wire_writes: list[bytes] = field(default_factory=list[bytes])
    _segments: list[MockSegmentWrite] = field(
        default_factory=list[MockSegmentWrite],
    )
    _frames_parsed: int = 0
    # Whether data packets are acknowledged, per the mode the host selected in
    # BAUD_AND_ACK. The FLDMBaudMode table pairs each baud code with an
    # ack_each_data_packet flag, and the loader only replies to SEND_CHUNK in
    # the modes where that flag is set. Defaults to True so a session that
    # never negotiates a mode still sees the acknowledged behaviour.
    _ack_each_chunk: bool = True
    _transfer_mode: tuple[int, bool] | None = None

    # ─── SerialIO duck-typed contract ──────────────────────────────────

    def write(self, data: bytes) -> int:
        self._wire_writes.append(bytes(data))
        self._rx_buf.extend(data)
        self._process_buffer()
        if self.strict_framing and self._unlocked and self._rx_buf:
            # The host writes one complete frame per call, so anything
            # still buffered here is a frame the loader could not finish
            # parsing: a truncated body, a bogus length, or trailing
            # bytes after a good frame.
            leftover = bytes(self._rx_buf)
            raise MockRadioProtocolError(
                f"{len(leftover)} byte(s) of post-unlock input did not form a "
                f"complete frame: {leftover[:16].hex(' ')}"
                + ("..." if len(leftover) > 16 else "")
            )
        return len(data)

    def read(self, max_bytes: int) -> bytes:
        if self.fault is MockRadioFault.DISCONNECT_MID_FLASH and self._unlocked:
            return b""
        out = bytes(self._tx_buf[:max_bytes])
        del self._tx_buf[:max_bytes]
        return out

    def pending_input(self) -> int:
        """Bytes queued for the host, without consuming or blocking.

        This is the counter the streamed data phase glances at between
        chunks, so it must agree with :meth:`read`: a radio that has left
        the bus has nothing waiting no matter what the loader queued before
        it went, and reporting otherwise would send the session off to drain
        a response that can never be read.
        """
        if self.fault is MockRadioFault.DISCONNECT_MID_FLASH and self._unlocked:
            return 0
        return len(self._tx_buf)

    def set_baud(self, baud: int) -> None:
        self._current_baud = baud

    def discard_input(self) -> None:
        self._rx_buf.clear()

    def close(self) -> None:
        pass

    # ─── Test introspection (not part of SerialIO) ─────────────────────

    @property
    def verb_log(self) -> list[int]:
        return list(self._verb_log)

    @property
    def wire_writes(self) -> tuple[bytes, ...]:
        """Exact transport writes in arrival order, for transcript assertions."""
        return tuple(self._wire_writes)

    @property
    def transferred(self) -> bytes:
        """Every SEND_CHUNK data byte received, in segment order."""
        return b"".join(bytes(seg.data) for seg in self._segments)

    @property
    def segment_writes(self) -> tuple[MockSegmentWrite, ...]:
        """One record per SETUP_SEGMENT, in the order the host sent them."""
        return tuple(self._segments)

    @property
    def transfer_mode(self) -> tuple[int, bool] | None:
        """``(baud, ack_each_data_packet)`` negotiated in BAUD_AND_ACK."""
        return self._transfer_mode

    @property
    def frames_parsed(self) -> int:
        """Complete framed commands decoded since unlock."""
        return self._frames_parsed

    @property
    def unparsed_input(self) -> bytes:
        """Received bytes not yet consumed as a complete frame."""
        return bytes(self._rx_buf)

    # ─── Protocol state machine ────────────────────────────────────────

    def _process_buffer(self) -> None:
        if not self._unlocked:
            self._try_unlock()
            return
        # A real loader drains everything it has, so decode every complete
        # frame in the buffer rather than only the first.
        while len(self._rx_buf) >= 9:
            try:
                frame, rest = parse_frame(bytes(self._rx_buf), xor_key=self._xor_key)
            except FrameError as exc:
                if self.strict_framing and not _is_incomplete_frame(exc):
                    msg = (
                        f"loader could not parse {len(self._rx_buf)} received "
                        f"byte(s): {exc}"
                    )
                    raise MockRadioProtocolError(msg) from exc
                return
            consumed = len(self._rx_buf) - len(rest)
            del self._rx_buf[:consumed]
            self._frames_parsed += 1
            self._handle_frame(frame)

    def _try_unlock(self) -> None:
        if self.fault is MockRadioFault.HANDSHAKE_TIMEOUT:
            return
        if self._current_baud not in self.responsive_at_bauds:
            return
        if bytes(self._rx_buf).startswith(CLEARTEXT_MAGIC):
            del self._rx_buf[: len(CLEARTEXT_MAGIC)]
            self._xor_key = 0
            self._tx_buf.extend(UNLOCK_REPLY)
            self._unlocked = True
            return
        if len(self._rx_buf) < 11:
            return
        probe_bytes = bytes(self._rx_buf[:11])
        if probe_bytes[2:9] != MAGIC:
            return
        del self._rx_buf[:11]
        # Derive the framed-traffic XOR key from the probe, exactly as a
        # real loader does — bytes 9 and 10 are minute and second.
        self._xor_key = derive_xor_key(
            Probe(
                prefix=probe_bytes[:2],
                minute=probe_bytes[9],
                second=probe_bytes[10],
            ),
        )
        # The on-wire unlock reply is two raw bytes (0x16 then 0x06),
        # NOT the "TH-D75  " string (which is only the XOR-key
        # derivation constant). See handshake.UNLOCK_REPLY.
        self._tx_buf.extend(UNLOCK_REPLY)
        self._unlocked = True

    def _send_raw(self, cleartext: bytes) -> None:
        """Emit a one- or two-byte ACK/BUSY/NAK response.

        When ``self.framed_acks`` is ``True`` and ``cleartext`` is a
        single ACK (``0x06``) or BUSY (``0x11``) byte, the response
        is wrapped in a framed reply (``Frame(verb=cleartext[0],
        payload=b"")``) — the actual on-wire ACK/BUSY form observed on
        real D75 V1.03. This mock retains bare two-byte NAKs for D74-style
        compatibility tests; the local D75 SELECT_TARGET probe instead
        returned a framed NAK (verb 0x15, payload 0x01).

        Otherwise, emit the raw bytes scrambled with the active key,
        matching the D75 cleartext path (and how D74 always replies).
        ``scramble`` is identity when key == 0 (pre-unlock or
        cleartext mode), so this works both before and after unlock.
        """
        if self.framed_acks and len(cleartext) == 1 and cleartext[0] in (0x06, 0x11):
            reply = Frame(header=0, verb=cleartext[0], payload=b"")
            self._tx_buf.extend(build_frame(reply, xor_key=self._xor_key))
            return
        self._tx_buf.extend(scramble(cleartext, self._xor_key))

    def _active_segment(self, verb_name: str) -> MockSegmentWrite:
        """Return the segment the host most recently set up."""
        if not self._segments:
            msg = f"{verb_name} arrived before any SETUP_SEGMENT"
            raise MockRadioProtocolError(msg)
        return self._segments[-1]

    def _handle_frame(self, frame: Frame) -> None:
        self._verb_log.append(frame.verb)
        if frame.verb == Verb.QUERY_TARGET:
            self._answer_query_target()
        elif frame.verb == Verb.SETUP_SEGMENT:
            self._answer_setup_segment(frame.payload)
        elif frame.verb == Verb.BEGIN_TRANSFER:
            self._answer_begin_transfer()
        elif frame.verb == Verb.BAUD_AND_ACK:
            self._negotiate_transfer_mode(frame.payload)
        elif frame.verb == Verb.SEND_CHUNK:
            self._answer_send_chunk(frame.payload)
        elif frame.verb == Verb.END_TRANSFER:
            self._active_segment("END_TRANSFER").end_transfers += 1
            self._send_raw(b"\x06")
        elif frame.verb == Verb.VERIFY_SEGMENT:
            self._answer_verify_segment()
        else:
            # Default: ACK any other verb
            self._send_raw(b"\x06")

    def _answer_query_target(self) -> None:
        """Reply with the configured 17-byte target profile, or NAK it."""
        if self.fault is MockRadioFault.QUERY_TARGET_NAK:
            self._send_raw(b"\x15\x01")
            return
        reply = Frame(
            header=0,
            verb=response_verb_for(Verb.QUERY_TARGET),
            payload=self.target_info_payload,
        )
        self._tx_buf.extend(build_frame(reply, xor_key=self._xor_key))

    def _answer_setup_segment(self, payload: bytes) -> None:
        """Open a segment record, then reply with the SETUP result or NAK it."""
        self._record_setup(payload)
        if self.fault is MockRadioFault.SETUP_SEGMENT_NAK:
            self._send_raw(b"\x15\x02")
            return
        reply = Frame(
            header=0,
            verb=response_verb_for(Verb.SETUP_SEGMENT),
            payload=self.setup_result,
        )
        self._tx_buf.extend(build_frame(reply, xor_key=self._xor_key))

    def _answer_begin_transfer(self) -> None:
        """Count the BEGIN, then answer BUSY before the final ACK."""
        segment = self._active_segment("BEGIN_TRANSFER")
        segment.begin_transfers += 1
        if self.fault is MockRadioFault.ERASE_BUSY_FOREVER:
            self._send_raw(b"\x11")
            return
        for _ in range(self.erase_busy_iterations):
            self._send_raw(b"\x11")
        self._send_raw(b"\x06")

    def _answer_send_chunk(self, payload: bytes) -> None:
        """Store one data packet; ACK it only in an acknowledged mode."""
        self._record_chunk(payload)
        if self.fault is MockRadioFault.WRITE_CHUNK_NAK:
            self._send_raw(b"\x15\x03")
            return
        if self._ack_each_chunk:
            self._send_raw(b"\x06")

    def _answer_verify_segment(self) -> None:
        """Reply with the one-byte VERIFY status for the active segment."""
        segment = self._active_segment("VERIFY_SEGMENT")
        if segment.checksum_length == 0:
            # $CL == 0 is the vendor's "skip the verify" signal; the
            # sub-sector overlays rely on it.
            msg = "VERIFY_SEGMENT for a segment whose $CL is zero"
            raise MockRadioProtocolError(msg)
        segment.verifies += 1
        status = self._verify_status(segment)
        reply = Frame(
            header=0,
            verb=response_verb_for(Verb.VERIFY_SEGMENT),
            payload=bytes([status]),
        )
        self._tx_buf.extend(build_frame(reply, xor_key=self._xor_key))

    def _verify_status(self, segment: MockSegmentWrite) -> int:
        """Return the one-byte VERIFY_SEGMENT result: 0 verified, 1 failed.

        With ``verify_checksum`` off, the answer is a fixture switch: success
        unless :attr:`MockRadioFault.VERIFY_FAILED` is set. Most tests want
        that, because their descriptors carry a ``$CA`` that was never
        computed from their payload.

        With it on, the loader does what the real one does: sum the halfwords
        it would read back out of NOR over ``$CS..$CS+$CL`` and compare them
        against the descriptor's ``$CA``. Bytes the host never sent are still
        erased, so they read as ``0xFF``. That is what makes a chunk lost in
        transit fail the segment rather than pass it, and it is the only
        backstop the streamed mode has, since nothing acknowledges the data
        packets themselves.
        """
        if self.fault is MockRadioFault.VERIFY_FAILED:
            return 1
        if not self.verify_checksum:
            return 0
        span = segment.checksum_start_offset + segment.checksum_length
        programmed = bytes(segment.data).ljust(span, b"\xff")
        window = programmed[segment.checksum_start_offset : span]
        return 0 if firmware_checksum(window) == segment.expected_after_checksum else 1

    def _record_setup(self, payload: bytes) -> None:
        """Open a new segment record from the 0x40 wire descriptor."""
        if len(payload) < _DESCRIPTOR_PREFIX_LEN:
            msg = (
                f"SETUP_SEGMENT payload is {len(payload)} bytes, shorter than "
                f"the {_DESCRIPTOR_PREFIX_LEN}-byte fixed descriptor"
            )
            raise MockRadioProtocolError(msg)
        version_length = int.from_bytes(payload[48:52], "little")
        if len(payload) - _DESCRIPTOR_PREFIX_LEN != version_length:
            msg = (
                f"SETUP_SEGMENT declares $VL={version_length} but carries "
                f"{len(payload) - _DESCRIPTOR_PREFIX_LEN} trailing $VA byte(s)"
            )
            raise MockRadioProtocolError(msg)
        self._segments.append(
            MockSegmentWrite(
                flash_start_addr=int.from_bytes(payload[0:4], "little"),
                data_length=int.from_bytes(payload[4:8], "little"),
                erase_length=int.from_bytes(payload[8:12], "little"),
                checksum_length=int.from_bytes(payload[36:40], "little"),
                checksum_start_offset=int.from_bytes(payload[32:36], "little"),
                expected_after_checksum=int.from_bytes(payload[30:32], "little"),
            )
        )

    def _negotiate_transfer_mode(self, payload: bytes) -> None:
        """Apply the 0x33 payload ``[mode_code, ack_each_data_packet]``.

        The loader's reply policy follows its own table keyed on the MODE
        CODE, not on the flag the host asserts. Keying off the flag would
        let a host that declares a streaming mode with the ACK bit set (or
        an unknown code entirely) pass every test while hanging on real
        hardware, which is the exact regression this fixture exists to
        catch.
        """
        if len(payload) != 2:
            self._send_raw(b"\x15\x01")
            return
        mode = _FLDM_BAUD_MODES.get(payload[0])
        if mode is None:
            self._send_raw(b"\x15\x01")  # unknown baud code
            return
        _baud, ack_each_data_packet = mode
        if payload[1] != int(ack_each_data_packet):
            msg = (
                f"BAUD_AND_ACK code 0x{payload[0]:02X} pairs with "
                f"ack_each_data_packet={int(ack_each_data_packet)} in the "
                f"loader's mode table, but the host declared {payload[1]}"
            )
            raise MockRadioProtocolError(msg)
        self._transfer_mode = mode
        self._ack_each_chunk = ack_each_data_packet
        self._send_raw(b"\x06")

    def _record_chunk(self, payload: bytes) -> None:
        """Validate and store one 0x43 data packet.

        D75 SEND_CHUNK payload: offset(u32) + chunk_length(u32) + data.
        See NOTE in session.py for the format. The declared length must
        match the data actually sent, the offset must continue the
        segment's running counter, and the total must never exceed the
        ``$DL`` the segment declared.
        """
        if len(payload) < 8:
            msg = (
                f"SEND_CHUNK payload is {len(payload)} bytes, too short for "
                "the 8-byte offset+length header"
            )
            raise MockRadioProtocolError(msg)
        offset = int.from_bytes(payload[:4], "little")
        declared_length = int.from_bytes(payload[4:8], "little")
        data = payload[8:]
        if declared_length != len(data):
            msg = (
                f"SEND_CHUNK declared_length={declared_length} "
                f"!= actual data length {len(data)}"
            )
            raise MockRadioProtocolError(msg)
        segment = self._active_segment("SEND_CHUNK")
        if offset != len(segment.data):
            msg = (
                f"SEND_CHUNK offset {offset} does not continue the segment's "
                f"running counter at {len(segment.data)}"
            )
            raise MockRadioProtocolError(msg)
        if offset + len(data) > segment.data_length:
            msg = (
                f"SEND_CHUNK would write {offset + len(data)} bytes into a "
                f"segment whose $DL is {segment.data_length}"
            )
            raise MockRadioProtocolError(msg)
        segment.data.extend(data)
        segment.chunk_count += 1


def _is_incomplete_frame(exc: FrameError) -> bool:
    """Return whether a parse failure only means "not all the bytes yet"."""
    message = str(exc)
    return "truncated" in message or "too short" in message
