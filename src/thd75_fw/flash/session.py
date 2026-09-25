"""TH-D75 FLDM flash session orchestrator.

Drives the full per-segment sequence: handshake → entry verbs →
for each segment: SETUP/BEGIN/CHUNK/END/(optional VERIFY) →
COMPLETE_UPDATE.

The high-level sequence (entry verbs → segment loop → completion)
follows the same Command-response model documented for the closely-
related TH-D74; D75-specific deltas (cipher, framed-ACK form,
SEND_CHUNK payload layout, omitted verbs) are documented at each
relevant call site below.
"""

from __future__ import annotations

import contextlib
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from .commands import AckCode, UnframedResponse, Verb, response_verb_for
from .handshake import (
    HandshakeError,
    HandshakeResult,
    perform_cleartext_unlock,
    perform_handshake,
)
from .progress import (
    FlashCompleted,
    HandshakeSucceeded,
    SegmentChunkSent,
    SegmentErased,
    SegmentProgress,
    SegmentStarted,
    SegmentVerified,
    TargetIdentified,
    TransportBaudChanged,
)
from .protocol import Frame, FrameError, ResponseReader, build_frame
from .segments import (
    STOCK_TARGET_TYPE_MASK_D75_V103,
    BootloaderRegionError,
    SegmentDescriptor,
    validate_non_bootloader_nor_region,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .diagnostics import WireTrace
    from .progress import ProgressListener


#: First eight QUERY_TARGET response bytes observed on a healthy stock
#: TH-D75 V1.03. The official D75 updater consumes these bytes for its
#: ``#TT`` and per-segment ``$TT`` compatibility checks. ``target_mask``
#: exposes the equivalent integer in the official updater's convention (reply
#: byte 0 is the high byte); the raw bytes remain the primary evidence.
EXPECTED_D75_TARGET_MASK_BYTES: bytes = b"\x02\x00\x00\x00\x00\x00\x00\x00"

#: QUERY_TARGET response bytes 8..15 observed on the same radio. The D75
#: updater reads a 17-byte response but does not consume these middle bytes;
#: assigning them D74's ``loader_profile_mask`` meaning would be speculation.
EXPECTED_D75_OPAQUE_BYTES_8_15: bytes = b"\x02\x00\x00\x00\x00\x00\x00\x00"

#: Final QUERY_TARGET response byte observed on stock D75 V1.03. The official
#: host consumes it and treats value 1 specially, but the complete target-side
#: status taxonomy has not been recovered.
EXPECTED_D75_TRAILING_STATUS: int = 0x00

#: Stock V1.03 ``#FC`` value. The vendor updater sends it as LE u16;
#: the successful OpenWood-compatible D75 hardware run sent the same
#: numeric value as LE u32. No other raw-image completion value has
#: been validated on this radio.
_D75_V103_COMPLETE_CODE: int = 0x1DB0

#: Maximum data bytes in one FLDM SEND_CHUNK payload. OpenWood's
#: loader implementation documents the same 2048-byte receiver limit.
_MAX_CHUNK_SIZE: int = 2048

#: FLDM transfer modes: ``baud_code -> (baud, ack_each_data_packet)``.
#:
#: The images advertise the same four pairs in their ``#BR`` lines
#: (57600,0 / 115200,0 / 576000,1 / 1152000,1). The ACK policy is a property
#: of the mode, not a free choice, so it is derived here rather than written
#: out beside the payload.
#:
#: This exists because the payload byte and the host's ack flag were two
#: independent literals, and changing the mode while missing the flag makes
#: the host declare one protocol and then run the other. Done in the
#: streaming direction the host blocks forever on an ACK the loader was
#: never going to send, after the segment is already erased. That edit was
#: made, twice, on 2026-07-25.
_FLDM_BAUD_MODES: dict[int, tuple[int, bool]] = {
    0x09: (57_600, False),
    0x0A: (115_200, False),
    0x12: (576_000, True),
    0x14: (1_152_000, True),
}

#: Hardware-proven transfer mode selected for the data phase.
#:
#: ``0x12`` declares 576000 baud and one ACK per SEND_CHUNK. The exact
#: direct-open OpenWood-compatible profile completed stock V1.03 restores on
#: this D75 on 2026-07-05 and 2026-07-25. Keep the mode and ACK policy coupled
#: through :func:`negotiated_transfer_mode`; changing either recreates an
#: unvalidated protocol.
_FLDM_TRANSFER_MODE_CODE: int = 0x12

#: Number of inter-BUSY gaps retained per BEGIN_TRANSFER.
#:
#: The count itself is exact; only the individual gaps are capped. A loader
#: that emits BUSY every few milliseconds through a six-second erase would
#: otherwise accumulate an unbounded list inside a progress event, and the
#: shape of the first gaps is what answers the open question of whether the
#: radio paces its erase at all.
_MAX_RECORDED_BUSY_INTERVALS: int = 16

#: Hardware-proven base margin for one loader response.
#:
#: Kept at module scope so pre-I/O diagnostics can report the production
#: default even when a test substitutes the ``FlashSession`` constructor.
DEFAULT_REPLY_TIMEOUT_SECONDS: float = 30.0


@dataclass(frozen=True, slots=True)
class TransferMode:
    """The BAUD_AND_ACK decision, resolved once and used everywhere.

    The payload byte and the host's ACK policy were two independent
    literals, and a change to one without the other makes the host declare
    one protocol and run another. Resolving both here means the
    configuration banner reports the same bytes the session sends, because
    it is the same object.
    """

    #: Baud code in the payload's first byte.
    code: int
    #: Baud that code stands for in the loader's table.
    declared_baud: int
    #: Whether the loader replies to every SEND_CHUNK in this mode.
    ack_each_data_packet: bool

    @property
    def payload(self) -> bytes:
        """Exact BAUD_AND_ACK payload bytes for this mode."""
        return bytes([self.code, int(self.ack_each_data_packet)])


def negotiated_transfer_mode() -> TransferMode:
    """Return the transfer mode every real flash declares.

    Public so the CLI can print the exact payload bytes before opening the
    port without duplicating the table.
    """
    declared_baud, ack_each_data_packet = _FLDM_BAUD_MODES[_FLDM_TRANSFER_MODE_CODE]
    return TransferMode(
        code=_FLDM_TRANSFER_MODE_CODE,
        declared_baud=declared_baud,
        ack_each_data_packet=ack_each_data_packet,
    )


#: Three byte values pinned from the stock V1.03 main image. These are the only
#: positive-control SETUP addresses admitted by the public calibration API.
#: Keeping the allowlist in code prevents a typo from turning the first
#: state-machine calibration into an arbitrary-address loader experiment.
_D75_V103_SETUP_CONTROLS: tuple[tuple[int, int], ...] = (
    (0x6020_0000, 0x1C),
    (0x6020_0014, 0x00),
    (0x6020_0020, 0xFF),
)

#: Ceiling on a single response read request.
#:
#: ``ResponseReader.bytes_needed`` reports the outstanding count honestly, and
#: on a healthy stream that is at most a few dozen bytes: the largest reply the
#: loader sends is the 17-byte QUERY_TARGET payload inside a 26-byte frame. A
#: desynchronised stream is the reason for a ceiling. Four arbitrary bytes read
#: as a frame's ``body_length`` can claim ~4 GiB, and that count would reach
#: ``os.read`` as its buffer size. Clamping keeps a desync costing one port
#: timeout per attempt, the same as the fixed-size reads this replaced, instead
#: of an allocation the host cannot satisfy.
_MAX_RESPONSE_READ_BYTES: int = 4096

#: One deliberately wrong value followed by the correct stock value at the
#: same allowlisted address. This pair is isolated behind a conspicuously named
#: opt-in method because the official D75 updater never sends a second SETUP
#: after the first reply is 1 ("update required").
_D75_V103_SETUP_MISMATCH_REPEAT: tuple[tuple[int, int], ...] = (
    (0x6020_0000, 0x1D),
    (0x6020_0000, 0x1C),
)

#: Length of the QUERY_TARGET (0x31 → 0x32) reply payload: eight
#: target-compatibility bytes, eight opaque bytes, and one trailing status.
_TARGET_INFO_PAYLOAD_SIZE: Final[int] = 17

#: Default for ``FlashRunOptions.force_segment_indices``: no segment is
#: rewritten against a SETUP result of "current".
_NO_FORCED_SEGMENTS: Final[frozenset[int]] = frozenset()

#: COMPLETE_UPDATE payload width, in bytes, of the successful
#: OpenWood-compatible D75 run: ``#FC`` encoded as LE u32. The official
#: updater's LE u16 form is the explicit alternative width 2.
_HARDWARE_PROVEN_COMPLETE_WIDTH: Final[int] = 4

#: Line rate of the cleartext ``FPROMOD`` unlock, and the only rate proven on
#: local D75 V1.03 hardware.
_PROVEN_CLEARTEXT_BAUD: Final[int] = 576_000


@dataclass(frozen=True, slots=True)
class TargetInfo:
    """Evidence-preserving decode of the 17-byte QUERY_TARGET reply.

    The official D75 updater consumes response bytes 0..7 for target-type
    compatibility and byte 16 as a trailing status. It ignores bytes 8..15.
    A related D74 implementation assigns ``<QQB>`` semantics to all 17 bytes,
    but that is not D75 proof, so the middle bytes remain explicitly opaque.
    """

    raw_payload: bytes
    target_mask_bytes: bytes
    opaque_bytes_8_15: bytes
    trailing_status: int

    @property
    def target_mask(self) -> int:
        """Target compatibility bytes in the official updater's convention."""
        return int.from_bytes(self.target_mask_bytes, "big")

    def matches_d75_v103(self) -> bool:
        """Return whether every field matches the stock D75 V1.03 baseline.

        The baseline is the empirically observed stock reply. A False return
        doesn't necessarily mean the radio is broken — it means the operator
        should verify the radio matches expectations before flashing.
        """
        return (
            self.target_mask_bytes == EXPECTED_D75_TARGET_MASK_BYTES
            and self.opaque_bytes_8_15 == EXPECTED_D75_OPAQUE_BYTES_8_15
            and self.trailing_status == EXPECTED_D75_TRAILING_STATUS
        )

    def d75_mismatch_reasons(self) -> list[str]:
        """Describe each field that differs from the D75 V1.03 baseline.

        Returns:
            One human-readable line per mismatching field; empty when the
            radio matches the baseline.

        """
        out: list[str] = []
        if self.target_mask_bytes != EXPECTED_D75_TARGET_MASK_BYTES:
            out.append(
                f"target_mask_bytes {self.target_mask_bytes.hex(' ')} "
                f"!= expected {EXPECTED_D75_TARGET_MASK_BYTES.hex(' ')}"
            )
        if self.opaque_bytes_8_15 != EXPECTED_D75_OPAQUE_BYTES_8_15:
            out.append(
                f"opaque_bytes_8_15 {self.opaque_bytes_8_15.hex(' ')} "
                f"!= expected {EXPECTED_D75_OPAQUE_BYTES_8_15.hex(' ')}"
            )
        if self.trailing_status != EXPECTED_D75_TRAILING_STATUS:
            out.append(
                f"trailing_status 0x{self.trailing_status:02X} "
                f"!= expected 0x{EXPECTED_D75_TRAILING_STATUS:02X}"
            )
        return out


@dataclass(frozen=True, slots=True)
class FlashOutcome:
    """Summary of a completed :meth:`FlashSession.flash_segments` run.

    ``segments_written`` and ``bytes_written`` count only segments that were
    actually transferred; a segment skipped because SETUP reported it current
    adds to neither.
    """

    target: TargetInfo
    segments_written: int
    bytes_written: int
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class SetupCalibrationOutcome:
    """Result of a SETUP-only, no-transfer calibration session.

    ``setup_results`` preserves one exact loader decision per supplied
    descriptor, in request order: ``0`` means the described bytes are current
    and ``1`` means the loader reports that an update would be required.
    """

    target: TargetInfo
    setup_results: tuple[int, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class FlashSessionOptions:
    """Tunables a :class:`FlashSession` fixes at construction, before any I/O.

    The defaults are the production profile: each ``None`` resolves to the
    matching :class:`FlashSession` class default, so ``FlashSessionOptions()``
    changes nothing. The progress listener and the wire trace are per-session
    collaborators rather than tunables, so they remain constructor arguments
    and one options value can configure any number of sessions.

    Attributes:
        chunk_size: Session ceiling for SEND_CHUNK data bytes, 1..2048;
            ``None`` means :attr:`FlashSession.DEFAULT_CHUNK_SIZE`.
        handshake_timeout: Per-baud keyed unlock timeout; ``None`` (or 0)
            means :attr:`FlashSession.DEFAULT_HANDSHAKE_TIMEOUT`.
        reply_timeout: Base window for one loader response; ``None`` means
            :attr:`FlashSession.BASE_REPLY_TIMEOUT_SECONDS`.
        progress_every_chunks: Emit a throughput sample every this many data
            packets; 0 turns the samples off.

    """

    chunk_size: int | None = None
    handshake_timeout: float | None = None
    reply_timeout: float | None = None
    progress_every_chunks: int = 0


@dataclass(frozen=True, slots=True, kw_only=True)
class FlashRunOptions:
    """How one :meth:`FlashSession.flash_segments` run unlocks, writes and ends.

    The defaults walk the keyed baud ladder, write every segment, and send the
    stock ``0x1DB0`` completion code as LE u32.

    Attributes:
        baud_ladder: Optional override for the handshake unlock-probe ordering
            (e.g. ``(19200,)`` to skip slower rates). ``None`` uses
            ``handshake.BAUD_LADDER``.
        complete_update_value: Numeric completion code. Stock D75 V1.03 uses
            ``0x1DB0``; no raw-image alternative is proven.
        complete_update_width: Wire width in bytes. ``2`` reproduces the
            official updater; ``4`` reproduces the successful
            OpenWood-compatible D75 hardware run.
        always_flash: Implements KEX ``#AF``. When false, a SETUP result of
            zero skips an already-current segment. Raw candidate images use
            true explicitly.
        force_segment_indices: Zero-based segment indices to write even when
            SETUP reports them current. This selective override is consulted
            only when ``always_flash`` is false.
        cleartext_unlock: Unlock with the cleartext ``FPROMOD`` token at
            ``cleartext_baud`` instead of walking the keyed baud ladder. This
            is the path proven on real D75 V1.03 hardware: framed traffic then
            runs in plaintext (XOR key 0) and the port stays at
            ``cleartext_baud`` for the rest of the session.
        cleartext_baud: Line rate set on the transport before ``FPROMOD`` when
            ``cleartext_unlock`` is true; unused on the keyed path. 576000 is
            the only rate proven locally.

    """

    baud_ladder: tuple[int, ...] | None = None
    complete_update_value: int = _D75_V103_COMPLETE_CODE
    complete_update_width: int = _HARDWARE_PROVEN_COMPLETE_WIDTH
    always_flash: bool = True
    force_segment_indices: frozenset[int] = _NO_FORCED_SEGMENTS
    cleartext_unlock: bool = False
    cleartext_baud: int = _PROVEN_CLEARTEXT_BAUD


#: Production session tunables: every :class:`FlashSession` class default.
_DEFAULT_SESSION_OPTIONS: Final[FlashSessionOptions] = FlashSessionOptions()

#: Default :meth:`FlashSession.flash_segments` run: keyed unlock, every segment
#: written, stock completion code as LE u32.
_DEFAULT_RUN_OPTIONS: Final[FlashRunOptions] = FlashRunOptions()


class FlashError(RuntimeError):
    """A flash session aborted. Carries enough context to diagnose."""

    def __init__(self, *, step: str, cause: str, recoverable: bool) -> None:
        """Record the failed step, what went wrong, and how to recover.

        Args:
            step: The command or phase that failed, for example
                ``"SETUP_SEGMENT[segment_0]"``.
            cause: What went wrong at that step.
            recoverable: ``True`` when the next action is to power-cycle the
                radio back into programming mode and diagnose; ``False`` when
                the bootloader may be damaged and no further write should be
                attempted.

        """
        self.step = step
        self.cause = cause
        self.recoverable = recoverable
        super().__init__(f"{step}: {cause}")


def _validate_flash_plan(
    segments: list[SegmentDescriptor],
    segment_data: dict[int, bytes],
    *,
    complete_update_value: int,
    complete_update_width: int,
    chunk_size: int,
) -> None:
    """Validate all caller-controlled plan data before device I/O.

    KEX parsing can produce a payload longer than ``$DL`` because its
    Intel HEX coverage includes erase padding, so the vendor-correct
    invariant is *at least* ``data_length`` bytes. The session trims
    that permitted excess immediately before chunking. Missing, short,
    zero-length, or unexpectedly indexed payloads are rejected rather
    than discovered after FLDM has begun erasing a segment.
    """
    _validate_plan_parameters(
        segments,
        complete_update_value=complete_update_value,
        complete_update_width=complete_update_width,
        chunk_size=chunk_size,
    )
    _validate_payload_indices(segments, segment_data)
    for idx, descriptor in enumerate(segments):
        _validate_segment_payload(
            idx,
            descriptor,
            segment_data,
            chunk_size=chunk_size,
        )


def _validate_plan_parameters(
    segments: list[SegmentDescriptor],
    *,
    complete_update_value: int,
    complete_update_width: int,
    chunk_size: int,
) -> None:
    """Reject an empty plan, a bad chunk size, or an unencodable completion.

    Raises:
        FlashError: With step ``PREFLIGHT`` for the first problem found.

    """
    if not segments:
        raise FlashError(
            step="PREFLIGHT",
            cause="flash plan has no segments",
            recoverable=True,
        )

    if not 1 <= chunk_size <= _MAX_CHUNK_SIZE:
        raise FlashError(
            step="PREFLIGHT",
            cause=f"chunk_size must be 1..{_MAX_CHUNK_SIZE}, got {chunk_size}",
            recoverable=True,
        )

    if complete_update_width not in (2, 4):
        raise FlashError(
            step="PREFLIGHT",
            cause=(
                "complete_update_width must be 2 (vendor u16) or "
                f"4 (hardware-tested u32), got {complete_update_width}"
            ),
            recoverable=True,
        )
    completion_max = (1 << (complete_update_width * 8)) - 1
    if not 0 <= complete_update_value <= completion_max:
        raise FlashError(
            step="PREFLIGHT",
            cause=(
                f"complete_update_value {complete_update_value:#x} does "
                f"not fit in the selected {complete_update_width}-byte "
                "unsigned wire format."
            ),
            recoverable=True,
        )


def _validate_payload_indices(
    segments: list[SegmentDescriptor],
    segment_data: dict[int, bytes],
) -> None:
    """Require exactly one payload per descriptor, keyed by segment index.

    Raises:
        FlashError: With step ``PREFLIGHT`` naming missing and unexpected
            payload indices.

    """
    expected_indices = set(range(len(segments)))
    actual_indices = set(segment_data)
    if actual_indices != expected_indices:
        missing = sorted(expected_indices - actual_indices)
        unexpected = sorted(actual_indices - expected_indices)
        details: list[str] = []
        if missing:
            details.append(f"missing payload indices {missing}")
        if unexpected:
            details.append(f"unexpected payload indices {unexpected}")
        raise FlashError(
            step="PREFLIGHT",
            cause="segment_data index mismatch: " + "; ".join(details),
            recoverable=True,
        )


def _validate_segment_payload(
    idx: int,
    descriptor: SegmentDescriptor,
    segment_data: dict[int, bytes],
    *,
    chunk_size: int,
) -> None:
    """Check one descriptor and its payload before any device I/O.

    Raises:
        FlashError: With step ``PREFLIGHT`` if ``$DL`` is zero, the NOR span
            is forbidden, the payload is shorter than ``$DL``, or ``$DL`` is
            not a whole number of packets.

    """
    if descriptor.data_length == 0:
        raise FlashError(
            step="PREFLIGHT",
            cause=f"segment {idx} has zero data_length",
            recoverable=True,
        )
    try:
        validate_non_bootloader_nor_region(
            descriptor.flash_start_addr,
            max(descriptor.data_length, descriptor.erase_length),
        )
    except BootloaderRegionError as exc:
        raise FlashError(
            step="PREFLIGHT",
            cause=f"segment {idx} has a forbidden NOR span: {exc}",
            recoverable=True,
        ) from exc
    actual_length = len(segment_data[idx])
    if actual_length < descriptor.data_length:
        raise FlashError(
            step="PREFLIGHT",
            cause=(
                f"segment {idx} payload is {actual_length} bytes, shorter "
                f"than descriptor data_length {descriptor.data_length}"
            ),
            recoverable=True,
        )
    effective_chunk_size = min(
        chunk_size,
        descriptor.chunk_size or chunk_size,
    )
    if descriptor.data_length % effective_chunk_size != 0:
        raise FlashError(
            step="PREFLIGHT",
            cause=(
                f"segment {idx} data_length {descriptor.data_length} is "
                f"not divisible by its {effective_chunk_size}-byte packet "
                "size; D75 short-final packets are unproven"
            ),
            recoverable=True,
        )


def _validate_force_segment_indices(
    force_segment_indices: frozenset[int],
    segment_count: int,
) -> None:
    """Require every forced index to be an ``int`` naming a planned segment.

    Raises:
        FlashError: With step ``PREFLIGHT`` listing every invalid index.

    """
    invalid_force_indices = [
        index
        for index in force_segment_indices
        if type(index) is not int or not 0 <= index < segment_count
    ]
    if invalid_force_indices:
        raise FlashError(
            step="PREFLIGHT",
            cause=(
                "force_segment_indices contains out-of-range or non-integer "
                f"indices for {segment_count} segment(s): "
                f"{invalid_force_indices!r}"
            ),
            recoverable=True,
        )


def _setup_calibration_descriptor(address: int, value: int) -> SegmentDescriptor:
    """Build the one exact SETUP equality descriptor admitted by the audit.

    Every fixed field comes from the planned D75 V1.03 oracle probe. In
    particular, ``erase_length`` and ``checksum_length`` are zero and the
    host never follows SETUP with BEGIN, DATA, END, VERIFY, or COMPLETE.
    That constrains the *host command sequence*; the uncaptured loader's
    target-side SETUP implementation is still unknown.
    """
    return SegmentDescriptor(
        flash_start_addr=address,
        data_length=2,
        erase_length=0,
        target_type_mask=STOCK_TARGET_TYPE_MASK_D75_V103,
        erase_wait_seconds=0,
        expected_before_checksum=0,
        expected_after_checksum=0,
        checksum_start_offset=0,
        checksum_length=0,
        checksum_wait_seconds=10,
        version_start_offset=0,
        version_length=1,
        version_check_bytes=bytes([value]),
    )


def _setup_calibration_plan(
    *,
    allow_mismatch_repeat: bool,
) -> tuple[tuple[SegmentDescriptor, ...], tuple[int, ...]]:
    """Return a fixed descriptor/result plan; no caller addresses accepted."""
    raw_plan = (
        _D75_V103_SETUP_MISMATCH_REPEAT
        if allow_mismatch_repeat
        else _D75_V103_SETUP_CONTROLS
    )
    descriptors = tuple(
        _setup_calibration_descriptor(address, value) for address, value in raw_plan
    )
    expected_results = (1, 0) if allow_mismatch_repeat else (0, 0, 0)
    return descriptors, expected_results


def _validate_setup_calibration_plan(
    descriptors: Sequence[SegmentDescriptor],
    expected_results: Sequence[int],
    *,
    allow_mismatch_repeat: bool,
) -> None:
    """Verify an exact fixed SETUP plan before any transport I/O."""
    expected_descriptors, canonical_results = _setup_calibration_plan(
        allow_mismatch_repeat=allow_mismatch_repeat,
    )
    if tuple(descriptors) != expected_descriptors:
        mode = "mismatch-repeat" if allow_mismatch_repeat else "positive-control"
        raise FlashError(
            step="SETUP_CALIBRATION_PREFLIGHT",
            cause=f"descriptor batch is not the exact {mode} allowlisted plan",
            recoverable=True,
        )
    if tuple(expected_results) != canonical_results:
        raise FlashError(
            step="SETUP_CALIBRATION_PREFLIGHT",
            cause=(
                f"expected_results must be exactly {canonical_results!r}, got "
                f"{tuple(expected_results)!r}"
            ),
            recoverable=True,
        )


def _decode_setup_result(payload: bytes, *, step: str) -> int:
    """Return an exact FLDM SETUP decision or abort on any other shape."""
    if len(payload) != 1 or payload[0] not in (0, 1):
        rendered = payload.hex(" ") or "<empty>"
        raise FlashError(
            step=step,
            cause=(
                "loader result must be one byte 0 (current) or 1 "
                f"(update required), got {rendered}"
            ),
            recoverable=True,
        )
    return payload[0]


def decode_target_info(payload: bytes) -> TargetInfo:
    """Decode the 17-byte QUERY_TARGET (0x31 → 0x32) response payload.

    D75 updater evidence supports only these roles: bytes 0..7 participate in
    target compatibility, bytes 8..15 are ignored, and byte 16 is consumed as
    a trailing status. All raw bytes are retained to avoid importing D74-only
    semantics.
    """
    if len(payload) != _TARGET_INFO_PAYLOAD_SIZE:
        msg = (
            f"target info payload must be {_TARGET_INFO_PAYLOAD_SIZE} bytes, "
            f"got {len(payload)}"
        )
        raise ValueError(msg)
    return TargetInfo(
        raw_payload=payload,
        target_mask_bytes=payload[0:8],
        opaque_bytes_8_15=payload[8:16],
        trailing_status=payload[16],
    )


def _decode_target_info_response(payload: bytes, *, step: str) -> TargetInfo:
    """Decode a loader reply without leaking a plan-style ``ValueError``.

    ``decode_target_info`` remains a pure decoder and deliberately raises
    ``ValueError`` for caller-supplied bytes.  Once QUERY_TARGET has been sent,
    however, a malformed payload is a loader-session failure: the radio has
    already advanced through ENTER_PROGRAM and TIMED_SESSION and must be
    power-cycled before another attempt.
    """
    try:
        return decode_target_info(payload)
    except ValueError as exc:
        raise FlashError(
            step=step,
            cause=str(exc),
            recoverable=True,
        ) from exc


def _traced_response(resp: Frame | UnframedResponse) -> tuple[int, bytes]:
    """Flatten a decoded response into the ``(verb, payload)`` a trace stores.

    An unframed reply has no payload, so its NAK subcode is passed through as
    one payload byte; without it a trace would show the rejection but not
    which one.
    """
    if isinstance(resp, Frame):
        return resp.verb, resp.payload
    subcode = resp.nak_subcode
    return int(resp.code), b"" if subcode is None else bytes([int(subcode)])


def _refuse_non_d75_target(target: TargetInfo) -> None:
    """Stop a calibration whose QUERY_TARGET reply is not the D75 V1.03 baseline.

    Raises:
        FlashError: With step ``TARGET_COMPATIBILITY`` listing every
            mismatching field.

    """
    target_issues = target.d75_mismatch_reasons()
    if target_issues:
        raise FlashError(
            step="TARGET_COMPATIBILITY",
            cause="; ".join(target_issues),
            recoverable=True,
        )


def _check_calibration_result(
    step: str,
    actual_result: int,
    expected_result: int,
    *,
    allow_mismatch_repeat: bool,
) -> None:
    """Stop a calibration at the first unplanned SETUP decision.

    Raises:
        FlashError: If the result differs from the plan, or is 1 in the
            positive-control plan, which never sends a SETUP after a 1.

    """
    if actual_result != expected_result:
        raise FlashError(
            step=step,
            cause=(
                f"expected SETUP result {expected_result}, got "
                f"{actual_result}; refusing any follow-up command"
            ),
            recoverable=True,
        )
    if actual_result == 1 and not allow_mismatch_repeat:
        raise FlashError(
            step=step,
            cause="SETUP result 1; refusing any follow-up command",
            recoverable=True,
        )


class _SessionTransport(Protocol):
    """Duck-typed minimal SerialIO contract used by FlashSession.

    ``read`` returns at most ``max_bytes`` and never consumes more than that,
    waits for that many to arrive, and returns short (possibly empty) when its
    own timeout expires first. The session holds up its end by requesting
    exactly the bytes the decoder still needs; asking for a round number the
    loader was never going to send is what turns the transport timeout into a
    fixed per-reply cost. A non-blocking fake satisfies this by returning
    whatever it has buffered, including ``b""``.

    ``pending_input`` reports how many received bytes are waiting and must
    neither block nor consume any of them. The streamed data phase is the only
    caller: it reads nothing between chunks, so this is what tells it that the
    loader has spoken. Returning a conservative ``0`` disables that detection
    rather than breaking it, but a transport that cannot answer honestly should
    say so at construction instead, because the session requires the capability
    before it will stream.
    """

    def write(self, data: bytes) -> int: ...
    def read(self, max_bytes: int) -> bytes: ...
    def pending_input(self) -> int: ...
    def set_baud(self, baud: int) -> None: ...
    def discard_input(self) -> None: ...


class FlashSession:
    """Single-use driver of one flash session.

    Run ``flash_segments(...)`` exactly once. To re-flash, construct a
    fresh session. Each ``ENTER_PROGRAM`` is a fresh loader interaction
    by design.
    """

    #: Default packet size, in bytes.
    #:
    #: This is the stock V1.03 ``$DU`` (data unit) declared in the KEX
    #: metadata, and it is what the official host sends. It is a ceiling, not
    #: a fixed size: ``_validate_segment_plan`` takes ``min()`` of this and the
    #: per-descriptor ``chunk_size``, so the two-byte CHECKBYTES and 32-byte
    #: FINAL_ZZZ overlays still go out as single short packets.
    #:
    #: 256 is the data size used by both retained successful D75 stock
    #: restores (2026-07-05 and 2026-07-25). The stock KEX advertises 1024,
    #: but every attempted 1024-byte ACK-mode transfer on this host stopped at
    #: the first packet and produced the radio's ``Data Error`` screen.
    #: Hardware writes therefore stay on the empirically proven size.
    DEFAULT_CHUNK_SIZE: int = 256
    D75_V103_COMPLETE_CODE: int = _D75_V103_COMPLETE_CODE
    MAX_CHUNK_SIZE: int = _MAX_CHUNK_SIZE

    #: Per-baud handshake timeout used against real radios. The MockRadio
    #: in tests responds in microseconds so test code can pass a much
    #: smaller value; real D75 hardware needs hundreds of ms (we observed
    #: ~immediate but the 2-byte unlock reply can split with a gap).
    DEFAULT_HANDSHAKE_TIMEOUT: float = 2.0

    #: Base response timeout from the retained successful OpenWood run.
    #:
    #: Ordinary command replies get this full window. SETUP and VERIFY add the
    #: descriptor's ``$CT``; BEGIN adds ``$ET`` and applies the resulting
    #: window independently to every response, so each BUSY starts a fresh
    #: wait. The successful D75 recovery did not impose the official host's
    #: two-second inter-response watchdog or its host-only ``$EM`` total.
    BASE_REPLY_TIMEOUT_SECONDS: float = DEFAULT_REPLY_TIMEOUT_SECONDS

    #: Window allowed for a mid-stream loader response to finish arriving.
    #:
    #: The between-chunk check can see the first byte of a framed error reply
    #: while the rest is still on the wire, so the drain that follows it gets a
    #: bounded grace rather than reporting a torn frame. Only the abort path
    #: reaches this wait: in a healthy streamed data phase nothing is ever
    #: waiting, so the value costs a working flash nothing. Two seconds is far
    #: beyond any real arrival — a nine-byte frame takes about 9 ms even at
    #: 9600 baud — and short enough that a loader which emitted one stray byte
    #: and then went silent still fails promptly.
    STREAMED_ERROR_DRAIN_SECONDS: float = 2.0

    @staticmethod
    def validate_plan(
        segments: list[SegmentDescriptor],
        segment_data: dict[int, bytes],
        *,
        complete_update_value: int,
        complete_update_width: int = _HARDWARE_PROVEN_COMPLETE_WIDTH,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        """Run the zero-I/O flash-plan preflight used by the CLI."""
        _validate_flash_plan(
            segments,
            segment_data,
            complete_update_value=complete_update_value,
            complete_update_width=complete_update_width,
            chunk_size=chunk_size,
        )

    def __init__(
        self,
        transport: _SessionTransport,
        options: FlashSessionOptions = _DEFAULT_SESSION_OPTIONS,
        *,
        progress: ProgressListener | None = None,
        trace: WireTrace | None = None,
    ) -> None:
        """Bind a transport and fix the session's tunables before any I/O.

        Args:
            transport: The open port, or a test double, that speaks the
                :class:`_SessionTransport` contract.
            options: Chunk size, timeouts and throughput-sample cadence; the
                default is the production profile.
            progress: Listener for progress events, or ``None`` for none.
            trace: Wire trace that records every frame, or ``None`` for none.

        Raises:
            ValueError: If ``options.progress_every_chunks`` is negative, the
                chunk size is outside 1..2048, or the reply timeout is not
                positive.

        """
        super().__init__()
        self._transport = transport
        self._progress = progress
        # Off unless the operator asked for it. Every frame path tests this
        # against None, which is the whole cost of the feature when unused;
        # see the per-chunk measurements in the trace module's docstring.
        self._trace = trace
        # 0 disables the periodic throughput line. Stored as a plain int and
        # hoisted into a local before the chunk loop so the data phase pays
        # one comparison, not an attribute lookup.
        progress_every_chunks = options.progress_every_chunks
        if progress_every_chunks < 0:
            msg = f"progress_every_chunks must be >= 0, got {progress_every_chunks}"
            raise ValueError(msg)
        self._progress_every_chunks = progress_every_chunks
        chunk_size = options.chunk_size
        self._chunk_size = self.DEFAULT_CHUNK_SIZE if chunk_size is None else chunk_size
        # Whether the loader ACKs every SEND_CHUNK. Set from the mode actually
        # negotiated in BAUD_AND_ACK; the conservative default is True so that
        # any path reaching the chunk loop without negotiating a mode still
        # waits for replies rather than streaming into a loader that expects to
        # be asked.
        self._ack_each_chunk = True
        # The transport's waiting-byte counter, bound once the negotiated mode
        # turns out to be a streaming one. ``None`` until then, and in an
        # acknowledged mode it stays ``None`` because every chunk is read.
        self._streaming_input_check: Callable[[], int] | None = None
        if not 1 <= self._chunk_size <= self.MAX_CHUNK_SIZE:
            msg = f"chunk_size must be 1..{self.MAX_CHUNK_SIZE}"
            raise ValueError(msg)
        self._handshake_timeout = (
            options.handshake_timeout or self.DEFAULT_HANDSHAKE_TIMEOUT
        )
        # The real CLI leaves this unset and therefore gets the proven 30 s
        # base. The override keeps offline fault-injection tests deterministic
        # without weakening the hardware path.
        reply_timeout = options.reply_timeout
        self._reply_timeout = (
            self.BASE_REPLY_TIMEOUT_SECONDS if reply_timeout is None else reply_timeout
        )
        if self._reply_timeout <= 0:
            msg_0 = "reply_timeout must be greater than zero"
            raise ValueError(msg_0)
        self._reader: ResponseReader | None = None
        self._handshake: HandshakeResult | None = None
        # A loader interaction is permanently single-use. Even an operation
        # that fails after unlock may have advanced target state; callers must
        # close the transport, power-cycle the radio, and construct a new
        # FlashSession before any subsequent probe or flash operation.
        self._consumed_operation: str | None = None
        # Buffer for responses decoded but not yet consumed by the caller.
        # A single transport.read() can return multiple responses (e.g.
        # BUSY immediately followed by ACK during erase); without this
        # buffer the second one is silently dropped.
        #
        # Invariant: the deque is empty between verbs in normal flow.
        # FLDM is purely request/response — the radio never sends
        # unsolicited bytes. If the deque is non-empty when a new
        # verb is about to be sent, it means a previous verb's
        # response stream wasn't fully drained (a bug in the verb's
        # handler) or the radio emitted something unexpected (a
        # protocol regression worth investigating). The
        # ``_read_one_response`` helper returns queued items first
        # without re-reading the transport, which is correct for the
        # BUSY/ACK pattern but would mask such a regression.
        #
        # Reply reads are sized to the exact outstanding count, so this deque
        # is no longer where an unexpected extra reply lands: nothing over-
        # reads it into here, and it stays on the transport instead. The
        # pre-send check therefore looks in both places; see
        # ``_refuse_if_reply_stream_undrained``.
        self._pending: deque[Frame | UnframedResponse] = deque()
        # ───── Async reader thread state (CURRENTLY UNUSED) ───────
        # WARNING: this describes an intended design, not the running one.
        # ``_start_async_reader`` / ``_stop_async_reader`` /
        # ``_wait_for_ack_from_queue`` have no call sites anywhere in ``src``
        # or ``tests``. The SEND_CHUNK pipeline is synchronous today: write a
        # chunk, read its ACK, write the next — the same shape OpenWood uses.
        #
        # The intent was to drain ACKs concurrently with writes, matching the
        # vendor's .NET SerialPort.DataReceived behaviour, with the thread
        # started at the top of each segment's chunk loop and stopped before
        # the next synchronous verb so the two readers never race on
        # transport.read.
        #
        # Left in place rather than deleted because it is a plausible future
        # optimisation, but do not reason about live behaviour from it. On
        # 2026-07-25 this comment sent an investigation of a real SEND_CHUNK
        # failure down a thread-race dead end for exactly that reason.
        #
        # Before wiring it up, note that ``_stop_async_reader`` joins with a
        # 2 s timeout and then clears ``_reader_thread`` regardless of whether
        # the thread actually exited, so a thread that misses its wakeup would
        # keep calling ``transport.read`` after the caller believes it stopped
        # — including after the transport is closed.
        self._ack_queue: queue.Queue[Frame | UnframedResponse] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        self._reader_stop: threading.Event = threading.Event()
        self._reader_error: BaseException | None = None

    def _restore_keyed_post_unlock_baud(self) -> None:
        """Restore 19200 after keyed unlock without losing loader-state context."""
        try:
            self._transport.set_baud(19_200)
        except BaseException as exc:
            raise FlashError(
                step="POST_UNLOCK_BAUD_RESTORE",
                cause=(
                    f"transport set_baud(19200) raised "
                    f"{type(exc).__name__}: {exc} after the loader accepted "
                    "the keyed unlock; no framed command was sent. Loader "
                    "state is advanced/uncertain, so disconnect USB and fully "
                    "power-cycle before any new FLDM session"
                ),
                recoverable=True,
            ) from exc

    def probe_target_only(
        self,
        *,
        baud_ladder: tuple[int, ...] | None = None,
    ) -> TargetInfo:
        """Handshake + official entry ordering through QUERY_TARGET, then stop.

        This sends no known NOR erase/program/finalization verb, but the D75
        loader itself has not been captured, so target-side nonmutation is not
        asserted. It advances FLDM state. Close the transport and power-cycle
        the radio after every exit, successful or otherwise.

        Use this to validate the framed-protocol round-trip (XOR
        encoding, framing, decoding) and to read the radio's target
        identification before committing to a real flash session.

        Raises:
            HandshakeError: If unlock fails at every baud in the ladder.
            FlashError: If ENTER_PROGRAM or QUERY_TARGET fails.

        A ``FlashSession`` is permanently consumed once this method begins.

        """
        self._claim_session("PROBE_TARGET")
        if baud_ladder is None:
            self._handshake = perform_handshake(
                self._transport,
                per_baud_timeout=self._handshake_timeout,
            )
        else:
            self._handshake = perform_handshake(
                self._transport,
                baud_ladder=baud_ladder,
                per_baud_timeout=self._handshake_timeout,
            )
        # The official keyed-unlock response handler unconditionally restores
        # SerialPort.BaudRate=19200 before ENTER_PROGRAM (f.cs:1395-1399).
        self._restore_keyed_post_unlock_baud()
        self._reader = ResponseReader(xor_key=self._handshake.xor_key)
        self._send_and_expect_ack(Verb.ENTER_PROGRAM, b"\x00", "ENTER_PROGRAM")
        self._send_and_expect_ack(Verb.TIMED_SESSION, b"", "TIMED_SESSION")
        target_payload = self._send_and_expect_framed(
            Verb.QUERY_TARGET,
            b"",
            "QUERY_TARGET",
        )
        return _decode_target_info_response(target_payload, step="QUERY_TARGET")

    def calibrate_setup_controls_only(self) -> SetupCalibrationOutcome:
        """Run the three exact stock-main SETUP positive controls.

        The allowlisted addresses/bytes are ``60200000=1C``,
        ``60200014=00``, and ``60200020=FF``. Each descriptor has exactly
        ``DL=2, EL=0, TT=0x0F, ET=CB=CA=CS=CL=0, CT=10, VS=0, VL=1``.
        A response other than the expected ``0`` stops immediately; in
        particular, the default path never sends another SETUP after result 1.

        The host sends no known NOR erase/program/finalization verb. That is
        not proof that the uncaptured target-side SETUP handler cannot mutate
        state. Close the transport and fully power-cycle after every exit.
        """
        descriptors, expected_results = _setup_calibration_plan(
            allow_mismatch_repeat=False,
        )
        return self._run_setup_calibration(
            descriptors,
            expected_results,
            allow_mismatch_repeat=False,
        )

    def calibrate_setup_mismatch_repeat_only(self) -> SetupCalibrationOutcome:
        """Explicitly test one repeated SETUP after a known mismatch.

        This opt-in sends exactly ``60200000=1D`` (expected result 1), then
        ``60200000=1C`` (expected result 0). The official D75 updater does not
        exercise this transition. Run the three positive controls first in a
        separate, freshly power-cycled session; this API intentionally exposes
        no low-NOR or arbitrary-address variant.
        """
        descriptors, expected_results = _setup_calibration_plan(
            allow_mismatch_repeat=True,
        )
        return self._run_setup_calibration(
            descriptors,
            expected_results,
            allow_mismatch_repeat=True,
        )

    def _run_setup_calibration(
        self,
        descriptors: Sequence[SegmentDescriptor],
        expected_results: Sequence[int],
        *,
        allow_mismatch_repeat: bool,
    ) -> SetupCalibrationOutcome:
        """Execute one prevalidated fixed SETUP-only experiment."""
        descriptor_batch = tuple(descriptors)
        result_batch = tuple(expected_results)
        _validate_setup_calibration_plan(
            descriptor_batch,
            result_batch,
            allow_mismatch_repeat=allow_mismatch_repeat,
        )
        operation = (
            "SETUP_MISMATCH_REPEAT"
            if allow_mismatch_repeat
            else "SETUP_POSITIVE_CONTROLS"
        )
        self._claim_session(operation)

        transfer_baud = 576_000
        step = "CLEARTEXT_UNLOCK"
        try:
            # Cleartext FPROMOD at 576000 is proven on the local D75. The
            # official D75 updater uses a keyed unlock; only the post-unlock
            # verb ordering below is claimed to match the official host.
            self._transport.set_baud(transfer_baud)
            self._handshake = perform_cleartext_unlock(
                self._transport,
                baud=transfer_baud,
                timeout=self._reply_timeout,
            )
            self._reader = ResponseReader(xor_key=self._handshake.xor_key)

            step = "ENTER_PROGRAM"
            self._send_and_expect_ack(Verb.ENTER_PROGRAM, b"\x00", step)
            step = "TIMED_SESSION"
            self._send_and_expect_ack(Verb.TIMED_SESSION, b"", step)
            step = "QUERY_TARGET"
            target_payload = self._send_and_expect_framed(
                Verb.QUERY_TARGET,
                b"",
                step,
            )
            target = _decode_target_info_response(target_payload, step=step)
            _refuse_non_d75_target(target)

            step = "BAUD_AND_ACK"
            self._send_and_expect_ack(
                Verb.BAUD_AND_ACK,
                b"\x12\x01",
                step,
            )

            setup_results: list[int] = []
            for idx, (descriptor, expected_result) in enumerate(
                zip(descriptor_batch, result_batch, strict=True),
            ):
                step = f"SETUP_CALIBRATION[{idx}]"
                payload = self._send_and_expect_framed(
                    Verb.SETUP_SEGMENT,
                    descriptor.to_recovery_wire(),
                    step,
                    timeout_seconds=(
                        descriptor.checksum_wait_seconds + self._reply_timeout
                    ),
                )
                actual_result = _decode_setup_result(payload, step=step)
                setup_results.append(actual_result)
                _check_calibration_result(
                    step,
                    actual_result,
                    expected_result,
                    allow_mismatch_repeat=allow_mismatch_repeat,
                )
        except FlashError:
            raise
        except (FrameError, HandshakeError, OSError, TimeoutError) as exc:
            raise FlashError(
                step=step,
                cause=f"{type(exc).__name__}: {exc}",
                recoverable=True,
            ) from exc

        return SetupCalibrationOutcome(
            target=target,
            setup_results=tuple(setup_results),
        )

    # NOTE on TIMED_SESSION (verb 0xA0) and SELECT_TARGET (verb 0xA3):
    #
    # Both verbs have code paths in the official Kenwood TH-D75 updater,
    # but stock V1.03 metadata has no ``#DB`` value, so that exact package
    # branches around SELECT_TARGET. The hardware evidence differs:
    #
    # SELECT_TARGET: confirmed hardware-tested on D75 V1.03 — the
    # loader replies `Frame(verb=0x15, payload=0x01)` (framed NAK,
    # "unsupported command") AND the radio's display advances to
    # "Error Data Error!!". This was an exploratory probe, not part of
    # the stock V1.03 flow. Keep it omitted.
    #
    # TIMED_SESSION: sent exactly once, immediately after
    # ENTER_PROGRAM and before QUERY_TARGET. That ordering matches
    # both OpenWood and the vendor state machine and completed a real
    # D75 V1.03 reflash. An earlier failure came from sending a second
    # TIMED_SESSION after BAUD_AND_ACK, not from this entry verb.
    #
    # What the loader does with it is UNKNOWN. The vendor's ``i()`` sends
    # verb 160 with a null payload and arms only its own 5-second reply
    # timer, so no duration is negotiated on the wire; the whole file has
    # exactly one 0xA0 call site, so the vendor never refreshes it and has
    # no keepalive verb to refresh it with. OpenWood's D74 client calls it
    # "the loader timeout window used during firmware update traffic" with
    # no figure and no citation, and that is a D74 statement regardless.
    # Settling it needs the loader itself, which lives in the uncaptured
    # NOR below 0x00200000.
    #
    # The host-side consequence is therefore a rule of practice, not a
    # measured budget: never idle. The vendor's flow has no host-initiated
    # pause anywhere — its data phase streams packets back to back, and the
    # only long silences in a session are the radio's own erase and verify,
    # where the radio is the one working. Do not add sleeps between chunks
    # or between segments on the theory that the loader needs settling time.
    #
    # Do not add SELECT_TARGET or move/repeat TIMED_SESSION without a
    # new hardware trace that justifies changing the proven ordering.

    def flash_segments(
        self,
        segments: list[SegmentDescriptor],
        segment_data: dict[int, bytes],
        options: FlashRunOptions = _DEFAULT_RUN_OPTIONS,
    ) -> FlashOutcome:
        """Run the full sequence. Raises ``FlashError`` on any failure.

        Args:
            segments: Descriptors built via SegmentDescriptor.for_*
                or .from_kex_block — one per FLDM segment.
            segment_data: Map of segment index → flat payload bytes
                streamed via SEND_CHUNK.
            options: Unlock path, write policy and completion code; see
                :class:`FlashRunOptions`. The default walks the keyed baud
                ladder, writes every segment and sends the stock completion
                code as LE u32.

        """
        complete_update_value = options.complete_update_value
        complete_update_width = options.complete_update_width
        always_flash = options.always_flash
        force_segment_indices = options.force_segment_indices
        _validate_flash_plan(
            segments,
            segment_data,
            complete_update_value=complete_update_value,
            complete_update_width=complete_update_width,
            chunk_size=self._chunk_size,
        )
        _validate_force_segment_indices(force_segment_indices, len(segments))
        self._claim_session("FLASH_SEGMENTS")

        start = time.monotonic()
        self._unlock_for_flash(options)
        target = self._enter_and_check_target(segments)
        self._negotiate_transfer_mode()
        # 3. Per-segment loop
        bytes_total = 0
        segments_written = 0
        for idx, descriptor in enumerate(segments):
            name = f"segment_{idx}"
            setup_result = self._set_up_segment(
                name,
                idx,
                descriptor,
                total_segments=len(segments),
            )
            if (
                setup_result == 0
                and not always_flash
                and idx not in force_segment_indices
            ):
                continue
            if (
                setup_result == 0
                and idx in force_segment_indices
                and self._trace is not None
            ):
                self._trace.note(f"{name} setup=current; qualification force-write")
            bytes_total += self._write_segment(
                name,
                descriptor,
                segment_data.get(idx, b""),
            )
            segments_written += 1
        # 4. COMPLETE_UPDATE
        #
        # The official D75 updater encodes #FC as LE u16. The successful
        # OpenWood-compatible D75 run encoded the same 0x1DB0 value as LE
        # u32. Width is explicit so neither provenance is mislabeled.
        fc_payload = complete_update_value.to_bytes(
            complete_update_width,
            "little",
        )
        self._send_and_expect_ack(
            Verb.COMPLETE_UPDATE,
            fc_payload,
            "COMPLETE_UPDATE",
        )
        elapsed = time.monotonic() - start
        if self._progress is not None:
            self._progress.emit(
                FlashCompleted(
                    bytes_written=bytes_total,
                    elapsed_seconds=elapsed,
                )
            )
        return FlashOutcome(
            target=target,
            segments_written=segments_written,
            bytes_written=bytes_total,
            elapsed_seconds=elapsed,
        )

    # ─── flash_segments phases, in the order the session runs them ───

    def _unlock_for_flash(self, options: FlashRunOptions) -> None:
        """Unlock the loader and arm the response decoder (step 1).

        Reports the resulting line rate and unlock as they happen, then binds
        a :class:`ResponseReader` to the negotiated cipher key.

        Args:
            options: The run's options; only the unlock fields
                (``baud_ladder``, ``cleartext_unlock``, ``cleartext_baud``)
                are read.

        """
        baud_ladder = options.baud_ladder
        cleartext_unlock = options.cleartext_unlock
        cleartext_baud = options.cleartext_baud
        # 1. Handshake. Two paths:
        #   * ``cleartext_unlock=True`` (locally proven on real D75 V1.03
        #     hardware at 576000 with an OpenWood-compatible client): the
        #     caller has already opened the transport at one of the
        #     supported ``#BR`` bauds (default 576000), and we send
        #     the cleartext ``FPROMOD`` magic. Framed traffic then
        #     runs in plaintext (xor_key=0). Simpler and faster.
        #   * ``cleartext_unlock=False`` (legacy, encrypted): walk
        #     the baud ladder probing the encrypted ``Thd75tw``
        #     magic until a baud answers, then derive an XOR key
        #     from the probe's timestamp bytes.
        if cleartext_unlock:
            self._transport.set_baud(cleartext_baud)
            self._emit_baud_change(cleartext_baud, "set before cleartext FPROMOD")
            self._handshake = perform_cleartext_unlock(
                self._transport,
                baud=cleartext_baud,
                timeout=self._reply_timeout,
            )
        elif baud_ladder is None:
            self._handshake = perform_handshake(
                self._transport,
                per_baud_timeout=self._handshake_timeout,
            )
        else:
            self._handshake = perform_handshake(
                self._transport,
                baud_ladder=baud_ladder,
                per_baud_timeout=self._handshake_timeout,
            )
        if not cleartext_unlock:
            # The official keyed path restores 19200 after the unlock reply and
            # before ENTER_PROGRAM. The local cleartext path has no equivalent
            # transition and remains at its explicitly selected 576000 rate.
            self._restore_keyed_post_unlock_baud()
            self._emit_baud_change(19_200, "official restore after keyed unlock")
        # Which rung of the ladder answered is a per-run observation, not a
        # setting, so it is reported here rather than in the configuration
        # banner the CLI prints before any I/O.
        if self._progress is not None:
            self._progress.emit(
                HandshakeSucceeded(
                    baud=self._handshake.baud,
                    xor_key=self._handshake.xor_key,
                )
            )
        if self._trace is not None:
            self._trace.note(
                f"unlocked at baud {self._handshake.baud} via "
                f"{'cleartext' if cleartext_unlock else 'keyed'} path"
            )
        self._reader = ResponseReader(xor_key=self._handshake.xor_key)

    def _enter_and_check_target(self, segments: list[SegmentDescriptor]) -> TargetInfo:
        """Run the entry sequence and gate the plan on the target (step 2).

        Returns:
            The decoded QUERY_TARGET reply.

        Raises:
            FlashError: If an entry command fails, or with step
                ``TARGET_COMPATIBILITY`` if the reply is not the D75 V1.03
                baseline or a segment's ``$TT`` excludes the radio's target
                mask; nothing destructive has been sent at that point.

        """
        # 2. Entry sequence — order matches openwood's hardware-tested
        # D74 client AND the .NET D75 updater's state machine: after
        # ENTER_PROGRAM ACKs, TIMED_SESSION advances the loader to
        # the "ready for target query" state, then QUERY_TARGET
        # returns the target profile, then BAUD_AND_ACK records the
        # transfer policy. Earlier wrong order (QUERY_TARGET before
        # TIMED_SESSION) left the D75 at "Error Data Error!!" until
        # recovery because the loader wasn't ready for QUERY in that
        # path.
        self._send_and_expect_ack(Verb.ENTER_PROGRAM, b"\x00", "ENTER_PROGRAM")
        self._send_and_expect_ack(Verb.TIMED_SESSION, b"", "TIMED_SESSION")
        target_payload = self._send_and_expect_framed(
            Verb.QUERY_TARGET,
            b"",
            "QUERY_TARGET",
        )
        target = _decode_target_info_response(target_payload, step="QUERY_TARGET")
        if self._progress is not None:
            self._progress.emit(
                TargetIdentified(
                    target_mask_bytes=target.target_mask_bytes,
                    opaque_bytes_8_15=target.opaque_bytes_8_15,
                    trailing_status=target.trailing_status,
                    raw_payload=target.raw_payload,
                )
            )
        target_issues = target.d75_mismatch_reasons()
        for idx, descriptor in enumerate(segments):
            if target.target_mask & descriptor.target_type_mask == 0:
                target_issues.append(
                    f"segment {idx} target_type_mask "
                    f"0x{descriptor.target_type_mask:016X} does not include "
                    f"radio target mask 0x{target.target_mask:016X}"
                )
        if target_issues:
            raise FlashError(
                step="TARGET_COMPATIBILITY",
                cause="; ".join(target_issues),
                recoverable=True,
            )
        return target

    def _negotiate_transfer_mode(self) -> None:
        """Declare the data-phase transfer mode with BAUD_AND_ACK."""
        # ────────────────────────────────────────────────────────────
        # SELECT_TARGET is deliberately omitted here. TIMED_SESSION
        # has already been sent at its required entry-sequence position
        # above and must not be repeated after BAUD_AND_ACK. See the
        # NOTE immediately before flash_segments for hardware evidence.
        # ────────────────────────────────────────────────────────────
        #
        # BAUD_AND_ACK payload (verb 0x33) — 2 bytes:
        #   [0] = baud_code   (which baud-mode the loader should expect)
        #   [1] = ack_each_data_packet  (1 = ACK every SEND_CHUNK)
        #
        # The valid baud_codes — extracted from the decompiled
        # official Kenwood TH-D75 firmware updater's baud-mode mapping
        # function:
        #
        #     code   baud      ack_each_data_packet
        #     0x09   57600     False
        #     0x0A   115200    False
        #     0x12   576000    True
        #     0x14   1152000   True
        #
        # A stale paragraph used to sit here asserting "we pick **0x12
        # (576000, ack=True)**", left behind when the selection moved to
        # `negotiated_transfer_mode()`. It contradicted the payload the very
        # next statement sends. Whatever mode is selected, it is selected in
        # exactly one place — `_FLDM_TRANSFER_MODE_CODE` — and both payload
        # bytes come from the same table row, so the declared protocol and the
        # protocol the chunk loop runs cannot drift apart.
        #
        # The selected 0x12/ACK profile is not merely inferred from metadata:
        # together with 256-byte data packets and one END_TRANSFER per segment,
        # it completed full stock restores on this D75 on 2026-07-05 and
        # 2026-07-25. The failed 1024-byte and streaming-mode experiments are
        # deliberately not used as defaults.
        mode = negotiated_transfer_mode()
        self._ack_each_chunk = mode.ack_each_data_packet
        if not self._ack_each_chunk:
            # Resolved here, before the first destructive verb, rather than
            # inside the chunk loop. A transport that cannot report waiting
            # bytes cannot stream safely, and finding that out mid-segment
            # means finding it out after an erase.
            self._claim_streaming_input_check()
        self._send_and_expect_ack(
            Verb.BAUD_AND_ACK,
            mode.payload,
            "BAUD_AND_ACK",
        )
        # We do not touch SerialPort baud after this ACK. The port keeps
        # whatever rate it was opened at: the keyed path stays at the restored
        # 19200 line coding, the cleartext path at the rate selected before
        # FPROMOD. On USB CDC line coding does not set the transport speed, so
        # this costs nothing.
        #
        # This used to be justified by "the official updater's
        # ack_each_packet=true branch deliberately does not assign
        # SerialPort.BaudRate after this ACK (f.cs:2551-2557)". **That reads
        # the branch backwards.** At f.cs:2551, inside `private void f()`,
        # `if (s().mBaudRateSelect.c())` tests the #BR ack flag, and the TRUE
        # arm is the one that assigns: it routes to state 14 → 15, which tests
        # `s().mSerialPort.BaudRate != s().mBaudRateSelect.d()` and on a
        # mismatch reaches state 11, which runs
        # `s().mSerialPort.BaudRate = s().mBaudRateSelect.d();` and then
        # `Thread.Sleep(1000);`.
        #
        # The ack=false arm falls straight through to state 10 and assigns
        # nothing there. (A separate assignment does exist on the ack=false
        # path in `private void d()` at f.cs:2754, followed by the baud-down
        # dance to 19200 at f.cs:2779 — a different method at a different
        # point in the sequence, not the same rule.)
        #
        # So not reconfiguring the port is a deliberate DELTA from the vendor,
        # and on the acknowledged mode it is a delta from the branch that most
        # clearly does reconfigure. It is still the right call on CDC; it is
        # simply not vendor parity, and must not be written up as such.

    def _set_up_segment(
        self,
        name: str,
        idx: int,
        descriptor: SegmentDescriptor,
        *,
        total_segments: int,
    ) -> int:
        """Announce one segment and send its SETUP (step 3a).

        Returns:
            The loader's decision: 0 when the described bytes are already
            current, 1 when an update is required.

        """
        if self._progress is not None:
            self._progress.emit(
                SegmentStarted(
                    name=name,
                    index=idx,
                    total_segments=total_segments,
                    byte_count=descriptor.data_length,
                    expected_erase_seconds=descriptor.erase_wait_seconds,
                    erase_length=descriptor.erase_length,
                )
            )
        # 3a. SETUP_SEGMENT
        setup_payload = self._send_and_expect_framed(
            Verb.SETUP_SEGMENT,
            descriptor.to_recovery_wire(),
            f"SETUP_SEGMENT[{name}]",
            timeout_seconds=(descriptor.checksum_wait_seconds + self._reply_timeout),
        )
        return _decode_setup_result(
            setup_payload,
            step=f"SETUP_SEGMENT[{name}]",
        )

    def _write_segment(
        self,
        name: str,
        descriptor: SegmentDescriptor,
        raw_data: bytes,
    ) -> int:
        """BEGIN, stream, END and (when ``$CL`` is nonzero) VERIFY one segment.

        Covers steps 3b to 3e for a segment the SETUP decision admitted.

        Returns:
            The number of data bytes streamed: the first ``$DL`` bytes of
            ``raw_data``.

        """
        self._begin_transfer(name, descriptor)
        # 3c. SEND_CHUNK loop
        #
        # D75 SEND_CHUNK (0x43) payload layout, extracted from the
        # official Kenwood TH-D75 firmware updater's dedicated
        # data-streaming helper class:
        #
        #     bytes 0-3 :  offset       (u32 LE)
        #     bytes 4-7 :  chunk_length (u32 LE)  ← D75 ADDITION
        #     bytes 8-N :  data
        #
        # The 4-byte chunk_length field is required by the D75
        # loader. The updater writes the same chunk_length value
        # on every chunk in a given segment (the descriptor's
        # chunk-size constant). Sending a SEND_CHUNK payload
        # without it — for example a bare `offset:u32 + data`
        # form — produces wire bytes the D75 loader silently
        # discards.
        #
        # Trim segment data to the descriptor's data_length. KEX
        # parsing returns the full intel-hex coverage (which equals
        # the erase region $EL, rounded up to a sector boundary).
        # The vendor only streams $DL bytes per segment — the
        # trailing $EL-$DL bytes are 0xFF erase fill that the radio
        # never receives. Stock V1.03 segments 1 and 4 are 32 KiB
        # bigger in $EL than $DL; sending those extra bytes would
        # over-shoot the loader's per-segment data counter.
        data = raw_data[: descriptor.data_length]
        self._send_segment_data(name, descriptor, data)
        # 3d. END_TRANSFER exactly once for the whole segment.
        #
        # `$DC` is host-side KEX metadata and is absent from the SETUP
        # descriptor, so it cannot tell the loader to withhold ACKs or
        # require intermediate END_TRANSFER commands. Both retained
        # successful D75 restores sent every 256-byte packet, received its
        # ACK, and then sent one END_TRANSFER after the segment's final
        # packet. Do not reintroduce a per-$DC cadence into this proven
        # recovery path.
        self._send_and_expect_ack(
            Verb.END_TRANSFER,
            b"",
            f"END_TRANSFER[{name}]",
        )
        # 3e. VERIFY_SEGMENT (only when $CL is non-zero)
        #
        # The vendor state machine skips this verb entirely when
        # the descriptor's checksum_length ($CL) is zero. Stock
        # sub-sector overlays use that exact pattern; asking FLDM
        # to verify them changes the state-machine sequence and can
        # make an otherwise valid ZZZ-last raw flash fail.
        if descriptor.checksum_length != 0:
            self._verify_segment(name, descriptor)
        return len(data)

    def _begin_transfer(self, name: str, descriptor: SegmentDescriptor) -> None:
        """Send BEGIN_TRANSFER and wait through any BUSY replies for its ACK.

        Reports how long that took and how the loader paced it with BUSY.

        Raises:
            FlashError: If the send or a read fails, or a response is neither
                BUSY nor ACK. A read timeout is reported with the loader state
                marked uncertain, since BEGIN_TRANSFER has already been sent.

        """
        # 3b. BEGIN_TRANSFER (may BUSY).
        #
        # The loader emits one or more BUSY responses while the
        # destination NOR sectors are being erased, then a final
        # ACK when the erase completes. Both forms (bare byte and
        # framed reply) are accepted via the centralised
        # :meth:`_is_ack` / :meth:`_is_busy` helpers — see
        # :meth:`_send_and_expect_ack` for the rationale (D75 V1.03
        # wraps its post-unlock acks/busys in framed replies).
        # The retained successful OpenWood run sends BEGIN for every
        # non-skipped segment, including the two overlays whose ``$EL`` is
        # zero. Preserve that exact state-machine sequence.
        erase_step = f"BEGIN_TRANSFER[{name}]"
        erase_start = time.monotonic()
        begin_response_timeout = descriptor.erase_wait_seconds + self._reply_timeout
        # Retain BUSY timing as telemetry only. It does not narrow the
        # proven per-response timeout or create a separate total budget.
        busy_count = 0
        first_busy_seconds: float | None = None
        busy_intervals: list[float] = []
        previous_busy = erase_start
        self._send(
            Verb.BEGIN_TRANSFER,
            b"",
            step=erase_step,
        )
        while True:
            resp = self._read_one_response_for_step(
                erase_step,
                timeout_seconds=begin_response_timeout,
                loader_state_uncertain=True,
            )
            if self._is_busy(resp):
                now = time.monotonic()
                busy_count += 1
                if first_busy_seconds is None:
                    first_busy_seconds = now - erase_start
                elif len(busy_intervals) < _MAX_RECORDED_BUSY_INTERVALS:
                    busy_intervals.append(now - previous_busy)
                previous_busy = now
                continue
            if self._is_ack(resp):
                break
            raise FlashError(
                step=erase_step,
                cause=f"unexpected response {resp!r}",
                recoverable=True,
            )
        erase_seconds = time.monotonic() - erase_start
        if self._trace is not None:
            self._trace.note(
                f"{erase_step} completed in {erase_seconds:.3f}s, "
                f"{busy_count} BUSY frames"
            )
        if self._progress is not None:
            self._progress.emit(
                SegmentErased(
                    name=name,
                    elapsed_seconds=erase_seconds,
                    busy_count=busy_count,
                    first_busy_seconds=first_busy_seconds,
                    busy_intervals=tuple(busy_intervals),
                )
            )

    def _send_segment_data(
        self,
        name: str,
        descriptor: SegmentDescriptor,
        data: bytes,
    ) -> None:
        """Stream one segment's data packets in the negotiated transfer mode.

        Raises:
            FlashError: If a packet is rejected or a transport operation fails.

        """
        # Per-segment chunk size, capped by the session default.
        #
        # Vendor uses $DU=1024 for large segments and $DU=$DL
        # (single-chunk) for sub-sector overlays. Use the session's
        # declared data unit, except that those overlays carry a smaller
        # ``$DU == $DL`` and must be sent as one exact packet. Preflight
        # has already proved divisibility, so no short final packet can
        # reach the radio.
        #
        # The session cap is intentionally 256 even though the descriptor
        # advertises $DU=1024. `$DU` is host metadata and is not serialized
        # in SETUP; the loader sees the actual length in every SEND_CHUNK
        # header. Two full D75 stock restores prove that four acknowledged
        # 256-byte packets are accepted in place of one advertised
        # 1024-byte data unit.
        effective_chunk_size = min(
            self._chunk_size,
            descriptor.chunk_size or self._chunk_size,
        )
        # Bound once per segment, not once per chunk: in the streamed mode
        # this is the transport's waiting-byte counter, and in the
        # acknowledged mode it is ``None`` because every chunk is read
        # anyway. The streamed branch below therefore pays one local
        # ``is not None`` test plus the counter call, and the acknowledged
        # branch pays nothing at all.
        streamed_input_check = (
            None if self._ack_each_chunk else self._streaming_input_check
        )
        # Periodic throughput. A run that is going to take three hours
        # instead of four minutes should say so while it still can be
        # stopped, not after. The counters are locals and the interval is
        # hoisted out of the attribute, so with reporting off the data
        # phase pays one truthiness test on an int per chunk.
        report_interval = self._progress_every_chunks
        data_phase_start = time.monotonic()
        chunks_sent = 0
        bytes_sent = 0
        chunks_since_report = 0
        # Preflight rejects zero-length segments, but initialize this for
        # static analysis and for defensive clarity on the post-loop
        # streamed-response check.
        step = f"SEND_CHUNK[{name}]@0"
        for offset in range(0, len(data), effective_chunk_size):
            chunk = data[offset : offset + effective_chunk_size]
            payload = (
                offset.to_bytes(4, "little") + len(chunk).to_bytes(4, "little") + chunk
            )
            step = f"SEND_CHUNK[{name}]@{offset}"
            if self._ack_each_chunk:
                self._send_and_expect_ack(Verb.SEND_CHUNK, payload, step)
            else:
                # ack_each_data_packet=False. The loader does not reply to
                # individual data packets in this mode, so reading for one
                # blocks until the timeout on every single chunk. Stream
                # them back to back and let END_TRANSFER and the segment
                # VERIFY be the synchronisation points; VERIFY checks the
                # programmed contents against the descriptor checksum, so a
                # chunk lost in transit still fails the segment rather than
                # passing silently.
                self._send(Verb.SEND_CHUNK, payload, step=step)
                # The loader owes no reply here, so anything it sends is a
                # rejection. Nothing else in this phase reads, so without
                # this glance those bytes would wait in the receive queue
                # until END_TRANSFER's read consumed them, which reports
                # the failure against END_TRANSFER and only after the rest
                # of the segment has been written into a loader that
                # stopped accepting it. The check never blocks and never
                # consumes a byte; the drain and the abort happen only
                # once it has already found something.
                if streamed_input_check is not None and streamed_input_check():
                    self._abort_on_streamed_response(step)
            if self._progress is not None:
                self._progress.emit(
                    SegmentChunkSent(
                        name=name,
                        offset=offset,
                        bytes_in_chunk=len(chunk),
                    )
                )
            if report_interval:
                chunks_sent += 1
                bytes_sent += len(chunk)
                chunks_since_report += 1
                if chunks_since_report >= report_interval:
                    chunks_since_report = 0
                    self._emit_throughput(
                        name,
                        chunks_sent=chunks_sent,
                        bytes_sent=bytes_sent,
                        elapsed_seconds=time.monotonic() - data_phase_start,
                    )
        if report_interval and chunks_since_report:
            # Close the segment's own record rather than leaving its last
            # partial interval to be inferred from the next segment.
            self._emit_throughput(
                name,
                chunks_sent=chunks_sent,
                bytes_sent=bytes_sent,
                elapsed_seconds=time.monotonic() - data_phase_start,
            )
        # The last chunk's rejection cannot have arrived before the check
        # that follows its own write, so look once more before handing the
        # port to END_TRANSFER. ``step`` is the final chunk's step: the
        # loop runs at least once because preflight rejects a zero-length
        # segment. Whatever still slips past this lands in END_TRANSFER's
        # read, which fails the segment under that verb's name rather than
        # letting a rejected chunk pass.
        if streamed_input_check is not None and streamed_input_check():
            self._abort_on_streamed_response(step)

    def _verify_segment(self, name: str, descriptor: SegmentDescriptor) -> None:
        """Ask the loader to check the segment against its ``$CA`` (step 3e).

        Raises:
            FlashError: If the reply is not exactly one byte, or reports
                anything but 0 (verified).

        """
        # The loader checks the descriptor's ``$CA`` internally
        # and returns exactly one result byte: 0 means verified,
        # 1 means verification failed. This is a status code, not
        # the computed checksum. OpenWood parses the same response
        # as ``SegmentVerifyResult`` and treats failure as fatal.
        verify_payload = self._send_and_expect_framed(
            Verb.VERIFY_SEGMENT,
            b"",
            f"VERIFY_SEGMENT[{name}]",
            timeout_seconds=(descriptor.checksum_wait_seconds + self._reply_timeout),
        )
        if len(verify_payload) != 1:
            raise FlashError(
                step=f"VERIFY_SEGMENT[{name}]",
                cause=(
                    f"loader result must be exactly 1 byte, got {len(verify_payload)}"
                ),
                recoverable=True,
            )
        verify_status = verify_payload[0]
        if verify_status != 0:
            description = (
                "segment checksum did not match"
                if verify_status == 1
                else "unknown verification status"
            )
            raise FlashError(
                step=f"VERIFY_SEGMENT[{name}]",
                cause=f"{description}: 0x{verify_status:02X}",
                recoverable=True,
            )
        if self._progress is not None:
            self._progress.emit(
                SegmentVerified(
                    name=name,
                    expected_checksum=descriptor.expected_after_checksum,
                    status_code=verify_status,
                )
            )

    # ─── Helpers ─────────────────────────────────────────────────────

    def _claim_session(self, operation: str) -> None:
        """Permanently consume this object before its first device I/O."""
        if self._consumed_operation is not None:
            raise FlashError(
                step=f"{operation}_PREFLIGHT",
                cause=(
                    "FlashSession is single-use and was already consumed by "
                    f"{self._consumed_operation}; close the transport, fully "
                    "power-cycle the radio, and construct a new session"
                ),
                recoverable=True,
            )
        self._consumed_operation = operation

    def _emit_baud_change(self, baud: int, reason: str) -> None:
        """Record an actual line-rate transition, not an intended one."""
        if self._progress is not None:
            self._progress.emit(TransportBaudChanged(baud=baud, reason=reason))
        if self._trace is not None:
            self._trace.note(f"baud -> {baud} ({reason})")

    def _emit_throughput(
        self,
        name: str,
        *,
        chunks_sent: int,
        bytes_sent: int,
        elapsed_seconds: float,
    ) -> None:
        """Emit one periodic data-phase throughput sample."""
        rate = bytes_sent / elapsed_seconds if elapsed_seconds > 0 else 0.0
        if self._progress is not None:
            self._progress.emit(
                SegmentProgress(
                    name=name,
                    chunks_sent=chunks_sent,
                    bytes_sent=bytes_sent,
                    elapsed_seconds=elapsed_seconds,
                    bytes_per_second=rate,
                )
            )
        if self._trace is not None:
            self._trace.note(
                f"{name}: {chunks_sent} chunks, {bytes_sent} bytes, "
                f"{elapsed_seconds:.3f}s, {rate:.0f} B/s"
            )

    def _start_async_reader(self) -> None:
        """Start the background ACK-reader thread.

        The thread continuously reads from ``self._transport``,
        feeds the bytes through ``self._reader`` to assemble
        complete responses, and puts each one onto
        ``self._ack_queue`` for the main thread to consume. This
        mirrors how the .NET updater's SerialPort.DataReceived
        event collects ACKs concurrently with the SEND_CHUNK loop —
        the main thread can keep writing without the radio's TX
        FIFO backpressuring its RX (which would in turn block our
        write and trigger WriteTimeout).

        This code has no call sites (see the note in ``__init__``) and its
        ``transport.read(4096)`` predates the exact-count read contract: the
        transport now waits for the full requested count, so that call costs a
        port timeout per iteration rather than returning whatever landed.
        Wiring this up means driving it from ``ResponseReader.bytes_needed``
        the way :meth:`_read_one_response` does, not reinstating a fixed size.
        """
        if self._reader is None:
            msg = "reader thread requires the descrambler — start after handshake"
            raise AssertionError(msg)
        # Reset state from any prior segment's reader. ``empty()`` can race a
        # producer, so ``get_nowait`` may still find nothing; either way the
        # drain stops there.
        self._reader_stop.clear()
        self._reader_error = None
        with contextlib.suppress(queue.Empty):
            while not self._ack_queue.empty():
                _ = self._ack_queue.get_nowait()
        # Drain anything the synchronous path already buffered.
        while self._pending:
            self._ack_queue.put(self._pending.popleft())

        def loop() -> None:
            try:
                while not self._reader_stop.is_set():
                    raw = self._transport.read(4096)
                    if not raw:
                        # Non-blocking transports (the mock radio
                        # in tests) return b"" immediately when no
                        # data is available; a small sleep yields
                        # the GIL so the main thread can advance.
                        # Real pyserial blocks for its read timeout
                        # so this branch is essentially never hit.
                        time.sleep(0.001)
                        continue
                    for resp in self._unlocked_reader().feed(raw):
                        self._ack_queue.put(resp)
            # The thread's top level: every failure, of any type, is stored for
            # the joining thread, which re-raises it (_stop_async_reader) or
            # reports it (_wait_for_ack_from_queue). Letting it escape would
            # only print it from threading.excepthook.
            except BaseException as exc:  # noqa: BLE001 - thread top level; joiner re-raises
                self._reader_error = exc

        self._reader_thread = threading.Thread(
            target=loop,
            daemon=True,
            name="thd75-flash-ack-reader",
        )
        self._reader_thread.start()

    def _stop_async_reader(self) -> None:
        """Stop the background reader thread and re-raise any error.

        The reader is blocked in ``transport.read()``. We set the
        stop event; the thread exits the next time ``read()``
        returns (which happens at the transport's read timeout,
        currently 1 s). A short ``join`` window covers the worst-
        case wakeup latency without hanging indefinitely on a
        misbehaving transport.
        """
        if self._reader_thread is None:
            return
        self._reader_stop.set()
        self._reader_thread.join(timeout=2.0)
        self._reader_thread = None
        if self._reader_error is not None:
            err = self._reader_error
            self._reader_error = None
            raise err

    def _wait_for_ack_from_queue(
        self,
        *,
        timeout: float,
        name: str,
        offset: int,
    ) -> Frame | UnframedResponse:
        """Block until the reader thread queues an ACK, with timeout.

        Re-raises any error the reader thread caught (so a
        transport hang surfaces as a FlashError on the main thread
        rather than a silent hang).
        """
        if self._reader_error is not None:
            err = self._reader_error
            self._reader_error = None
            raise FlashError(
                step=f"SEND_CHUNK[{name}]@{offset}",
                cause=f"reader thread error: {err!r}",
                recoverable=False,
            )
        try:
            return self._ack_queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise FlashError(
                step=f"SEND_CHUNK[{name}]@{offset}",
                cause=(
                    f"no ACK from reader queue within {timeout}s "
                    f"(in-flight chunks queued but radio stopped "
                    f"responding)"
                ),
                recoverable=True,
            ) from exc

    def _claim_streaming_input_check(self) -> None:
        """Bind the transport's waiting-byte counter, or refuse to stream.

        A streamed data phase reads nothing between chunks, so this counter is
        the session's only way to hear a loader that has started rejecting
        them. Without it a NAK would sit unread for the remainder of the
        segment. That is a real failure mode rather than a missing nicety, so a
        transport that cannot supply the counter does not get to stream.

        Called from BAUD_AND_ACK, before SETUP, BEGIN, or any byte of data, so
        the refusal costs nothing but the session; discovering it later would
        mean discovering it after an erase.

        Raises:
            FlashError: If the transport has no callable ``pending_input``.

        """
        if not callable(getattr(self._transport, "pending_input", None)):
            raise FlashError(
                step="BAUD_AND_ACK",
                cause=(
                    "the selected transfer mode acknowledges no data packet, "
                    "so the host streams chunks and only notices a rejected "
                    "one by checking for waiting bytes between them; this "
                    f"transport ({type(self._transport).__name__}) has no "
                    "callable pending_input(), so a mid-stream NAK would go "
                    "unread until END_TRANSFER"
                ),
                recoverable=True,
            )
        self._streaming_input_check = self._transport.pending_input

    def _abort_on_streamed_response(self, step: str) -> None:
        """Fail the segment because the loader spoke during a streamed phase.

        In the ``ack_each_data_packet=0`` modes the loader answers no data
        packet at all, so any byte arriving while chunks stream is the loader
        rejecting one. The bytes are drained and decoded here purely to name
        what arrived; the call never returns.

        ``step`` names the chunk in flight when the bytes were seen. The
        loader's reply trails the writer by a round trip, so the rejected chunk
        may be a slightly earlier one in the same segment. That is still the
        right attribution to report: it points at the data phase and at an
        offset within one chunk or so of the truth, where the alternative was
        pointing at END_TRANSFER.

        Raises:
            FlashError: Always. ``recoverable`` is true because the loader has
                just demonstrated that it is alive and answering; this is a
                rejected write, not a damaged bootloader.

        """
        try:
            resp = self._read_one_response(
                timeout_seconds=self.STREAMED_ERROR_DRAIN_SECONDS,
            )
        except (FrameError, OSError, TimeoutError) as exc:
            raise FlashError(
                step=step,
                cause=(
                    "loader sent bytes during a data phase that acknowledges "
                    "nothing, and they did not decode into a response within "
                    f"{self.STREAMED_ERROR_DRAIN_SECONDS}s: "
                    f"{type(exc).__name__}: {exc}"
                ),
                recoverable=True,
            ) from exc
        raise FlashError(
            step=step,
            cause=(
                f"loader sent {resp!r} during a data phase that acknowledges "
                "nothing; the reply can only be a rejection of this chunk or "
                "one already streamed, so the rest of the segment is not sent"
            ),
            recoverable=True,
        )

    def _refuse_if_reply_stream_undrained(self, verb: Verb, step: str) -> None:
        """Refuse to send while the previous command's reply is still around.

        FLDM is strictly request/response and the loader never speaks unbidden,
        so anything undrained when a verb is about to go out means the previous
        verb's reply stream was not fully consumed, or the loader said
        something nobody asked for. Either way the link is out of phase, and
        sending anyway makes the *next* reply the one that looks wrong while
        the evidence that would have explained it is already gone. On this
        transport that costs a power cycle to recover from, and on the SETUP
        oracle paths it would mean an unplanned command reaching the loader.

        Two places have to be checked, because reply reads are now sized to the
        exact outstanding count. A response decoded but not yet handed to the
        caller sits in ``_pending``; a reply the host never asked for is still
        on the transport, since an exact-count read has no reason to pick up
        anything beyond the response it was sizing for. The fixed-size reads
        this replaced happened to over-read, which is the only reason the
        second case ever landed in ``_pending`` to be caught there.

        Raises:
            FlashError: If either the decoded queue or the transport's receive
                queue still holds anything.

        """
        if self._pending:
            raise FlashError(
                step=step,
                cause=(
                    f"refusing to send {verb.name}: {len(self._pending)} "
                    "unconsumed response(s) remain from the previous command"
                ),
                recoverable=True,
            )
        # Transports without the counter fall back to the queue check alone.
        # The streaming path, where it is load-bearing rather than a backstop,
        # refuses such a transport outright; see _claim_streaming_input_check.
        if not callable(getattr(self._transport, "pending_input", None)):
            return
        waiting = self._transport.pending_input()
        if waiting:
            raise FlashError(
                step=step,
                cause=(
                    f"refusing to send {verb.name}: {waiting} unconsumed "
                    "response byte(s) are still waiting on the transport from "
                    "the previous command"
                ),
                recoverable=True,
            )

    def _unlocked_reader(self) -> ResponseReader:
        """Return the response decoder the unlock bound.

        Raises:
            AssertionError: If no unlock has bound one. Every public entry
                point unlocks before it reads, so this is an internal
                invariant, raised bare as the ``assert`` it replaces did.

        """
        if self._reader is None:
            raise AssertionError
        return self._reader

    def _send(self, verb: Verb, payload: bytes, *, step: str) -> None:
        if self._handshake is None:
            # Every public entry point unlocks before its first send, so this
            # is an internal invariant: the bare AssertionError it always was.
            raise AssertionError
        self._refuse_if_reply_stream_undrained(verb, step)
        frame = Frame(header=0, verb=int(verb), payload=payload)
        wire = build_frame(frame, xor_key=self._handshake.xor_key)
        # Recorded before the write, so a frame that hangs the transport is
        # in the trace as sent rather than missing from it. The cleartext
        # payload is what gets recorded, truncated: the scrambled wire form
        # would need the session key to read back.
        if self._trace is not None:
            self._trace.record_tx(int(verb), payload)
        try:
            written = self._transport.write(wire)
        except (OSError, TimeoutError) as exc:
            raise FlashError(
                step=step,
                cause=f"transport write failed: {type(exc).__name__}: {exc}",
                recoverable=True,
            ) from exc
        if written != len(wire):
            raise FlashError(
                step=step,
                cause=f"short transport write: sent {written} of {len(wire)} bytes",
                recoverable=True,
            )

    def _read_one_response(
        self,
        *,
        timeout_seconds: float | None = None,
    ) -> Frame | UnframedResponse:
        reader = self._unlocked_reader()
        if self._pending:
            return self._pending.popleft()
        # The transport blocks until the requested count arrives or its port
        # timeout fires, so the loop needs no ``time.sleep()`` of its own. An
        # earlier 5 ms sleep added 5 ms to every SEND_CHUNK round trip, which
        # is reason enough to have removed it.
        #
        # The quantification that used to follow — "~20% of the per-chunk time,
        # turning a ~6-minute V1.03 reflash into ~7" — is withdrawn as
        # UNVERIFIED. Both figures trace back to a reflash duration no log in
        # this repo records, and the "~20%" additionally requires a per-chunk
        # round trip that was never measured. The sleep was pure overhead
        # regardless of what fraction it was.
        #
        # Ask for exactly the reference decoder's next stage. ``read`` returns
        # the instant the requested byte count lands and otherwise waits out
        # the port timeout, so a fixed ceiling like the previous ``read(256)``
        # made every reply cost that whole timeout: the loader answers with one
        # ACK byte or a short frame and never with 256 bytes, so the count was
        # never satisfied and the wait always ran to the deadline. Per-packet
        # ACK segments paid it once per chunk. For a framed reply,
        # ``bytes_needed`` reproduces OpenWood's four low-level reads: one
        # classifying byte, one second sync byte, the six-byte ``HH + LL + VV``
        # header, then ``body_length`` bytes of payload plus checksum. The
        # boundaries matter because OpenWood re-applies macOS's custom baud
        # ioctl before every one of those reads.
        #
        # 30 s is part of the hardware-proven recovery profile. The reference
        # library's 2 s default made a 576000/ACK/256 transfer reach partway
        # through a segment and then abort; setting its reply ceiling to 30 s
        # completed stock restores on 2026-07-05 and 2026-07-25. Reads still
        # return as soon as a complete response arrives, so this margin adds no
        # latency to a healthy exchange.
        response_timeout = (
            self._reply_timeout if timeout_seconds is None else timeout_seconds
        )
        deadline = time.monotonic() + response_timeout
        while time.monotonic() < deadline:
            # ``feed`` drains every complete response before returning, so the
            # reader is always mid-response here and the count is positive. The
            # floor of 1 keeps a ``read(0)`` (which reads nothing) from
            # spinning the loop against its deadline if that ever changes.
            want = min(
                max(1, reader.bytes_needed()),
                _MAX_RESPONSE_READ_BYTES,
            )
            chunk = self._transport.read(want)
            if chunk:
                ready = reader.feed(chunk)
                if ready:
                    # Timestamped where the response is decoded, not where a
                    # caller consumes it: a BUSY buffered behind an ACK must
                    # keep the arrival time that makes erase pacing readable.
                    if self._trace is not None:
                        for response in ready:
                            self._trace.record_rx(*_traced_response(response))
                    self._pending.extend(ready)
                    return self._pending.popleft()
        msg = f"no response within {response_timeout:g}s"
        raise TimeoutError(msg)

    def _read_one_response_for_step(
        self,
        step: str,
        *,
        timeout_seconds: float | None = None,
        loader_state_uncertain: bool = False,
    ) -> Frame | UnframedResponse:
        """Read one response and retain command context on transport failures."""
        try:
            return self._read_one_response(timeout_seconds=timeout_seconds)
        except TimeoutError as exc:
            cause = f"response read failed: TimeoutError: {exc}"
            if loader_state_uncertain:
                cause += (
                    "; BEGIN_TRANSFER was already sent and loader state is "
                    "uncertain. Disconnect "
                    "USB and fully power-cycle before any new FLDM session"
                )
            raise FlashError(
                step=step,
                cause=cause,
                recoverable=True,
            ) from exc
        except (FrameError, OSError) as exc:
            raise FlashError(
                step=step,
                cause=f"response read failed: {type(exc).__name__}: {exc}",
                recoverable=True,
            ) from exc

    @staticmethod
    def _is_ack(resp: Frame | UnframedResponse) -> bool:
        """Return whether ``resp`` is a positive acknowledgement.

        The D75 loader can send one in either form:

        * Unframed bare ``0x06`` byte (cleartext mode / alternate
          loader variants).
        * Framed reply with verb ``0x06`` and empty payload (the form
          a real D75 V1.03 loader returns to framed commands).

        Centralised so every site that waits on an ACK uses the same
        acceptance criteria — keeping ``_send_and_expect_ack`` and the
        BEGIN_TRANSFER busy/ack loop in :meth:`_begin_transfer` in lockstep.
        """
        if isinstance(resp, UnframedResponse) and resp.code is AckCode.ACK:
            return True
        return bool(
            isinstance(resp, Frame)
            and resp.verb == AckCode.ACK.value
            and not resp.payload
        )

    @staticmethod
    def _is_busy(resp: Frame | UnframedResponse) -> bool:
        """Return whether ``resp`` is a "still working, try again" reply.

        BUSY appears during BEGIN_TRANSFER's erase phase — the loader
        emits one or more BUSY responses while the NOR sectors are
        being erased, then a final ACK when the erase completes. The
        bare ``0x11`` form is documented; the framed form (verb 0x11,
        empty payload) mirrors the framed-ACK pattern observed on D75.
        """
        if isinstance(resp, UnframedResponse) and resp.code is AckCode.BUSY:
            return True
        return bool(
            isinstance(resp, Frame)
            and resp.verb == AckCode.BUSY.value
            and not resp.payload
        )

    @staticmethod
    def _is_nak(resp: Frame | UnframedResponse) -> bool:
        """Return whether ``resp`` is a negative acknowledgement.

        D75 produces NAKs in framed form on hardware (verified via the
        SELECT_TARGET probe: ``Frame(verb=0x15, payload=0x01)``). The
        bare two-byte form ``0x15 <subcode>`` is the documented
        cleartext-mode shape; this helper recognises both so the
        ``recoverable`` flag on ``FlashError`` is set correctly
        regardless of which form the loader emits.
        """
        if isinstance(resp, UnframedResponse) and resp.code is AckCode.NAK:
            return True
        return bool(isinstance(resp, Frame) and resp.verb == AckCode.NAK.value)

    def _send_and_expect_ack(self, verb: Verb, payload: bytes, step: str) -> None:
        """Send `verb` and validate the loader's positive acknowledgement.

        Empirically observed on a real D75: the loader's ACK to a
        framed command is **itself a framed reply with verb 0x06 and
        empty payload**, not a raw single byte 0x06. We accept either
        form so the same code path works for both the framed-ACK case
        (real D75 V1.03 hardware) and the bare-byte case (cleartext
        mode or any loader variant that doesn't wrap its ACKs):

        * **Unframed**: ``UnframedResponse(AckCode.ACK)`` — single
          0x06 byte (cleartext mode).
        * **Framed**: ``Frame(verb=0x06, payload=b"")`` — what the
          actual D75 V1.03 loader sends.
        """
        self._send(verb, payload, step=step)
        resp = self._read_one_response_for_step(step)
        if self._is_ack(resp):
            return
        raise FlashError(
            step=step,
            cause=f"expected ACK, got {resp!r}",
            recoverable=self._is_nak(resp),
        )

    def _send_and_expect_framed(
        self,
        verb: Verb,
        payload: bytes,
        step: str,
        *,
        timeout_seconds: float | None = None,
    ) -> bytes:
        self._send(verb, payload, step=step)
        resp = self._read_one_response_for_step(
            step,
            timeout_seconds=timeout_seconds,
        )
        if not isinstance(resp, Frame):
            # resp's static type narrows to UnframedResponse here; the
            # only way an unframed response shows up where a framed
            # one was expected is a bare NAK in cleartext mode.
            raise FlashError(
                step=step,
                cause=f"expected framed response, got {resp!r}",
                recoverable=resp.code is AckCode.NAK,
            )
        # A framed NAK (D75-style ``Frame(verb=0x15, payload=<subcode>)``)
        # is a "loader rejected this verb" condition and is recoverable
        # in the same sense an unframed NAK would be — the operator can
        # power-cycle and try again.
        if self._is_nak(resp):
            raise FlashError(
                step=step,
                cause=f"loader rejected verb: {resp!r}",
                recoverable=True,
            )
        if resp.verb != response_verb_for(verb):
            raise FlashError(
                step=step,
                cause=f"unexpected response verb 0x{resp.verb:02X}",
                recoverable=True,
            )
        return resp.payload
