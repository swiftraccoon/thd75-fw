"""Typed progress events emitted by FlashSession.

The CLI renders these via Rich (see ``thd75_fw.flash_ui``); tests use
a list-recording listener to assert event ordering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class HandshakeStarted:
    """A keyed unlock is about to probe ``port`` at each rate of ``baud_ladder``.

    Part of the listener vocabulary the console renders; ``FlashSession`` does
    not currently emit it.
    """

    port: str
    baud_ladder: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class HandshakeBaudTried:
    """One rung of the keyed unlock ladder was probed at ``baud``.

    ``succeeded`` says whether the loader answered at that rate. Part of the
    listener vocabulary the console renders; ``FlashSession`` does not
    currently emit it.
    """

    baud: int
    succeeded: bool


@dataclass(frozen=True, slots=True)
class HandshakeSucceeded:
    """The loader accepted the unlock at ``baud``.

    ``xor_key`` is the session cipher key framed traffic runs under: the key
    derived from the probe on the keyed path, or 0 on the cleartext path.
    """

    baud: int
    xor_key: int


@dataclass(frozen=True, slots=True)
class TargetIdentified:
    """The decoded 17-byte QUERY_TARGET reply, split into its evidenced roles.

    Mirrors :class:`~thd75_fw.flash.session.TargetInfo`: bytes 0..7 are the
    target compatibility mask, bytes 8..15 are opaque, byte 16 is the trailing
    status, and ``raw_payload`` keeps all 17 bytes.
    """

    target_mask_bytes: bytes
    opaque_bytes_8_15: bytes
    trailing_status: int
    raw_payload: bytes


@dataclass(frozen=True, slots=True)
class TransportBaudChanged:
    """One observed line-rate change, with the reason the session had.

    The host opens the port at one rate and may move to another before the
    unlock or after it, depending on the unlock path. Recording each actual
    transition means a later reader never has to infer the rate a run used
    from which code path it thinks was taken.
    """

    baud: int
    reason: str


@dataclass(frozen=True, slots=True)
class SegmentStarted:
    """The session is about to send SETUP for one segment of the plan.

    ``index`` is zero-based out of ``total_segments``; ``byte_count`` is the
    descriptor ``$DL`` and ``expected_erase_seconds`` its ``$ET``.
    """

    name: str
    index: int
    total_segments: int
    byte_count: int
    expected_erase_seconds: int
    #: Descriptor ``$EL``. The proven recovery path still sends
    #: BEGIN_TRANSFER when this is zero, matching the successful reference
    #: flasher's overlay sequence; zero only means the descriptor requests no
    #: erase span.
    erase_length: int = 0


@dataclass(frozen=True, slots=True)
class SegmentErased:
    """Erase telemetry for one BEGIN_TRANSFER.

    Whether the D75 loader emits BUSY during erase at all is unresolved, so
    ``busy_count == 0`` is a reportable result, not a gap in the data.
    ``busy_intervals`` is capped by the session (see
    ``_MAX_RECORDED_BUSY_INTERVALS``) so a chatty loader cannot grow this
    without bound; ``busy_count`` stays exact regardless.
    """

    name: str
    elapsed_seconds: float
    busy_count: int = 0
    first_busy_seconds: float | None = None
    busy_intervals: tuple[float, ...] = ()


@dataclass(frozen=True, slots=True)
class SegmentChunkSent:
    """One SEND_CHUNK data packet of ``bytes_in_chunk`` bytes at ``offset``.

    Emitted after the packet is written (and, in the acknowledged mode, after
    its ACK is read).
    """

    name: str
    offset: int
    bytes_in_chunk: int


@dataclass(frozen=True, slots=True)
class SegmentProgress:
    """Periodic data-phase throughput, emitted every N chunks.

    Exists so a slow run is diagnosable while it runs. The per-chunk event
    above is suppressed by the console listener because it would dominate a
    multi-MB segment; this one is rate-limited at the source.
    """

    name: str
    chunks_sent: int
    bytes_sent: int
    elapsed_seconds: float
    bytes_per_second: float


@dataclass(frozen=True, slots=True)
class SegmentVerified:
    """VERIFY_SEGMENT passed for one segment.

    ``status_code`` is the loader's one-byte result (0 means verified) and
    ``expected_checksum`` is the descriptor ``$CA`` the loader checked.
    """

    name: str
    expected_checksum: int
    status_code: int


@dataclass(frozen=True, slots=True)
class FlashCompleted:
    """COMPLETE_UPDATE was acknowledged; the whole plan has been flashed.

    ``bytes_written`` counts the ``$DL`` bytes of every written segment, and
    ``elapsed_seconds`` runs from just before the unlock to the COMPLETE_UPDATE
    acknowledgement.
    """

    bytes_written: int
    elapsed_seconds: float


ProgressEvent = (
    HandshakeStarted
    | HandshakeBaudTried
    | HandshakeSucceeded
    | TransportBaudChanged
    | TargetIdentified
    | SegmentStarted
    | SegmentErased
    | SegmentChunkSent
    | SegmentProgress
    | SegmentVerified
    | FlashCompleted
)


class ProgressListener(Protocol):
    """Subscriber interface for ProgressEvents."""

    def emit(self, event: ProgressEvent) -> None:
        """Receive one event, in the order the session produced it."""
        ...
