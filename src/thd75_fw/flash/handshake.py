"""TH-D75 FLDM encrypted-unlock handshake and baud-rate negotiation.

The D75 loader supports two unlock paths: a cleartext ``"FPROMOD"``
token (no XOR) and an encrypted 11-byte token of the shape
``"..Thd75tw.."`` (with a per-session XOR key derived from the
PC clock). The official Kenwood TH-D75 firmware updater uses only
the encrypted path; this module mirrors that choice. The D75 XOR-
key derivation formula sums the model-name constant ``"TH-D75  "``
(byte sum ``0xB9``) into the key — see :func:`derive_xor_key`.

Two distinct things were historically conflated under the name
``EXPECTED_REPLY``:

* The **wire reply** the loader actually sends back after accepting
  unlock — two raw bytes ``0x16 0x06``. Now :data:`UNLOCK_REPLY`.
  Verified on real D75 V1.03 hardware: these arrive in this order,
  not XOR-scrambled, after a successful keyed unlock.
* The **XOR-key derivation string** ``"TH-D75  "`` whose byte sum
  (``0xB9``) is the XOR constant in the key formula. Never appears
  on the serial port; only its sum matters. Now :data:`_DERIVATION_STRING`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol

MAGIC: Final[bytes] = b"Thd75tw"

#: Length of the probe's leading prefix field, which precedes :data:`MAGIC` in
#: the 11-byte ``[prefix:2][b"Thd75tw":7][minute:1][second:1]`` layout.
_PROBE_PREFIX_LENGTH: Final[int] = 2

#: The CLEARTEXT unlock magic. The FLDM loader supports two unlock
#: paths: cleartext (this constant — 7 bytes ``"FPROMOD"``) and
#: encrypted (the 11-byte ``MAGIC`` above with two timestamp bytes
#: appended). After cleartext unlock, the framed protocol runs with
#: XOR key 0 (no encryption) — which sidesteps the entire D75 4-step
#: cipher complexity. The local D75 V1.03 hardware run verified this
#: path at 576000 baud. OpenWood independently documents it on D74;
#: that project is not evidence for other D75 baud rates.
CLEARTEXT_MAGIC: Final[bytes] = b"FPROMOD"

#: The XOR-key derivation string. Its byte sum (``0xB9``) is the XOR
#: constant in the key formula — see :func:`derive_xor_key`. NOT a
#: wire reply; the loader never sends these bytes back. The constant
#: itself is the model-name string the official Kenwood TH-D75
#: firmware updater sums when computing the per-session XOR key.
_DERIVATION_STRING: Final[bytes] = b"TH-D75  "

#: The bytes the FLDM loader actually sends on the wire after
#: accepting an unlock probe:
#:
#: * ``0x16`` — unlock ACK (loader accepted the unlock token)
#: * ``0x06`` — mode-change OK (loader entered programming mode,
#:   ready for framed FLDM commands)
#:
#: Both are **raw bytes** — they are not XOR-scrambled, even after
#: the keyed-unlock path. Verified on real D75 V1.03 hardware. The
#: two bytes may arrive separately; :func:`perform_handshake`
#: accumulates until both are received or the per-baud timeout fires.
UNLOCK_REPLY: Final[bytes] = b"\x16\x06"

#: Baud rates to try in order during the unlock probe. The order
#: matches the official Kenwood TH-D75 firmware updater's primary
#: ladder (verified in ``f.cs`` lines 602-627: state transitions
#: ``.c → .d → .g → .h → .b`` map to 19200 → 4800 → 38400 → 57600
#: → 9600). Real D75 V1.03 hardware in FPM responds at 19200 — the
#: first ladder entry — so subsequent rates are exercised only when
#: the radio is in an unusual state. The vendor additionally has
#: fallback paths for 2400 and 1200 baud (states ``.e`` and ``.f``)
#: that fire only after the primary ladder is exhausted; we omit
#: those because they are vanishingly rare in practice and slow
#: down the per-baud retry loop. Operators can override via the
#: ``--baud-ladder`` CLI flag if needed.
BAUD_LADDER: Final[tuple[int, ...]] = (19200, 4800, 38400, 57600, 9600)


@dataclass(frozen=True, slots=True)
class Probe:
    """The 11-byte encrypted-unlock probe.

    Layout: ``[prefix:2][b"Thd75tw":7][minute:1][second:1]``
    """

    prefix: bytes
    minute: int
    second: int

    def to_wire(self) -> bytes:
        """Serialize the probe as the 11 bytes the loader expects.

        Returns:
            ``prefix + MAGIC + bytes([minute, second])``.

        Raises:
            ValueError: If ``prefix`` is not exactly two bytes.

        """
        if len(self.prefix) != _PROBE_PREFIX_LENGTH:
            msg = f"prefix must be 2 bytes, got {len(self.prefix)}"
            raise ValueError(msg)
        return self.prefix + MAGIC + bytes([self.minute, self.second])


def build_probe(now: datetime, prefix: bytes = b"\x00\x00") -> Probe:
    """Construct a Probe using the PC clock for the timestamp bytes."""
    return Probe(prefix=prefix, minute=now.minute, second=now.second)


#: Fallback XOR key when the derivation yields 0 (TH-D75_V103_e.exe
#: f.cs case 6: ``this.m_m = 117``). The D74 analogue is 0x74.
_XOR_KEY_FALLBACK: Final[int] = 0x75


def derive_xor_key(probe: Probe, derivation: bytes = _DERIVATION_STRING) -> int:
    """Derive the framed-protocol XOR key from the probe timestamp.

    Fully reverse-engineered from TH-D75_V103_e.exe ``f.cs::l()``
    (lines 2062-2219; probe construction at 2130-2139 and key derivation at
    2164-2184)::

        b2 = sum(bytes of "TH-D75  ") & 0xFF                      # case 8
        b3 = (minute + second) of the probe                       # case 0
        b3 = (-b3) & 0xFF                                         # case 1
        m_m = (b3 ^ b2) & 0xFF                                    # case 1
        if m_m == 0: m_m = 0x75                                   # case 6

    ``b2`` is the additive byte-sum of the **derivation string** —
    a CONSTANT in the formula (0xB9 for D75's "TH-D75  "). The
    loader's actual on-wire reply is :data:`UNLOCK_REPLY` (two
    raw bytes ``0x16 0x06``), unrelated to ``b2``. The previous
    version of this function passed the on-wire reply here, which
    only worked because both happened to share the same identifier
    (``EXPECTED_REPLY``); the two are now properly separated.

    ``b3`` derives from the two timestamp bytes the PC put in the
    probe (negated in two's complement). The model-name string only
    enters the formula via its byte-sum, so the same formula
    structure could be retargeted to a different radio model by
    changing :data:`_DERIVATION_STRING` (and the fallback constant,
    which the official updater hardcodes per-model).

    Args:
        probe: The probe sent to the loader (supplies minute + second).
        derivation: The model-specific derivation string. Defaults to
            :data:`_DERIVATION_STRING` (D75's "TH-D75  "). Pass an
            alternative only when verifying the formula structure
            against another model (e.g. D74's "TH-D74  ").

    Returns:
        The 0..255 XOR key for all subsequent framed traffic.

    """
    b2 = sum(derivation) & 0xFF
    b3 = (-(probe.minute + probe.second)) & 0xFF
    key = (b3 ^ b2) & 0xFF
    return _XOR_KEY_FALLBACK if key == 0 else key


@dataclass(frozen=True, slots=True)
class HandshakeResult:
    """What survives the handshake into the framed-protocol session."""

    baud: int
    probe: Probe
    reply: bytes
    xor_key: int


class HandshakeError(RuntimeError):
    """The loader did not answer at any baud, or answered with garbage."""


class AmbiguousUnlockError(HandshakeError):
    """An unlock write may have changed loader state before transport failure.

    Once any part of an unlock token may have reached the radio, the host must
    not guess whether the loader consumed it.  The only safe recovery is to
    close/disconnect the transport and fully power-cycle the radio before a
    new FLDM session.
    """

    def __init__(self, *, stage: str, baud: int, cause: str) -> None:
        """Record where the unlock became ambiguous and why.

        Args:
            stage: The unlock step that failed (for example
                ``"keyed unlock write"``).
            baud: The line rate the step ran at.
            cause: What the transport reported.

        """
        self.stage = stage
        self.baud = baud
        self.cause = cause
        super().__init__(
            f"{stage} at baud {baud}: {cause}; unlock state is ambiguous. "
            "MANDATORY: disconnect USB and fully power-cycle the radio before "
            "any new FLDM session."
        )


class _HandshakeTransport(Protocol):
    """Duck-typed minimal SerialIO contract used by perform_handshake.

    ``read`` waits for the requested count and returns short only when its own
    timeout expires, so both unlock paths below request exactly the unread
    remainder of :data:`UNLOCK_REPLY` rather than a fixed ceiling.
    """

    def write(self, data: bytes) -> int: ...
    def read(self, max_bytes: int) -> bytes: ...
    def set_baud(self, baud: int) -> None: ...
    def discard_input(self) -> None: ...


def _collect_unlock_reply(transport: _HandshakeTransport, deadline: float) -> bytes:
    """Accumulate :data:`UNLOCK_REPLY`-sized input until it is complete or late.

    Each read asks for exactly the unread remainder of the two-byte reply.
    Until the reply is complete, every read is followed by a 5 ms pause, and
    no new read starts once ``deadline`` (a ``time.monotonic()`` value) has
    passed. Both unlock paths call this with the unlock token already written,
    so the caller decides what a transport failure here means.

    Args:
        transport: The port the unlock token was written to.
        deadline: Monotonic time after which no further read is started.

    Returns:
        The bytes received, which may be short or wrong; the caller compares
        them with :data:`UNLOCK_REPLY`.

    """
    reply = b""
    while time.monotonic() < deadline:
        chunk = transport.read(len(UNLOCK_REPLY) - len(reply))
        if chunk:
            reply += chunk
            if len(reply) >= len(UNLOCK_REPLY):
                break
        time.sleep(0.005)
    return reply


def perform_cleartext_unlock(
    transport: _HandshakeTransport,
    *,
    baud: int,
    timeout: float = 2.0,
) -> HandshakeResult:
    """Send the cleartext ``FPROMOD`` unlock and wait for the loader.

    No XOR key, no probe ladder, no per-baud retries. The local D75
    V1.03 hardware run proves this path at 576000 baud. OpenWood's
    `fldm.py` proves the related D74 behavior only; the other D75
    metadata `#BR` rates have not been exercised locally. The caller
    is responsible for opening the transport at the selected baud.

    Returns a HandshakeResult with ``xor_key = 0`` so framed traffic
    runs in plaintext — this is what makes the cleartext path so much
    simpler than the encrypted one (no D75 4-step cipher needed for
    SETUP_SEGMENT, SEND_CHUNK, etc.).
    """
    try:
        transport.discard_input()
    except BaseException as exc:
        msg = (
            "cleartext pre-unlock discard_input failed before FPROMOD was sent: "
            f"{type(exc).__name__}: {exc}"
        )
        raise HandshakeError(msg) from exc
    try:
        written = transport.write(CLEARTEXT_MAGIC)
    except BaseException as exc:
        raise AmbiguousUnlockError(
            stage="cleartext unlock write",
            baud=baud,
            cause=(
                f"transport raised {type(exc).__name__}: {exc}; some or all "
                "FPROMOD bytes may have reached the loader"
            ),
        ) from exc
    if written != len(CLEARTEXT_MAGIC):
        raise AmbiguousUnlockError(
            stage="cleartext unlock write",
            baud=baud,
            cause=(
                f"short transport write reported {written} of "
                f"{len(CLEARTEXT_MAGIC)} FPROMOD bytes"
            ),
        )
    deadline = time.monotonic() + timeout
    try:
        reply = _collect_unlock_reply(transport, deadline)
    except BaseException as exc:
        raise AmbiguousUnlockError(
            stage="cleartext unlock reply read",
            baud=baud,
            cause=(
                f"transport/reply wait raised {type(exc).__name__}: {exc} "
                "after the complete FPROMOD token was written"
            ),
        ) from exc
    if reply != UNLOCK_REPLY:
        msg = (
            f"cleartext unlock at baud {baud}: expected "
            f"{UNLOCK_REPLY!r}, got {reply!r} (timeout={timeout}s)"
        )
        raise HandshakeError(msg)
    # cleartext path: no probe, no XOR key — use a synthetic Probe
    # with zero timestamps so the HandshakeResult shape stays
    # consistent with the encrypted path.
    return HandshakeResult(
        baud=baud,
        probe=Probe(prefix=b"\x00\x00", minute=0, second=0),
        reply=reply,
        xor_key=0,
    )


def _set_keyed_probe_baud(
    transport: _HandshakeTransport,
    baud: int,
    *,
    unlock_write_completed: bool,
) -> None:
    """Move the port to the next ladder rate, classifying any failure.

    Raises:
        AmbiguousUnlockError: If ``set_baud`` fails after an earlier rung
            already wrote a complete probe that drew no conclusive reply.
        HandshakeError: If ``set_baud`` fails before any probe was written.

    """
    try:
        transport.set_baud(baud)
    except BaseException as exc:
        detail = f"transport set_baud raised {type(exc).__name__}: {exc}"
        if unlock_write_completed:
            raise AmbiguousUnlockError(
                stage="keyed unlock baud change",
                baud=baud,
                cause=(
                    f"{detail} after an earlier complete unlock probe was "
                    "written without a conclusive reply"
                ),
            ) from exc
        msg = (
            f"keyed pre-unlock set_baud({baud}) failed before any probe "
            f"was sent: {type(exc).__name__}: {exc}"
        )
        raise HandshakeError(msg) from exc


def _discard_keyed_probe_input(
    transport: _HandshakeTransport,
    baud: int,
    *,
    unlock_write_completed: bool,
) -> None:
    """Drop stale input before a probe, classifying any failure.

    Raises:
        AmbiguousUnlockError: If ``discard_input`` fails after an earlier rung
            already wrote a complete probe that drew no conclusive reply.
        HandshakeError: If ``discard_input`` fails before any probe was
            written.

    """
    try:
        transport.discard_input()
    except BaseException as exc:
        detail = f"transport discard_input raised {type(exc).__name__}: {exc}"
        if unlock_write_completed:
            raise AmbiguousUnlockError(
                stage="keyed unlock input discard",
                baud=baud,
                cause=(
                    f"{detail} after an earlier complete unlock probe was "
                    "written without a conclusive reply"
                ),
            ) from exc
        msg = (
            f"keyed pre-unlock discard_input at baud {baud} failed before "
            f"any probe was sent: {type(exc).__name__}: {exc}"
        )
        raise HandshakeError(msg) from exc


def _write_keyed_probe(transport: _HandshakeTransport, wire: bytes, baud: int) -> None:
    """Write the complete encrypted unlock probe or declare the state ambiguous.

    Raises:
        AmbiguousUnlockError: If the write raises or reports fewer bytes than
            the probe holds, since part of the probe may have reached the
            loader either way.

    """
    try:
        written = transport.write(wire)
    except BaseException as exc:
        raise AmbiguousUnlockError(
            stage="keyed unlock write",
            baud=baud,
            cause=(
                f"transport raised {type(exc).__name__}: {exc}; some or "
                "all encrypted unlock bytes may have reached the loader"
            ),
        ) from exc
    if written != len(wire):
        raise AmbiguousUnlockError(
            stage="keyed unlock write",
            baud=baud,
            cause=(
                f"short transport write reported {written} of "
                f"{len(wire)} encrypted unlock bytes"
            ),
        )


def perform_handshake(
    transport: _HandshakeTransport,
    *,
    baud_ladder: tuple[int, ...] = BAUD_LADDER,
    per_baud_timeout: float = 2.0,
) -> HandshakeResult:
    """Walk the baud ladder; return HandshakeResult on first success.

    Sends the encrypted-unlock probe at each baud in turn and waits
    for the loader's two-byte raw reply :data:`UNLOCK_REPLY`
    (``0x16 0x06``). On the first success it derives the framed-
    protocol XOR key (see :func:`derive_xor_key`) and returns.
    Raises :class:`HandshakeError` if no baud answers.

    The default ``per_baud_timeout`` is 2 seconds — long enough to
    accommodate the loader sending the two raw bytes separately
    with brief gaps. (Earlier versions used a 1-second timeout and
    occasionally truncated the second byte under host-side scheduling
    jitter; 2 seconds is comfortably above any inter-byte gap we've
    observed on real D75 V1.03 hardware.)
    """
    # Local wall-clock time, as the official updater's ``DateTime.Now``
    # supplies it; ``astimezone()`` only attaches the local zone and leaves the
    # minute and second the probe carries unchanged.
    probe = build_probe(datetime.now().astimezone())
    wire = probe.to_wire()
    unlock_write_completed = False
    for baud in baud_ladder:
        _set_keyed_probe_baud(
            transport,
            baud,
            unlock_write_completed=unlock_write_completed,
        )
        _discard_keyed_probe_input(
            transport,
            baud,
            unlock_write_completed=unlock_write_completed,
        )
        _write_keyed_probe(transport, wire, baud)
        unlock_write_completed = True
        deadline = time.monotonic() + per_baud_timeout
        try:
            reply = _collect_unlock_reply(transport, deadline)
        except BaseException as exc:
            raise AmbiguousUnlockError(
                stage="keyed unlock reply read",
                baud=baud,
                cause=(
                    f"transport/reply wait raised {type(exc).__name__}: {exc} "
                    "after the complete encrypted unlock probe was written"
                ),
            ) from exc
        if reply == UNLOCK_REPLY:
            return HandshakeResult(
                baud=baud,
                probe=probe,
                reply=reply,
                xor_key=derive_xor_key(probe),
            )
    msg = (
        f"no reply at any baud (tried {baud_ladder!r}, "
        f"per-baud timeout {per_baud_timeout}s)"
    )
    raise HandshakeError(msg)
