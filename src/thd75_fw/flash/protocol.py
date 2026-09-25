"""TH-D75 FLDM wire-protocol primitives — pure, sans-io.

Frame layout: ``SYNC SYNC HH LL.. VV PP.. CC``
(two 0xAB sync bytes, one header byte, four-byte little-endian
``body_length`` covering verb + payload, one verb byte, payload
bytes, one-byte additive checksum over everything except the sync
bytes). This layout was extracted from the official Kenwood TH-D75
firmware updater's framing function.

**Cipher applied to framed traffic** — a 4-step substitution +
permutation pass with a 256-byte S-box:

    1. idx  = (key + cleartext_byte) mod 256
    2. s    = M_H[idx]                            (S-box lookup)
    3. s'   = s XOR key
    4. wire = rotate_left(s', 3)                  (8-bit rotate)

The S-box and the rotate/XOR/lookup sequence were extracted from
the official D75 firmware updater (the same TX descrambler and the
inverse RX descrambler appear there as obfuscator-processed state-
machine helper methods). We verified scramble ∘ descramble is the
identity over all 65,536 (byte, key) pairs.

The radio's RX descrambler is the exact inverse:
``rotate_right_3 → XOR-key → find-in-M_H → subtract-key``.

When ``key == 0`` the cipher is bypassed (identity) so cleartext
mode (``FPROMOD`` unlock) still works without special-casing.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Final

from .commands import AckCode, NakSubcode, UnframedResponse

SYNC: Final[bytes] = b"\xab\xab"
HEADER_OUTGOING: Final[int] = 0x00

#: Bytes OpenWood reads through the framed response verb before it sizes the
#: tail: ``SYNC(2) + HH(1) + LL(4) + VV(1)``. Its receive path deliberately
#: obtains these as ``1 + 1 + 6`` byte reads, then requests ``body_length``
#: bytes (payload plus checksum).
_FRAME_HEADER_SIZE: Final[int] = 8

#: Size of the smallest legal frame:
#: ``SYNC(2) + HH(1) + LL(4) + VV(1) + CC(1)``.
_MIN_FRAME_SIZE: Final[int] = 9

#: Largest session cipher key. The key is a single byte, and 0 disables the
#: cipher.
_MAX_CIPHER_KEY: Final[int] = 0xFF

#: Largest value of the one-byte header (``HH``) and verb (``VV``) fields.
_MAX_BYTE_FIELD: Final[int] = 0xFF

#: Largest payload :class:`Frame` accepts. This is a design constraint of this
#: host, not a wire limit: the ``LL`` length field is four bytes wide.
_MAX_FRAME_PAYLOAD: Final[int] = 0xFFFF

#: Size of an unframed NAK: the ``0x15`` code byte followed by its subcode.
_NAK_RESPONSE_SIZE: Final[int] = 2

#: 256-byte substitution table extracted verbatim from the official
#: Kenwood TH-D75 firmware updater (the ``m_h`` field on its main
#: form class, used by both the host's TX scrambler and the inverse
#: RX descrambler). Verified to be a valid permutation — every value
#: 0..255 appears exactly once. The S-box is essential to the cipher
#: — substituting a different S-box, or removing it and falling back
#: to plain XOR, produces wire bytes the D75 loader silently
#: discards (the wire bytes are not interpretable as a valid frame
#: after the radio's inverse descrambler runs on them).
M_H: Final[bytes] = bytes(
    (
        91,
        205,
        239,
        65,
        79,
        125,
        0,
        153,
        94,
        200,
        73,
        168,
        111,
        32,
        180,
        124,
        162,
        90,
        61,
        84,
        225,
        242,
        178,
        85,
        75,
        174,
        196,
        86,
        12,
        247,
        106,
        167,
        119,
        186,
        76,
        135,
        40,
        155,
        62,
        78,
        141,
        142,
        234,
        210,
        122,
        54,
        254,
        255,
        27,
        154,
        123,
        46,
        159,
        224,
        152,
        184,
        207,
        189,
        29,
        134,
        105,
        8,
        6,
        104,
        143,
        7,
        220,
        34,
        194,
        116,
        137,
        88,
        107,
        53,
        56,
        31,
        110,
        49,
        74,
        126,
        36,
        92,
        95,
        108,
        171,
        246,
        16,
        191,
        241,
        230,
        193,
        19,
        151,
        41,
        169,
        26,
        1,
        136,
        98,
        201,
        11,
        113,
        64,
        13,
        109,
        204,
        131,
        10,
        181,
        145,
        23,
        235,
        63,
        158,
        93,
        203,
        100,
        237,
        182,
        77,
        229,
        218,
        50,
        156,
        52,
        199,
        44,
        89,
        121,
        198,
        231,
        192,
        71,
        24,
        172,
        28,
        232,
        138,
        21,
        183,
        243,
        188,
        33,
        197,
        2,
        217,
        221,
        195,
        140,
        9,
        69,
        213,
        47,
        120,
        4,
        202,
        82,
        42,
        38,
        17,
        139,
        248,
        177,
        25,
        97,
        215,
        118,
        87,
        81,
        251,
        219,
        66,
        253,
        130,
        228,
        176,
        250,
        20,
        170,
        101,
        128,
        185,
        223,
        148,
        72,
        102,
        48,
        211,
        240,
        226,
        30,
        187,
        114,
        166,
        165,
        103,
        144,
        83,
        80,
        238,
        132,
        129,
        190,
        59,
        244,
        208,
        149,
        15,
        99,
        55,
        18,
        236,
        245,
        112,
        216,
        212,
        14,
        127,
        209,
        45,
        179,
        133,
        3,
        57,
        115,
        233,
        22,
        70,
        146,
        175,
        37,
        147,
        35,
        68,
        252,
        164,
        249,
        173,
        150,
        206,
        43,
        96,
        157,
        117,
        222,
        60,
        160,
        58,
        67,
        163,
        51,
        227,
        5,
        214,
        161,
        39,
    )
)

#: Inverse of ``M_H``: ``M_H_INV[M_H[i]] == i`` for all i in 0..255.
#: Used by the RX descrambler to find the pre-image of a received byte.
M_H_INV: Final[bytes] = bytes(M_H.index(i) for i in range(256))


#: Longest span whose exact byte sum can be read back out of a single
#: Adler-32. The low half of an Adler-32 is ``(1 + sum(span)) mod 65521``,
#: and 256 bytes of ``0xFF`` sum to 65280, so ``1 + sum`` cannot reach the
#: modulus and the sum survives unreduced. 257 bytes can exceed it, so this
#: is the ceiling, not a tuning knob. It also divides every data unit the
#: loader accepts, so a SEND_CHUNK payload splits evenly.
_ADLER_EXACT_SPAN: Final[int] = 256


def sum8(data: bytes) -> int:
    """Frame checksum: 8-bit unsigned sum of every byte.

    Byte-identical to ``sum(data) & 0xFF``, computed through
    :func:`zlib.adler32` because that runs the per-byte work in C. Spans
    of at most :data:`_ADLER_EXACT_SPAN` bytes come back exactly as
    ``(adler32(span) & 0xFFFF) - 1``; longer buffers are summed span by
    span and the partial sums added as ordinary unbounded integers, so
    nothing is truncated until the final mask. Integer addition is
    associative and ``&`` distributes over it, which is what makes the
    split safe.

    This is the flasher's hottest pure-CPU function: the data phase
    checksums the whole of every frame it builds, roughly a kilobyte at
    a time, tens of thousands of times per image.
    """
    if len(data) <= _ADLER_EXACT_SPAN:
        return ((zlib.adler32(data) & 0xFFFF) - 1) & 0xFF
    total = 0
    for start in range(0, len(data), _ADLER_EXACT_SPAN):
        span = data[start : start + _ADLER_EXACT_SPAN]
        total += (zlib.adler32(span) & 0xFFFF) - 1
    return total & 0xFF


def scramble(data: bytes, key: int) -> bytes:
    """Encrypt cleartext frame bytes for transmission to the radio.

    Applies the D75 4-step cipher (add-key → S-box → XOR-key →
    rotate-left-3) to every byte. ``key == 0`` is identity (used
    before unlock and for cleartext-mode unlock).
    """
    if not 0 <= key <= _MAX_CIPHER_KEY:
        msg = f"key must be 0..255, got {key}"
        raise ValueError(msg)
    if key == 0:
        return data
    return bytes(
        (((M_H[(key + b) & 0xFF] ^ key) << 3) | ((M_H[(key + b) & 0xFF] ^ key) >> 5))
        & 0xFF
        for b in data
    )


def descramble(data: bytes, key: int) -> bytes:
    """Decrypt wire bytes received from the radio back to cleartext.

    Exact inverse of :func:`scramble` (rotate-right-3 → XOR-key →
    M_H_INV lookup → subtract-key). ``key == 0`` is identity.
    """
    if not 0 <= key <= _MAX_CIPHER_KEY:
        msg = f"key must be 0..255, got {key}"
        raise ValueError(msg)
    if key == 0:
        return data
    return bytes(
        (M_H_INV[((b >> 3) | (b << 5)) & 0xFF ^ key] - key) & 0xFF for b in data
    )


# Backward-compatible alias for callers that imported the old name.
# Removed once all in-tree call sites migrate to scramble/descramble.
def xor_with_key(data: bytes, key: int) -> bytes:
    """Apply :func:`scramble`; deprecated in favour of it and :func:`descramble`.

    The name is a misnomer — the actual D75 cipher is more than just XOR. Kept
    as an identity-at-key-0 shim while call sites migrate.
    """
    return scramble(data, key)


@dataclass(frozen=True, slots=True)
class Frame:
    """Decoded (cleartext) representation of a single FLDM frame.

    Serialization through ``build_frame`` handles the XOR pass. Validating
    byte ranges at construction prevents a caller accidentally encoding
    an out-of-range verb or header.
    """

    header: int
    verb: int
    payload: bytes

    def __post_init__(self) -> None:
        """Reject a header, verb or payload that cannot be encoded.

        Raises:
            ValueError: If ``header`` or ``verb`` is outside 0..255, or the
                payload exceeds 65535 bytes.

        """
        if not 0 <= self.header <= _MAX_BYTE_FIELD:
            msg = f"header must be 0..255, got {self.header}"
            raise ValueError(msg)
        if not 0 <= self.verb <= _MAX_BYTE_FIELD:
            msg = f"verb must be 0..255, got {self.verb}"
            raise ValueError(msg)
        if len(self.payload) > _MAX_FRAME_PAYLOAD:
            msg = (
                f"payload too large: {len(self.payload)} bytes "
                "(max 65535 per design constraint)"
            )
            raise ValueError(msg)

    @property
    def body_length(self) -> int:
        """Value of the on-wire LL..LL field (1 byte verb + payload bytes)."""
        return 1 + len(self.payload)


class FrameError(ValueError):
    """Frame failed structural validation (sync, length, checksum)."""


def build_frame(frame: Frame, *, xor_key: int = 0) -> bytes:
    """Serialize a cleartext Frame to on-wire bytes.

    Applies the D75 4-step cipher (see :func:`scramble`) when
    ``xor_key != 0``. The parameter retains the historic name for
    backwards compatibility with existing call sites; despite the
    name the actual encoding is the full cipher, not just XOR.
    """
    # ``<BIB`` is the checksummed prefix ``HH LL.. VV`` exactly: one header
    # byte, the four-byte little-endian body_length, one verb byte, and the
    # leading ``<`` suppresses any alignment padding between them.
    body_head = struct.pack("<BIB", frame.header, frame.body_length, frame.verb)
    payload = frame.payload
    # Checksum the payload where it already lives instead of copying it into
    # a concatenated ``checked_body`` first. ``sum8`` truncates to 8 bits and
    # the final mask truncates again, which changes nothing: masking
    # distributes over addition, so this is the same byte the whole-body sum
    # produced. That saves a kilobyte-scale copy on every frame.
    cksum = (sum(body_head) + sum8(payload)) & 0xFF
    # One join, so the wire buffer is allocated once and each piece is copied
    # into it once, rather than growing a new bytes object per concatenation.
    cleartext = b"".join((SYNC, body_head, payload, bytes((cksum,))))
    return scramble(cleartext, xor_key)


def parse_frame(raw: bytes, *, xor_key: int = 0) -> tuple[Frame, bytes]:
    """Parse exactly one frame from the front of raw.

    Returns the decoded Frame and any trailing bytes after the frame.
    Raises ``FrameError`` on any structural problem (short, missing
    sync, truncated body, checksum mismatch). Applies the D75
    descramble pass (see :func:`descramble`) when ``xor_key != 0``.
    """
    cleartext = descramble(raw, xor_key)
    # Min frame: SYNC(2) + HH(1) + LL(4) + VV(1) + CC(1) = 9 bytes.
    if len(cleartext) < _MIN_FRAME_SIZE:
        msg = f"frame too short: {len(cleartext)} bytes (need >= {_MIN_FRAME_SIZE})"
        raise FrameError(msg)
    if cleartext[:2] != SYNC:
        msg = f"missing sync, got bytes {cleartext[:2].hex()}"
        raise FrameError(msg)
    body_length = int.from_bytes(cleartext[3:7], "little")
    if body_length < 1:
        msg = f"body length must be >= 1, got {body_length}"
        raise FrameError(msg)
    total_size = 2 + 1 + 4 + body_length + 1
    if len(cleartext) < total_size:
        msg = f"truncated: have {len(cleartext)} bytes, need {total_size}"
        raise FrameError(msg)
    checked_body = cleartext[2 : 7 + body_length]
    actual_cksum = cleartext[7 + body_length]
    expected_cksum = sum8(checked_body)
    if actual_cksum != expected_cksum:
        msg = (
            f"checksum mismatch: got 0x{actual_cksum:02X}, "
            f"expected 0x{expected_cksum:02X}"
        )
        raise FrameError(msg)
    verb = cleartext[7]
    payload = cleartext[8 : 7 + body_length]
    header = cleartext[2]
    return Frame(header=header, verb=verb, payload=payload), cleartext[total_size:]


class ResponseReader:
    """Stream-oriented response parser.

    Serial reads return arbitrary byte chunks; the loader emits a mix of
    unframed responses (06/11/15 xx, never XOR'd) and framed responses
    (SYNC...payload..CKS, XOR-encrypted under the active key). Feed bytes
    in any chunking; receive complete responses as they become available.
    """

    def __init__(self, xor_key: int = 0) -> None:
        """Start an empty reader that decodes under ``xor_key``.

        Args:
            xor_key: The session cipher key; 0 reads cleartext.

        Raises:
            ValueError: If ``xor_key`` is outside 0..255.

        """
        super().__init__()
        if not 0 <= xor_key <= _MAX_CIPHER_KEY:
            msg = f"xor_key must be 0..255, got {xor_key}"
            raise ValueError(msg)
        self._xor_key = xor_key
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame | UnframedResponse]:
        """Buffer ``data`` and return every response it completes, in order.

        Incomplete trailing bytes stay buffered for the next call.

        Raises:
            FrameError: If the buffered bytes cannot be a valid response (a
                bad sync, checksum or length, or an unknown NAK subcode).

        """
        self._buf.extend(data)
        out: list[Frame | UnframedResponse] = []
        while True:
            consumed, response = self._try_decode_one()
            if response is None:
                break
            del self._buf[:consumed]
            out.append(response)
        return out

    def has_partial(self) -> bool:
        """Return whether bytes of an incomplete response are still buffered."""
        return len(self._buf) > 0

    def bytes_needed(self) -> int:
        """Byte count for the next OpenWood-compatible staged read.

        Callers read replies off a serial port, and ``pyserial``'s ``read(n)``
        returns early only once *n* bytes have arrived; anything short of that
        costs the port's whole timeout. Each returned count is exact for the
        current parsing stage, so a prompt reply still returns promptly.

        The boundaries intentionally mirror OpenWood's ``recv_frame`` and
        ``_recv_exact`` calls rather than coalescing adjacent reads. That
        distinction is observable at 576000 baud on macOS: OpenWood reassigns
        pyserial's timeout before each read, and every assignment re-applies
        the custom baud through ``IOSSIOSPEED``.

        * empty buffer: one byte, which distinguishes an unframed
          ACK/BUSY/NAK from the ``SYNC`` that opens a framed reply;
        * a NAK opener: one more byte for its subcode;
        * the first framed sync byte: one byte for the second sync byte;
        * both sync bytes: six bytes for ``HH + LL + VV``;
        * the complete eight-byte header: ``body_length`` bytes for payload
          plus checksum.

        Returns ``0`` when the buffered bytes already form a complete
        response. ``feed`` drains every complete response before returning, so
        in normal flow that only happens if a caller inspects the reader
        mid-decode. The count is otherwise unbounded on purpose: a desynced
        stream can yield an absurd ``body_length``, and clamping the resulting
        read request is the transport caller's job (see
        ``session._MAX_RESPONSE_READ_BYTES``).
        """
        if not self._buf:
            return 1
        first = descramble(bytes(self._buf[:1]), self._xor_key)[0]
        if first in (AckCode.ACK.value, AckCode.BUSY.value):
            return 0
        if first == AckCode.NAK.value:
            return max(0, _NAK_RESPONSE_SIZE - len(self._buf))
        if len(self._buf) < len(SYNC):
            return len(SYNC) - len(self._buf)
        if len(self._buf) < _FRAME_HEADER_SIZE:
            return _FRAME_HEADER_SIZE - len(self._buf)
        cleartext_header = descramble(
            bytes(self._buf[:_FRAME_HEADER_SIZE]),
            self._xor_key,
        )
        body_length = int.from_bytes(cleartext_header[3:7], "little")
        total = _FRAME_HEADER_SIZE + body_length
        return max(0, total - len(self._buf))

    def _try_decode_one(self) -> tuple[int, Frame | UnframedResponse | None]:
        if not self._buf:
            return (0, None)
        # Every byte the radio sends post-unlock is run through the
        # D75 cipher (see module docstring). Descramble before any
        # framing/markers are interpreted; otherwise wire 0x9E (which
        # is what ACK 0x06 looks like after scrambling at key 0x59)
        # would be misclassified as a framed-frame start or noise.
        first = descramble(bytes(self._buf[:1]), self._xor_key)[0]
        # Unframed: ACK (1 byte), BUSY (1 byte), NAK (2 bytes — verb + subcode)
        if first == AckCode.ACK.value:
            return (1, UnframedResponse(AckCode.ACK))
        if first == AckCode.BUSY.value:
            return (1, UnframedResponse(AckCode.BUSY))
        if first == AckCode.NAK.value:
            return self._try_decode_nak()
        return self._try_decode_framed()

    def _try_decode_nak(self) -> tuple[int, UnframedResponse | None]:
        """Decode a buffered two-byte NAK, or wait for its subcode byte."""
        if len(self._buf) < _NAK_RESPONSE_SIZE:
            return (0, None)  # waiting for subcode
        second = descramble(bytes(self._buf[:_NAK_RESPONSE_SIZE]), self._xor_key)[1]
        try:
            sub = NakSubcode(second)
        except ValueError as exc:
            msg = f"unknown NAK subcode 0x{second:02X}"
            raise FrameError(msg) from exc
        return (_NAK_RESPONSE_SIZE, UnframedResponse(AckCode.NAK, sub))

    def _try_decode_framed(self) -> tuple[int, Frame | None]:
        """Decode one buffered framed reply, or wait for the rest of it."""
        # Framed: try to decode under the active XOR key.
        if len(self._buf) < _MIN_FRAME_SIZE:
            return (0, None)
        try:
            frame, _ = parse_frame(bytes(self._buf), xor_key=self._xor_key)
        except FrameError as exc:
            # Truncation is "wait for more bytes", not a hard error.
            if "truncated" in str(exc) or "too short" in str(exc):
                return (0, None)
            raise
        # Compute frame size to consume.
        cleartext_header = descramble(
            bytes(self._buf[:_FRAME_HEADER_SIZE]),
            self._xor_key,
        )
        body_length = int.from_bytes(cleartext_header[3:7], "little")
        total = _FRAME_HEADER_SIZE + body_length
        return (total, frame)
