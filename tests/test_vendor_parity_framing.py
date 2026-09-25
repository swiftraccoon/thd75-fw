r"""Vendor parity tests — framing layer.

Frame magic bytes, length field width/endianness, checksum algorithm,
ACK/NAK byte values. Each test cites the vendor source location (o.cs
case numbers / line ranges from the obfuscator state machine).

Frame layout (from o.cs analysis):

    Offset:  0    1    2    3    4    5    6    7    8         8+N
             AB   AB   00   L0   L1   L2   L3   VV   D0..DN-1  CK
             |    |    |    \\-------v-------/   |    \\---v---/  |
           magic magic 00    length:u32 LE     verb  payload   checksum

Where:
- ``length:u32 LE`` = ``payload_len + 1`` (verb counts toward length)
- Total frame size = 9 + payload_len
- Checksum = sum8(00, L0, L1, L2, L3, VV, D0..DN-1) — the two AB magic
  bytes are EXCLUDED from the checksum (vendor o.cs case 12 only adds
  array[num4] (the 0x00) to b2, not the two ABs).
"""

from __future__ import annotations

import pytest

from thd75_fw.flash.commands import Verb
from thd75_fw.flash.protocol import (
    HEADER_OUTGOING,
    SYNC,
    Frame,
    FrameError,
    build_frame,
    parse_frame,
    sum8,
)

# --- magic / header constants -------------------------------------------


def test_sync_magic_is_two_0xab_bytes() -> None:
    """vendor: o.cs:9 (`const byte b = 171`), o.cs:172-175 (case 12).

    Case 12 writes `array[num4] = 171` twice consecutively.
    """
    assert SYNC == b"\xab\xab"
    assert len(SYNC) == 2


def test_header_outgoing_is_0x00() -> None:
    """vendor: o.cs:11 (`const byte c = 0`), o.cs:176 (case 12).

    Case 12 writes `array[num4] = 0` as the third header byte.
    """
    assert HEADER_OUTGOING == 0x00


def test_frame_total_overhead_is_9_bytes() -> None:
    """vendor: o.cs:7 (`const int m_a = 9`), o.cs:221 (`new byte[A_1.Length + 9]`).

    Total frame overhead (everything except the payload bytes) = 9:
    2 magic + 1 header + 4 length + 1 verb + 1 checksum.
    """
    empty_frame = Frame(
        header=HEADER_OUTGOING, verb=Verb.ENTER_PROGRAM.value, payload=b""
    )
    wire = build_frame(empty_frame, xor_key=0)
    assert len(wire) == 9


# --- length-field semantics ---------------------------------------------


def test_body_length_includes_verb_byte() -> None:
    """vendor: o.cs:185 (`num3 = (uint)(A_1.Length + 1)`), o.cs:233 (`num3 = 1u`).

    o.cs:233 applies when payload is null.

    The `length:u32 LE` field counts (verb + payload), NOT just payload.
    With empty payload, length = 1 (just the verb byte).
    """
    f_empty = Frame(header=HEADER_OUTGOING, verb=0x30, payload=b"")
    assert f_empty.body_length == 1

    f_with_payload = Frame(header=HEADER_OUTGOING, verb=0x33, payload=b"\x12\x01")
    assert f_with_payload.body_length == 3  # 1 verb + 2 payload bytes


def test_length_field_is_little_endian_u32() -> None:
    """vendor: o.cs case 14 (lines 113-128) writes 4 bytes.

    They are `(num3 & 0xFF)`, `((num3 & 0xFF00) >> 8)`, `((num3 & 0xFF0000) >> 16)`,
    `((num3 & 0xFF000000u) >> 24)` — least-significant byte first.
    """
    # 100-byte payload: body_length = 101 = 0x65 = LE u32 (0x65, 0x00, 0x00, 0x00).
    payload = bytes(100)
    f = Frame(header=HEADER_OUTGOING, verb=0x44, payload=payload)
    wire = build_frame(f, xor_key=0)
    # Wire offsets 3..7 are the length field.
    assert wire[3:7] == bytes([0x65, 0x00, 0x00, 0x00])


# --- frame layout ------------------------------------------------------


def test_frame_layout_byte_by_byte_for_empty_payload() -> None:
    """vendor: o.cs case 12 + case 14 + case 6 — empty-payload frame is 9 bytes.

    The bytes are AB AB 00 01 00 00 00 VV CK.
    """
    verb = 0x30  # ENTER_PROGRAM
    f = Frame(header=HEADER_OUTGOING, verb=verb, payload=b"")
    wire = build_frame(f, xor_key=0)
    assert wire[0:2] == b"\xab\xab"  # SYNC
    assert wire[2] == 0x00  # header
    assert wire[3:7] == b"\x01\x00\x00\x00"  # length=1 (just verb)
    assert wire[7] == verb  # verb byte
    # wire[8] is the checksum (asserted in checksum tests below)


def test_frame_layout_byte_by_byte_for_2byte_payload() -> None:
    """vendor: o.cs case 14 + case 9 — payload bytes follow the verb byte.

    BAUD_AND_ACK with payload [0x12, 0x01] (576000 baud + ack-each-packet).
    """
    f = Frame(header=HEADER_OUTGOING, verb=Verb.BAUD_AND_ACK.value, payload=b"\x12\x01")
    wire = build_frame(f, xor_key=0)
    assert wire[0:2] == b"\xab\xab"
    assert wire[2] == 0x00
    assert wire[3:7] == b"\x03\x00\x00\x00"  # length = 1+2 = 3
    assert wire[7] == 0x33  # BAUD_AND_ACK verb
    assert wire[8:10] == b"\x12\x01"  # payload


# --- checksum -----------------------------------------------------------


def test_checksum_is_sum8_of_header_length_verb_payload() -> None:
    """vendor: o.cs cases 12, 14, 9 and 6 compute and append the checksum.

    Case 12 (line 177 `b2 += array[num4]` adds only the 0x00 byte to
    checksum, NOT the two 0xAB sync bytes); case 14 (lines 115-127 add
    length bytes and verb); case 9 (line 106 adds each payload byte); case
    6 (line 196 writes `array[num4] = b2` as the trailing checksum byte).
    """
    verb = 0x30
    payload = b"\x42\xab\x00\xff"
    f = Frame(header=HEADER_OUTGOING, verb=verb, payload=payload)
    wire = build_frame(f, xor_key=0)

    # Reconstruct expected checksum: header + length + verb + payload (NO SYNC).
    body_length = 1 + len(payload)
    checked_body = (
        bytes([HEADER_OUTGOING])
        + body_length.to_bytes(4, "little")
        + bytes([verb])
        + payload
    )
    expected_cksum = sum8(checked_body)

    # Checksum is the trailing byte.
    assert wire[-1] == expected_cksum


def test_checksum_excludes_the_two_sync_bytes() -> None:
    """vendor: o.cs case 12 (lines 172-178) — the 0xAB writes skip the checksum.

    The two 0xAB writes use `array[num4] = 171; num4++` WITHOUT incrementing
    `b2`. Only the 0x00 on line 177 gets `b2 += array[num4]`.

    Equivalently: a frame whose payload-checksum-significant bytes are
    all zeros has wire checksum = 0, NOT 0xAB+0xAB = 0x56.
    """
    # All checksum-significant bytes are 0: header=0, length-LE-bytes=0,
    # verb=0, payload=empty. But body_length must be >= 1 (covered by Frame
    # validation). So pick verb=0, empty payload → length=1, checksum
    # should be 0x01 (just the length LSB), NOT 0x01 + 0xAB + 0xAB = 0x57.
    f = Frame(header=0x00, verb=0x00, payload=b"")
    wire = build_frame(f, xor_key=0)
    assert wire[-1] == 0x01  # checksum = sum8(00 + 01000000 + 00) = 0x01
    # If sync bytes were included it would be 0x57.
    assert wire[-1] != (0xAB + 0xAB + 0x01) & 0xFF


def test_sum8_is_byte_sum_modulo_256() -> None:
    """vendor: o.cs implicit (the checksum accumulator `b2` is a byte).

    It wraps on overflow because it's a `byte` type in C#.
    """
    assert sum8(b"") == 0
    assert sum8(b"\x01\x02\x03") == 6
    assert sum8(b"\xff\x01") == 0  # overflow wraps
    assert sum8(b"\xff" * 256) == 0  # 256 * 255 = 65280 ≡ 0 mod 256


# --- build/parse round trip ---------------------------------------------


def test_build_then_parse_round_trips_for_various_payloads() -> None:
    """vendor: o.cs:a(byte, byte[]) builds; Form1.DataReceived parses.

    The Form1.DataReceived event handler parses incoming frames using the
    inverse logic. Round-trip equivalence is the meta-invariant for both
    encoders.
    """
    test_cases = [
        (Verb.ENTER_PROGRAM, b""),
        (Verb.QUERY_TARGET, b""),
        (Verb.BAUD_AND_ACK, b"\x12\x01"),
        (Verb.SEND_CHUNK, b"\x00\x00\x10\x00" + b"\x40\x00\x00\x00" + bytes(64)),
        (Verb.COMPLETE_UPDATE, b"\xb0\x1d"),  # official 0x1DB0 LE u16
    ]
    for verb, payload in test_cases:
        f = Frame(header=HEADER_OUTGOING, verb=verb.value, payload=payload)
        wire = build_frame(f, xor_key=0)
        parsed, trailing = parse_frame(wire, xor_key=0)
        assert parsed.header == HEADER_OUTGOING
        assert parsed.verb == verb.value
        assert parsed.payload == payload
        assert trailing == b""


def test_parse_rejects_bad_sync() -> None:
    """vendor: implicit — radio's RX parser drops bytes until SYNC matches."""
    bad = b"\x00\x00\x00\x01\x00\x00\x00\x30\x30"
    try:
        _ = parse_frame(bad, xor_key=0)
    except FrameError:
        pass
    else:
        msg = "expected FrameError for missing sync"
        raise AssertionError(msg)


def test_parse_rejects_bad_checksum() -> None:
    """vendor: case 12 + case 6 ensure checksum is appended.

    The RX side verifies it matches the computed sum8 over the same checked
    region.
    """
    f = Frame(header=HEADER_OUTGOING, verb=0x30, payload=b"")
    wire = bytearray(build_frame(f, xor_key=0))
    wire[-1] ^= 0xFF  # corrupt checksum
    with pytest.raises(FrameError) as exc_info:
        _ = parse_frame(bytes(wire), xor_key=0)
    assert "checksum" in str(exc_info.value).lower()


def test_parse_rejects_truncated_frame() -> None:
    """vendor: case 14 — length field defines body size.

    The receiver must wait for full body before validating checksum.
    """
    f = Frame(header=HEADER_OUTGOING, verb=0x30, payload=b"\x12\x34\x56")
    wire = build_frame(f, xor_key=0)
    # Drop the last 2 bytes (part of payload + checksum)
    with pytest.raises(FrameError) as exc_info:
        _ = parse_frame(wire[:-2], xor_key=0)
    message = str(exc_info.value).lower()
    assert "truncated" in message or "short" in message


# --- cipher interaction --------------------------------------------------


def test_build_frame_with_key_0_is_unscrambled() -> None:
    """vendor: o.cs case 13 calls `Form1.b(array)` (cipher in-place) before write.

    Key=0 is the identity, so key=0 leaves the cleartext frame unchanged on
    the wire.
    """
    f = Frame(header=HEADER_OUTGOING, verb=0x30, payload=b"\x00")
    wire_no_cipher = build_frame(f, xor_key=0)
    # First two bytes should still be the raw 0xAB sync bytes.
    assert wire_no_cipher[0:2] == b"\xab\xab"


def test_build_frame_with_nonzero_key_changes_bytes() -> None:
    """vendor: o.cs case 13 — cipher is applied to the entire constructed frame.

    It covers header + length + verb + payload + checksum, not just the
    payload. With a non-zero key the sync bytes themselves get scrambled.
    """
    f = Frame(header=HEADER_OUTGOING, verb=0x30, payload=b"")
    wire_no_cipher = build_frame(f, xor_key=0)
    wire_with_cipher = build_frame(f, xor_key=0x42)
    assert wire_no_cipher != wire_with_cipher
    # Sync bytes should differ under cipher (0xAB scrambled with key 0x42 != 0xAB)
    assert wire_with_cipher[0:2] != b"\xab\xab"
