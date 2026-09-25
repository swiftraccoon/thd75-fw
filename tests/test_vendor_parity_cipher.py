"""Vendor parity tests — cipher layer.

S-box, key derivation, scramble/descramble round-trip. Each test cites the
vendor source location it asserts against and reads the vendor bytes
directly from the decompiled `.cs` files (no manual transcription of
constants — the test files in `ref/` are read-only ground truth).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from thd75_fw.flash.handshake import _DERIVATION_STRING
from thd75_fw.flash.protocol import M_H, M_H_INV, descramble, scramble

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENDOR_Q_CS = PROJECT_ROOT / "ref/TH-D75_V103_E/decompiled/q.cs"
VENDOR_FORM1 = PROJECT_ROOT / "ref/TH-D75_V103_E/decompiled/THD75_Updater_E/Form1.cs"


def _parse_sbox_from_q_cs() -> bytes:
    """Extract the 256-byte forward S-box from q.cs's static-data blob.

    vendor: q.cs:11 (the "Not supported: data(...)" comment carries the
    raw bytes that the .NET CLR loads into the static field at runtime).
    """
    if not VENDOR_Q_CS.exists():
        pytest.skip(f"Vendor source not present: {VENDOR_Q_CS}")
    text = VENDOR_Q_CS.read_text(encoding="utf-8")
    match = re.search(r"data\(([^)]+)\)", text)
    assert match is not None, "q.cs static-data blob not found"
    tokens = match.group(1).split()
    assert len(tokens) == 256, f"q.cs blob has {len(tokens)} bytes, expected 256"
    return bytes(int(t, 16) for t in tokens)


def _parse_sbox_from_form1_cs() -> bytes:
    """Extract the 256-byte forward S-box from Form1.cs:162 decimal literal.

    vendor: Form1.cs:162-225 (`private readonly byte[] m_h = new byte[256] {
    91, 205, 239, 65, ... }`). The decimal literal spans ~16 lines after
    the declaration; we capture every integer literal in the `{ ... }` block.
    """
    if not VENDOR_FORM1.exists():
        pytest.skip(f"Vendor source not present: {VENDOR_FORM1}")
    text = VENDOR_FORM1.read_text(encoding="utf-8")
    # Locate the m_h declaration at line 162 and capture its initializer body.
    match = re.search(
        r"m_h\s*=\s*new\s*byte\s*\[\s*256\s*\]\s*\{([^}]+)\}",
        text,
    )
    assert match is not None, "Form1.cs m_h initializer not found"
    body = match.group(1)
    tokens = re.findall(r"-?\d+", body)
    assert len(tokens) == 256, f"Form1.cs m_h has {len(tokens)} bytes, expected 256"
    # Decimal values; convert via int() not bytes().
    return bytes(int(t) & 0xFF for t in tokens)


def test_sbox_q_cs_blob_matches_m_h() -> None:
    """vendor: q.cs:11 (static-data forward S-box)."""
    vendor_q = _parse_sbox_from_q_cs()
    assert len(vendor_q) == 256
    assert len(M_H) == 256
    assert vendor_q == M_H


def test_sbox_form1_initializer_matches_m_h() -> None:
    """vendor: Form1.cs:162-225 (readable decimal-literal forward S-box)."""
    vendor_form1 = _parse_sbox_from_form1_cs()
    assert len(vendor_form1) == 256
    assert vendor_form1 == M_H


def test_q_cs_and_form1_sbox_are_byte_identical() -> None:
    """vendor: q.cs:11 vs Form1.cs:162-225 — same data, two encodings.

    The obfuscator/compiler emits the S-box twice: once as an unmanaged
    static struct (q.cs) and once as a readable byte[] initializer in the
    Form1 class. Either MUST match the other byte-for-byte.
    """
    assert _parse_sbox_from_q_cs() == _parse_sbox_from_form1_cs()


def test_m_h_is_a_permutation_of_0_to_255() -> None:
    """Sanity invariant of any S-box: it must be a bijection over [0, 256).

    vendor: q.cs:11 / Form1.cs:162-225 (S-box; invariant inherent to its design)
    """
    assert sorted(M_H) == list(range(256))


def test_m_h_inv_is_inverse_of_m_h() -> None:
    """vendor: implicit (inverse computed by descrambler, not stored).

    For every i in [0, 256): M_H[M_H_INV[i]] == i.
    """
    for i in range(256):
        assert M_H[M_H_INV[i]] == i, (
            f"M_H_INV[{i:#x}] = {M_H_INV[i]:#x}; "
            f"M_H[M_H_INV[{i:#x}]] = {M_H[M_H_INV[i]]:#x}, expected {i:#x}"
        )


def test_derivation_string_is_th_d75_two_spaces() -> None:
    """vendor: f.cs:2139,2164-2169 (constant and XOR-key derivation).

    The string "TH-D75  " that OpenWood mentions is the XOR-key
    derivation constant (its sum = 0xB9), not the wire reply.

    Note: the cited "sum = 0xB9" refers to ``sum & 0xFF`` (the byte
    width relevant to XOR key derivation). The full integer sum is
    441 (0x1B9); the low byte is 0xB9. Both forms are asserted.
    """
    assert _DERIVATION_STRING == b"TH-D75  "
    assert len(_DERIVATION_STRING) == 8
    assert sum(_DERIVATION_STRING) == 441
    assert sum(_DERIVATION_STRING) & 0xFF == 0xB9


def test_scramble_descramble_round_trip_exhaustive() -> None:
    """vendor: THD75_Updater_E/Form1.cs:3208-3477 (cipher and inverse).

    The round trip is verified exhaustively over all 65,536 pairs.
    """
    for byte_val in range(256):
        for key in range(256):
            data = bytes([byte_val])
            scrambled = scramble(data, key)
            recovered = descramble(scrambled, key)
            assert recovered == data, (
                f"Round-trip failure: byte=0x{byte_val:02x}, "
                f"key=0x{key:02x}, scrambled=0x{scrambled[0]:02x}, "
                f"recovered=0x{recovered[0]:02x}"
            )


def test_scramble_is_4step_not_plain_xor() -> None:
    """vendor: THD75_Updater_E/Form1.cs:3208-3321 (cipher composition).

    D74 is byte ^ key; D75 is a 4-step cipher. Spot-check
    at multiple non-zero-key values where simple XOR would produce a
    different result. (Key=0 is short-circuited to identity in our
    implementation; see ``protocol.py`` docstring "``key == 0`` is identity".)
    """
    for byte_val, key in [(0x00, 0x42), (0xFF, 0x01), (0x55, 0xAA), (0x01, 0x42)]:
        data = bytes([byte_val])
        scrambled = scramble(data, key)
        simple_xor = bytes([byte_val ^ key])
        assert scrambled != simple_xor, (
            f"Cipher appears to be plain XOR for byte=0x{byte_val:02x}, "
            f"key=0x{key:02x}. scramble = 0x{scrambled[0]:02x}; "
            f"XOR would be 0x{simple_xor[0]:02x}."
        )


def test_scramble_with_key_zero_is_identity_short_circuit() -> None:
    """vendor: implicit (a handshake that derives key=0 bypasses the keyed cipher).

    Our ``scramble`` / ``descramble`` short-circuit when ``key == 0``,
    returning the input unchanged (see protocol.py docstring: "``key == 0``
    is identity"). This matters because:

    - Before the keyed handshake completes, the cipher transport is
      effectively "off" (key=0); the unlock-reply bytes (0x16 0x06) are
      NOT scrambled even though they pass through the same I/O layer.
    - The 4-step composition with key=0 (add-0 → S-box → XOR-0 → rotl3)
      would NOT be identity by itself (it'd produce ``rotl3(M_H[b])``),
      so the identity short-circuit is a deliberate behavior, not an
      arithmetic accident.
    """
    for byte_val in [0x00, 0x42, 0xFF, 0xAB]:
        assert scramble(bytes([byte_val]), 0) == bytes([byte_val])
        assert descramble(bytes([byte_val]), 0) == bytes([byte_val])
