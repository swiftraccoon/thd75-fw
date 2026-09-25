"""Vendor parity tests — verb opcodes.

Parses the vendor `b.cs` enum (22 entries) and asserts our `Verb`,
`AckCode`, `NakSubcode`, and `UNLOCK_REPLY` constants line up.

Each test cites the vendor source. Where a vendor opcode is deliberately
absent from our Python enums (e.g., framed-response verb = request+1, or
declared-but-unsent verbs like D74's 0x41 BEGIN_TRANSFER), the test
documents the deliberate gap rather than asserting equivalence.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from thd75_fw.flash.commands import AckCode, NakSubcode, Verb, response_verb_for
from thd75_fw.flash.handshake import UNLOCK_REPLY

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENDOR_B_CS = PROJECT_ROOT / "ref/TH-D75_V103_E/decompiled/b.cs"


def _parse_b_cs_enum() -> dict[str, int]:
    """Parse the `internal enum b` body from b.cs into a name→value dict.

    vendor: b.cs:1-25 (the entire file is the enum declaration).
    """
    if not VENDOR_B_CS.exists():
        pytest.skip(f"Vendor source not present: {VENDOR_B_CS}")
    text = VENDOR_B_CS.read_text(encoding="utf-8")
    pattern = re.compile(r"^\s*([a-z])\s*=\s*(\d+)\s*,?\s*$", re.MULTILINE)
    result: dict[str, int] = {}
    for match in pattern.finditer(text):
        name, value = match.group(1), int(match.group(2))
        result[name] = value
    return result


def test_b_cs_enum_has_22_entries() -> None:
    """vendor: b.cs:1-25 (22 enum members, a through v)."""
    enum_values = _parse_b_cs_enum()
    assert len(enum_values) == 22, (
        f"b.cs parsed {len(enum_values)} entries, expected 22. "
        f"Got: {sorted(enum_values.items())}"
    )


def test_b_cs_member_names_are_a_through_v() -> None:
    """vendor: b.cs (Dotfuscator-renamed members)."""
    enum_values = _parse_b_cs_enum()
    expected = {chr(ord("a") + i) for i in range(22)}  # a, b, ..., v
    assert set(enum_values.keys()) == expected


def test_ack_byte_is_0x06_per_b_cs_a() -> None:
    """vendor: b.cs:3 (`a = 6`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["a"] == 0x06
    assert AckCode.ACK.value == 0x06


def test_unlock_reply_first_byte_is_0x16_per_b_cs_b() -> None:
    """vendor: b.cs:4 (`b = 22`).

    The first byte of the 2-byte unlock reply. RE finding:
    'Unlock reply IS 2 raw bytes (0x16 0x06)'.
    """
    enum_values = _parse_b_cs_enum()
    assert enum_values["b"] == 0x16
    assert UNLOCK_REPLY[0] == 0x16


def test_busy_byte_is_0x11_per_b_cs_c() -> None:
    """vendor: b.cs:5 (`c = 17`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["c"] == 0x11
    assert AckCode.BUSY.value == 0x11


def test_nak_byte_is_0x15_per_b_cs_d() -> None:
    """vendor: b.cs:6 (`d = 21`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["d"] == 0x15
    assert AckCode.NAK.value == 0x15


def test_enter_program_opcode_is_0x30_per_b_cs_f() -> None:
    """vendor: b.cs:8 (`f = 48`); used at f.cs ENTER_PROGRAM callsite."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["f"] == 0x30
    assert Verb.ENTER_PROGRAM.value == 0x30


def test_query_target_opcode_is_0x31_per_b_cs_g() -> None:
    """vendor: b.cs:9 (`g = 49`); framed response is 0x32 = g+1 per convention."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["g"] == 0x31
    assert Verb.QUERY_TARGET.value == 0x31
    assert response_verb_for(Verb.QUERY_TARGET) == 0x32
    # b.cs:h is 0x32, the framed-response opcode.
    assert enum_values["h"] == 0x32


def test_baud_and_ack_opcode_is_0x33_per_b_cs_i() -> None:
    """vendor: b.cs:11 (`i = 51`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["i"] == 0x33
    assert Verb.BAUD_AND_ACK.value == 0x33


def test_setup_segment_opcode_is_0x40_per_b_cs_j() -> None:
    """vendor: b.cs:12 (`j = 64`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["j"] == 0x40
    assert Verb.SETUP_SEGMENT.value == 0x40


def test_d74_begin_transfer_0x41_declared_but_not_in_our_verb_enum() -> None:
    """vendor: b.cs:13 (`k = 65`).

    D74's BEGIN_TRANSFER opcode per openwood. The vendor enum declares
    0x41 (perhaps for D74 compatibility) but D75 never sends it. We
    deliberately omit 0x41 from our `Verb` enum and only define 0x42.
    This test documents the deliberate gap.
    """
    enum_values = _parse_b_cs_enum()
    assert enum_values["k"] == 0x41
    # 0x41 must NOT be present in our Verb enum.
    assert 0x41 not in {int(v) for v in Verb}


def test_begin_transfer_opcode_is_0x42_per_b_cs_l() -> None:
    """vendor: b.cs:14 (`l = 66`); cite: f.cs:2686 `o.a(66, null)`.

    RE finding: 'BEGIN_TRANSFER is verb 0x42 on D75, NOT 0x41.'
    """
    enum_values = _parse_b_cs_enum()
    assert enum_values["l"] == 0x42
    assert Verb.BEGIN_TRANSFER.value == 0x42


def test_send_chunk_opcode_is_0x43_per_b_cs_m() -> None:
    """vendor: b.cs:15 (`m = 67`); cite: n.cs:137 and n.cs:247.

    n.cs:137 is `o.a(67, array4)` and n.cs:247 is `o.a(67, array)`.

    SEND_CHUNK is 0x43 in the vendor enum, not 0x44.
    """
    enum_values = _parse_b_cs_enum()
    assert enum_values["m"] == 0x43
    assert Verb.SEND_CHUNK.value == 0x43


def test_end_transfer_opcode_is_0x44_per_b_cs_n() -> None:
    """vendor: b.cs:16 (`n = 68`); cite: n.cs:172 `o.a(68, null)`."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["n"] == 0x44
    assert Verb.END_TRANSFER.value == 0x44


def test_verify_segment_opcode_is_0x45_per_b_cs_o() -> None:
    """vendor: b.cs:17 (`o = 69`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["o"] == 0x45
    assert Verb.VERIFY_SEGMENT.value == 0x45
    # b.cs:p (0x46) is the framed response for VERIFY_SEGMENT (45 + 1).
    assert enum_values["p"] == 0x46
    assert response_verb_for(Verb.VERIFY_SEGMENT) == 0x46


def test_complete_update_opcode_is_0x50_per_b_cs_q() -> None:
    """vendor: b.cs:19 (`q = 80`)."""
    enum_values = _parse_b_cs_enum()
    assert enum_values["q"] == 0x50
    assert Verb.COMPLETE_UPDATE.value == 0x50


def test_timed_session_opcode_is_0xa0_per_b_cs_r() -> None:
    """vendor: b.cs:20 (`r = 160`).

    Note: user's 2026-05-25 protocol-correction commit re-introduced
    sending TIMED_SESSION as part of the entry sequence (per openwood).
    """
    enum_values = _parse_b_cs_enum()
    assert enum_values["r"] == 0xA0
    assert Verb.TIMED_SESSION.value == 0xA0


def test_select_target_opcode_is_0xa3_per_b_cs_u() -> None:
    """vendor: b.cs:23 (`u = 163`).

    RE finding: 'SELECT_TARGET (0xA3): hardware-tested on D75
    V1.03 — returns framed NAK 0x15 0x01 ... AND triggers radio display
    "Error Data Error!!".' We deliberately do NOT send this verb, but
    we define the opcode for completeness/diagnostic.
    """
    enum_values = _parse_b_cs_enum()
    assert enum_values["u"] == 0xA3
    assert Verb.SELECT_TARGET.value == 0xA3


def test_response_verb_convention_is_request_plus_one() -> None:
    """vendor: implicit convention used throughout f.cs.

    Every framed response carries verb = request_verb + 1. b.cs encodes
    both pairs (0x31/0x32 = QUERY_TARGET/response, 0x45/0x46 =
    VERIFY_SEGMENT/response).
    """
    assert response_verb_for(Verb.QUERY_TARGET) == 0x32
    assert response_verb_for(Verb.VERIFY_SEGMENT) == 0x46


def test_nak_subcodes_match_documented_values() -> None:
    """OpenWood D74 names for values the D75 host handles as NAK subcodes.

    The numeric D75 branches are present in ``f.cs``; the semantic labels come
    from related-model OpenWood evidence and are not D75 hardware captures.
    """
    assert NakSubcode.UNSUPPORTED_COMMAND.value == 0x01
    assert NakSubcode.INVALID_PROGRAM_PAYLOAD.value == 0x02
    assert NakSubcode.DATA_WRITE_REJECTED.value == 0x03
    assert NakSubcode.COMMAND_ALREADY_ACTIVE.value == 0x04


def test_our_verb_enum_subset_of_b_cs() -> None:
    """Every value in our Verb enum must appear in b.cs."""
    enum_values = _parse_b_cs_enum()
    vendor_opcodes = set(enum_values.values())
    ours_opcodes = {int(v) for v in Verb}
    extras = ours_opcodes - vendor_opcodes
    assert not extras, (
        f"Our Verb enum has opcodes not declared in vendor b.cs: {extras}"
    )


def test_vendor_opcodes_we_dont_define_are_documented() -> None:
    """Every vendor opcode missing from our Verb enum falls in a known category.

    Any such opcode is either:

    - A framed-response opcode (request + 1), covered implicitly by
      `response_verb_for()`.
    - The D74 BEGIN_TRANSFER (0x41), deliberately omitted.
    - An ACK/BUSY/NAK byte (covered by `AckCode`).
    - The unlock-reply first byte (0x16), covered by `UNLOCK_REPLY[0]`.
    - An opcode left unhandled pending a decision (0x12, 0xA1, 0xA2, 0xA4).

    This test documents the categorization without asserting handling.
    """
    enum_values = _parse_b_cs_enum()
    vendor_opcodes = set(enum_values.values())
    ours_opcodes = {int(v) for v in Verb}
    ack_codes = {int(c) for c in AckCode}
    unlock_first = UNLOCK_REPLY[0]
    framed_response_verbs = {int(v) + 1 for v in Verb}
    d74_only = {0x41}
    needs_decision = {0x12, 0xA1, 0xA2, 0xA4}
    accounted = (
        ours_opcodes
        | ack_codes
        | {unlock_first}
        | framed_response_verbs
        | d74_only
        | needs_decision
    )
    unaccounted = vendor_opcodes - accounted
    assert not unaccounted, (
        f"Vendor opcodes not accounted for in any category: {unaccounted}"
    )
