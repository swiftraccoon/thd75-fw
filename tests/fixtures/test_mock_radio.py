"""Sanity tests for the MockRadio test fixture.

The fixture is only worth trusting for a whole-package flash if its
loader-side rules actually bite, so the tests below drive it directly:
frames in, raw response bytes out, no FlashSession in between.
"""

from __future__ import annotations

import pytest

from tests.fixtures.mock_radio import MockRadio, MockRadioProtocolError
from thd75_fw.flash.commands import Verb
from thd75_fw.flash.handshake import (
    CLEARTEXT_MAGIC,
    MAGIC,
    UNLOCK_REPLY,
    Probe,
    derive_xor_key,
)
from thd75_fw.flash.protocol import Frame, build_frame, descramble
from thd75_fw.flash.segments import SegmentDescriptor

_PROBE_MINUTE = 0x2A
_PROBE_SECOND = 0x0F


def test_mock_radio_unlocks_at_responsive_baud() -> None:
    radio = MockRadio(responsive_at_bauds=(38400,))
    radio.set_baud(38400)
    _ = radio.write(b"\x00\x00" + MAGIC + b"\x2a\x0f")  # probe
    assert radio.read(64) == UNLOCK_REPLY


def test_mock_radio_unlocks_exact_cleartext_magic_at_selected_baud() -> None:
    radio = MockRadio(responsive_at_bauds=(576_000,))
    radio.set_baud(576_000)

    _ = radio.write(CLEARTEXT_MAGIC)

    assert radio.read(64) == UNLOCK_REPLY
    assert radio.wire_writes == (CLEARTEXT_MAGIC,)
    _command(radio, 0, Verb.ENTER_PROGRAM, b"\x00")
    assert radio.read(64) == b"\x06"
    assert radio.verb_log == [int(Verb.ENTER_PROGRAM)]


def test_mock_radio_silent_at_wrong_baud() -> None:
    radio = MockRadio(responsive_at_bauds=(38400,))
    radio.set_baud(9600)
    _ = radio.write(b"\x00\x00" + MAGIC + b"\x2a\x0f")
    assert radio.read(64) == b""


def _unlocked_radio(*, erase_busy_iterations: int = 1) -> tuple[MockRadio, int]:
    """Return an unlocked loader plus the XOR key it derived from the probe."""
    radio = MockRadio(
        responsive_at_bauds=(38400,),
        erase_busy_iterations=erase_busy_iterations,
    )
    radio.set_baud(38400)
    _ = radio.write(b"\x00\x00" + MAGIC + bytes([_PROBE_MINUTE, _PROBE_SECOND]))
    assert radio.read(64) == UNLOCK_REPLY
    key = derive_xor_key(
        Probe(prefix=b"\x00\x00", minute=_PROBE_MINUTE, second=_PROBE_SECOND),
    )
    return radio, key


def _command(radio: MockRadio, key: int, verb: Verb, payload: bytes = b"") -> None:
    """Send one framed command exactly as FlashSession would."""
    _ = radio.write(
        build_frame(
            Frame(header=0, verb=int(verb), payload=payload),
            xor_key=key,
        )
    )


def _descriptor(*, data_length: int, erase_length: int) -> SegmentDescriptor:
    return SegmentDescriptor(
        flash_start_addr=0x6020_0000,
        data_length=data_length,
        erase_length=erase_length,
        target_type_mask=0x0F,
        erase_wait_seconds=1,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0,
        checksum_start_offset=0,
        checksum_length=0,
        checksum_wait_seconds=1,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )


def _chunk_payload(offset: int, declared_length: int, data: bytes) -> bytes:
    return offset.to_bytes(4, "little") + declared_length.to_bytes(4, "little") + data


@pytest.mark.parametrize(
    ("baud_code", "ack_each_data_packet"),
    [(0x09, False), (0x0A, False), (0x12, True), (0x14, True)],
)
def test_data_packets_are_answered_only_in_acknowledged_modes(
    *,
    baud_code: int,
    ack_each_data_packet: bool,
) -> None:
    """The reply policy follows the loader's own baud-code table.

    A fixture that ACKs every data packet regardless would let a host
    declare a streamed mode and then wait forever for a reply on real
    hardware, which is the failure this rule exists to catch.
    """
    radio, key = _unlocked_radio()
    _command(
        radio,
        key,
        Verb.BAUD_AND_ACK,
        bytes([baud_code, int(ack_each_data_packet)]),
    )
    assert descramble(radio.read(64), key) == b"\x06"

    _command(
        radio,
        key,
        Verb.SETUP_SEGMENT,
        _descriptor(data_length=4, erase_length=0).to_wire(),
    )
    _ = radio.read(64)  # SETUP result

    _command(radio, key, Verb.SEND_CHUNK, _chunk_payload(0, 4, b"data"))
    reply = descramble(radio.read(64), key)
    assert reply == (b"\x06" if ack_each_data_packet else b"")
    assert radio.transfer_mode is not None
    assert radio.transfer_mode[1] is ack_each_data_packet


def test_unknown_baud_code_is_rejected() -> None:
    radio, key = _unlocked_radio()
    _command(radio, key, Verb.BAUD_AND_ACK, b"\x99\x00")
    assert descramble(radio.read(64), key) == b"\x15\x01"
    assert radio.transfer_mode is None


@pytest.mark.parametrize("erase_length", [0, 4])
def test_begin_transfer_reports_busy_before_its_ack(erase_length: int) -> None:
    radio, key = _unlocked_radio(erase_busy_iterations=2)
    _command(
        radio,
        key,
        Verb.SETUP_SEGMENT,
        _descriptor(data_length=4, erase_length=erase_length).to_wire(),
    )
    _ = radio.read(64)

    _command(radio, key, Verb.BEGIN_TRANSFER)
    assert descramble(radio.read(64), key) == b"\x11\x11\x06"
    assert radio.segment_writes[0].begin_transfers == 1


def test_chunk_whose_declared_length_lies_is_rejected() -> None:
    radio, key = _unlocked_radio()
    _command(
        radio,
        key,
        Verb.SETUP_SEGMENT,
        _descriptor(data_length=8, erase_length=0).to_wire(),
    )
    _ = radio.read(64)

    with pytest.raises(MockRadioProtocolError, match="declared_length"):
        _command(radio, key, Verb.SEND_CHUNK, _chunk_payload(0, 8, b"data"))


def test_chunk_that_skips_the_running_offset_is_rejected() -> None:
    radio, key = _unlocked_radio()
    _command(
        radio,
        key,
        Verb.SETUP_SEGMENT,
        _descriptor(data_length=8, erase_length=0).to_wire(),
    )
    _ = radio.read(64)

    _command(radio, key, Verb.SEND_CHUNK, _chunk_payload(0, 4, b"data"))
    with pytest.raises(MockRadioProtocolError, match="running counter"):
        _command(radio, key, Verb.SEND_CHUNK, _chunk_payload(8, 4, b"more"))


def test_chunk_past_the_declared_data_length_is_rejected() -> None:
    radio, key = _unlocked_radio()
    _command(
        radio,
        key,
        Verb.SETUP_SEGMENT,
        _descriptor(data_length=4, erase_length=0).to_wire(),
    )
    _ = radio.read(64)

    _command(radio, key, Verb.SEND_CHUNK, _chunk_payload(0, 4, b"data"))
    with pytest.raises(MockRadioProtocolError, match=r"\$DL"):
        _command(radio, key, Verb.SEND_CHUNK, _chunk_payload(4, 4, b"more"))


def test_truncated_frame_fails_at_the_write_that_sent_it() -> None:
    """A framing regression must not present as a read timeout later."""
    radio, key = _unlocked_radio()
    wire = build_frame(
        Frame(header=0, verb=int(Verb.QUERY_TARGET), payload=b""),
        xor_key=key,
    )

    with pytest.raises(MockRadioProtocolError, match="did not form a complete frame"):
        _ = radio.write(wire[:-1])
