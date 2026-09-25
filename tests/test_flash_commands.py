"""Tests for thd75_fw.flash.commands."""

from __future__ import annotations

import pytest

from thd75_fw.flash.commands import (
    AckCode,
    NakSubcode,
    UnframedResponse,
    Verb,
    response_verb_for,
)


class TestVerb:
    def test_known_verbs(self) -> None:
        assert Verb.ENTER_PROGRAM.value == 0x30
        assert Verb.QUERY_TARGET.value == 0x31
        assert Verb.BAUD_AND_ACK.value == 0x33
        assert Verb.SETUP_SEGMENT.value == 0x40
        assert Verb.BEGIN_TRANSFER.value == 0x42
        assert Verb.SEND_CHUNK.value == 0x43
        assert Verb.END_TRANSFER.value == 0x44
        assert Verb.VERIFY_SEGMENT.value == 0x45
        assert Verb.COMPLETE_UPDATE.value == 0x50
        assert Verb.TIMED_SESSION.value == 0xA0
        assert Verb.SELECT_TARGET.value == 0xA3

    def test_all_in_u8_range(self) -> None:
        for v in Verb:
            assert 0 <= int(v) <= 0xFF


class TestResponseVerbFor:
    def test_request_plus_one(self) -> None:
        assert response_verb_for(Verb.QUERY_TARGET) == 0x32
        assert response_verb_for(Verb.SETUP_SEGMENT) == 0x41
        assert response_verb_for(Verb.VERIFY_SEGMENT) == 0x46


class TestUnframedResponse:
    def test_ack_no_subcode(self) -> None:
        r = UnframedResponse(AckCode.ACK)
        assert r.code == AckCode.ACK
        assert r.nak_subcode is None

    def test_nak_with_subcode(self) -> None:
        r = UnframedResponse(AckCode.NAK, NakSubcode.UNSUPPORTED_COMMAND)
        assert r.code == AckCode.NAK
        assert r.nak_subcode == NakSubcode.UNSUPPORTED_COMMAND

    def test_nak_without_subcode_rejected(self) -> None:
        with pytest.raises(ValueError, match="nak_subcode must be set iff code is NAK"):
            _ = UnframedResponse(AckCode.NAK)

    def test_ack_with_subcode_rejected(self) -> None:
        with pytest.raises(ValueError, match="nak_subcode must be set iff code is NAK"):
            _ = UnframedResponse(AckCode.ACK, NakSubcode.UNSUPPORTED_COMMAND)
