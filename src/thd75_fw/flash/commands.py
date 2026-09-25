"""TH-D75 FLDM verb set and response codes.

The verb numbers, payload shapes, and response semantics here were
extracted from the official Kenwood TH-D75 firmware updater. The
complete verb set was identified by enumerating every framed-send
call site in the decompiled updater (the main framer module plus the
dedicated data-streaming class that wraps SEND_CHUNK / END_TRANSFER).
Each verb's payload format and response behaviour is documented at
the relevant call site in ``flash/session.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Verb(IntEnum):
    """Outgoing command verbs.

    Convention: framed responses carry verb = request_verb + 1
    (see ``response_verb_for``).
    """

    ENTER_PROGRAM = 0x30
    QUERY_TARGET = 0x31
    BAUD_AND_ACK = 0x33
    SETUP_SEGMENT = 0x40
    BEGIN_TRANSFER = 0x42
    SEND_CHUNK = 0x43
    END_TRANSFER = 0x44
    VERIFY_SEGMENT = 0x45
    COMPLETE_UPDATE = 0x50
    TIMED_SESSION = 0xA0
    SELECT_TARGET = 0xA3


def response_verb_for(request_verb: Verb) -> int:
    """Framed-response verb for a request that returns a framed reply."""
    return int(request_verb) + 1


class AckCode(IntEnum):
    """One- or two-byte unframed responses from the loader."""

    ACK = 0x06
    BUSY = 0x11
    NAK = 0x15


class NakSubcode(IntEnum):
    """Second byte of a 0x15 NAK response (subcode)."""

    UNSUPPORTED_COMMAND = 0x01
    INVALID_PROGRAM_PAYLOAD = 0x02
    DATA_WRITE_REJECTED = 0x03
    COMMAND_ALREADY_ACTIVE = 0x04


@dataclass(frozen=True, slots=True)
class UnframedResponse:
    """A 1- or 2-byte ACK/BUSY/NAK response (never XOR-encrypted)."""

    code: AckCode
    nak_subcode: NakSubcode | None = None

    def __post_init__(self) -> None:
        """Require a subcode on a NAK and forbid one on ACK or BUSY.

        Raises:
            ValueError: If ``nak_subcode`` is missing for a NAK or present for
                any other code.

        """
        if (self.code is AckCode.NAK) != (self.nak_subcode is not None):
            msg = "nak_subcode must be set iff code is NAK"
            raise ValueError(msg)
