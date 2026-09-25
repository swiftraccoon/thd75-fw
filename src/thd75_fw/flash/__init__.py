"""TH-D75 firmware flasher.

Speaks the Kenwood FLDM (FldmLoader) serial protocol to a TH-D75 in
Firmware Programming Mode. See ``docs/USAGE.md`` for usage, the write
gates, and the stock recovery procedure.
"""

from __future__ import annotations

from . import (
    commands,
    diagnostics,
    handshake,
    progress,
    protocol,
    retry,
    segments,
    serial_io,
    session,
)
from .commands import AckCode, NakSubcode, UnframedResponse, Verb
from .diagnostics import FlashConfig, WireTrace
from .handshake import (
    BAUD_LADDER,
    HandshakeError,
    HandshakeResult,
    Probe,
    perform_handshake,
)
from .segments import FlatImageOptions, SegmentDescriptor
from .session import (
    FlashError,
    FlashOutcome,
    FlashRunOptions,
    FlashSession,
    FlashSessionOptions,
    TargetInfo,
)

__all__ = [
    "BAUD_LADDER",
    "AckCode",
    "FlashConfig",
    "FlashError",
    "FlashOutcome",
    "FlashRunOptions",
    "FlashSession",
    "FlashSessionOptions",
    "FlatImageOptions",
    "HandshakeError",
    "HandshakeResult",
    "NakSubcode",
    "Probe",
    "SegmentDescriptor",
    "TargetInfo",
    "UnframedResponse",
    "Verb",
    "WireTrace",
    "commands",
    "diagnostics",
    "handshake",
    "perform_handshake",
    "progress",
    "protocol",
    "retry",
    "segments",
    "serial_io",
    "session",
]
