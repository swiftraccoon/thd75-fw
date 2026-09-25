"""Tests for thd75_fw.flash.progress."""

from __future__ import annotations

import pytest

from thd75_fw.flash.progress import (
    FlashCompleted,
    HandshakeStarted,
    ProgressEvent,
    ProgressListener,
)


class _RecordingListener:
    def __init__(self) -> None:
        super().__init__()
        self.events: list[ProgressEvent] = []

    def emit(self, event: ProgressEvent) -> None:
        self.events.append(event)


def test_recording_listener_satisfies_protocol() -> None:
    # _RecordingListener satisfies the ProgressListener Protocol: the
    # annotated assignment is the static check, and the event goes in through
    # the Protocol-typed name. `events` is concrete-only (not part of the
    # Protocol), so it is read back through the concrete reference.
    recorder = _RecordingListener()
    listener: ProgressListener = recorder
    listener.emit(HandshakeStarted(port="/dev/cu.X", baud_ladder=(38400,)))
    assert len(recorder.events) == 1


def test_events_are_frozen_dataclasses() -> None:
    event = FlashCompleted(bytes_written=1024, elapsed_seconds=1.5)
    field_name = "bytes_written"
    with pytest.raises(AttributeError):
        setattr(event, field_name, 0)
