"""Tests for thd75_fw.flash_ui."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from thd75_fw.flash.progress import (
    FlashCompleted,
    HandshakeSucceeded,
    SegmentVerified,
)
from thd75_fw.flash_ui import RichProgressListener


def _capture() -> tuple[RichProgressListener, StringIO]:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=80)
    return RichProgressListener(console), buf


def test_handshake_succeeded_renders_baud_and_key() -> None:
    listener, buf = _capture()
    listener.emit(HandshakeSucceeded(baud=38400, xor_key=0x4A))
    out = buf.getvalue()
    assert "38400" in out
    assert "0x4A" in out


def test_segment_verified_shows_loader_status_and_descriptor_checksum() -> None:
    listener, buf = _capture()
    listener.emit(
        SegmentVerified(
            name="FIRMWARE",
            expected_checksum=0x3343,
            status_code=0,
        )
    )
    out = buf.getvalue()
    assert "0x3343" in out
    assert "status 0x00" in out


def test_flash_completed_shows_byte_count_and_elapsed() -> None:
    listener, buf = _capture()
    listener.emit(
        FlashCompleted(
            bytes_written=41 * 1024 * 1024,
            elapsed_seconds=272.0,
        )
    )
    out = buf.getvalue()
    assert "complete" in out.lower()
    assert "272" in out
