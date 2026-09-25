"""Offline whole-package flash integration through the mock loader.

A complete stock-shaped KEX is driven end to end with no serial port
anywhere.

The rest of the session suite drives a one-segment plan whose ``$DL`` is
exactly one chunk. That plan never runs the chunk loop past its first
iteration, never crosses a segment boundary, and cannot observe an
END_TRANSFER cadence at all, so a whole class of regression — a
mis-derived offset, a dropped or duplicated chunk, a cluster-boundary rule
applied to the wrong mode — passes it untouched.

These tests drive the real seven-segment shape at the production data unit
and in the transfer mode the session actually negotiates:

* :func:`test_scaled_stock_package_flashes_every_segment` and its
  neighbours run a structurally identical package scaled to tens of
  kilobytes, so they belong in every suite run;
* :func:`test_real_stock_package_flashes_end_to_end` runs the real
  ~15.3 MB V1.03 artifact and is marked ``slow``: it needs ``--run-slow``
  and the operator-supplied KEX under ``recovery/``.
"""

from __future__ import annotations

import sys
import time
from itertools import groupby, pairwise
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.fixtures.mock_radio import MockRadio, MockRadioProtocolError
from tests.fixtures.synthetic_kex import (
    build_plaintext_kex,
    flash_plan,
    scaled_stock_segments,
)
from thd75_fw.flash import session as flash_session
from thd75_fw.flash.commands import Verb
from thd75_fw.flash.protocol import build_frame
from thd75_fw.flash.session import (
    FlashRunOptions,
    FlashSession,
    FlashSessionOptions,
    negotiated_transfer_mode,
)

if TYPE_CHECKING:
    from thd75_fw.flash.protocol import Frame
    from thd75_fw.flash.segments import SegmentDescriptor

#: Operator-supplied plaintext artifact. ``recovery/`` is gitignored — this
#: repository never redistributes Kenwood firmware bytes — so the full-image
#: test skips when it is absent instead of failing.
REAL_STOCK_KEX = (
    Path(__file__).resolve().parents[1] / "recovery" / "TH-D75_V103_stock_plaintext.KEX"
)

#: Exact operating baud of the proven direct-open cleartext recovery path.
_MOCK_UNLOCK_BAUD = 576_000


# ─── plan helpers ───────────────────────────────────────────────────────


def _chunk_count(descriptor: SegmentDescriptor, session_chunk_size: int) -> int:
    """SEND_CHUNK frames one segment costs at the session's data unit."""
    unit = min(session_chunk_size, descriptor.chunk_size or session_chunk_size)
    chunks, remainder = divmod(descriptor.data_length, unit)
    assert remainder == 0, (
        f"$DL {descriptor.data_length} is not a whole number of {unit}-byte "
        "packets; the session preflight should have rejected this plan"
    )
    return chunks


def _verb_runs(verb_log: list[int]) -> list[tuple[int, int]]:
    """Run-length encode a verb log.

    A full image is ~15k SEND_CHUNK frames, so the readable form of "the
    wire order was right" is the run-length encoding, not the raw list.
    """
    return [(verb, sum(1 for _ in group)) for verb, group in groupby(verb_log)]


def _expected_verb_runs(
    segments: list[SegmentDescriptor],
    *,
    session_chunk_size: int,
) -> list[tuple[int, int]]:
    """Return the exact verb order a full package flash owes the loader.

    Entry sequence, then per segment SETUP, BEGIN, the data packets,
    END_TRANSFER, and VERIFY only when ``$CL`` is nonzero; COMPLETE_UPDATE
    closes the session. The hardware-proven OpenWood recovery path sends BEGIN
    even for zero-erase overlays and sends one END_TRANSFER after all packets
    in each segment.
    """
    runs: list[tuple[int, int]] = [
        (int(Verb.ENTER_PROGRAM), 1),
        (int(Verb.TIMED_SESSION), 1),
        (int(Verb.QUERY_TARGET), 1),
        (int(Verb.BAUD_AND_ACK), 1),
    ]
    for descriptor in segments:
        chunks = _chunk_count(descriptor, session_chunk_size)
        runs.append((int(Verb.SETUP_SEGMENT), 1))
        runs.append((int(Verb.BEGIN_TRANSFER), 1))
        runs.append((int(Verb.SEND_CHUNK), chunks))
        runs.append((int(Verb.END_TRANSFER), 1))
        if descriptor.checksum_length:
            runs.append((int(Verb.VERIFY_SEGMENT), 1))
    runs.append((int(Verb.COMPLETE_UPDATE), 1))
    return runs


def _assert_bytes_equal(actual: bytes, expected: bytes, label: str) -> None:
    """Compare megabyte-scale payloads without a megabyte-scale failure."""
    if actual == expected:
        return
    if len(actual) != len(expected):
        pytest.fail(
            f"{label}: loader received {len(actual)} bytes, expected {len(expected)}"
        )
    for offset, (got, want) in enumerate(zip(actual, expected, strict=True)):
        if got != want:
            pytest.fail(
                f"{label}: first byte mismatch at offset {offset} "
                f"(0x{offset:X}): received 0x{got:02X}, expected 0x{want:02X}"
            )


def _assert_package_flashed(
    radio: MockRadio,
    outcome: flash_session.FlashOutcome,
    segments: list[SegmentDescriptor],
    payloads: dict[int, bytes],
    *,
    session_chunk_size: int,
) -> None:
    """Assert one complete package reached the loader intact and in order."""
    mode = negotiated_transfer_mode()
    assert radio.transfer_mode == (
        mode.declared_baud,
        mode.ack_each_data_packet,
    ), "loader applied a different transfer mode than the host negotiated"

    # Nothing the host wrote was left dangling or unparsable. Without this a
    # framing regression shows up as a read timeout somewhere later, whose
    # message says nothing about framing.
    assert radio.unparsed_input == b"", (
        f"loader still holds {len(radio.unparsed_input)} unparsed byte(s)"
    )
    assert radio.frames_parsed == len(radio.verb_log)

    assert outcome.segments_written == len(segments)
    assert outcome.bytes_written == sum(d.data_length for d in segments)

    writes = radio.segment_writes
    assert len(writes) == len(segments)
    for index, (descriptor, write) in enumerate(zip(segments, writes, strict=True)):
        label = f"segment {index} (0x{descriptor.flash_start_addr:08X})"
        assert write.flash_start_addr == descriptor.flash_start_addr, label
        assert write.data_length == descriptor.data_length, label
        assert write.chunk_count == _chunk_count(descriptor, session_chunk_size), (
            f"{label}: wrong SEND_CHUNK count"
        )
        assert write.begin_transfers == 1, (
            f"{label}: the proven recovery path owes one BEGIN_TRANSFER "
            "for every written segment"
        )
        assert write.verifies == (1 if descriptor.checksum_length else 0), (
            f"{label}: VERIFY_SEGMENT is owed exactly when $CL is nonzero"
        )
        # The KEX carries erase padding past $DL for some segments; only the
        # declared $DL bytes may ever reach the radio.
        _assert_bytes_equal(
            bytes(write.data),
            payloads[index][: descriptor.data_length],
            label,
        )

    assert _verb_runs(radio.verb_log) == _expected_verb_runs(
        segments,
        session_chunk_size=session_chunk_size,
    )


def _flash_package(
    segments: list[SegmentDescriptor],
    payloads: dict[int, bytes],
) -> tuple[MockRadio, flash_session.FlashOutcome]:
    """Run one complete offline flash and return the loader and outcome."""
    radio = MockRadio(
        responsive_at_bauds=(_MOCK_UNLOCK_BAUD,),
        # The form a real D75 V1.03 loader answers framed commands with.
        framed_acks=True,
        # Answer VERIFY_SEGMENT from the programmed bytes rather than from a
        # fixture switch. Both packages carry real $CA values, so the loader
        # checks the reassembled image the way the radio does — which is the
        # only backstop the streamed mode has, since nothing acknowledges the
        # data packets themselves.
        verify_checksum=True,
    )
    session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
    return radio, session.flash_segments(
        segments,
        payloads,
        FlashRunOptions(
            always_flash=False, cleartext_unlock=True, cleartext_baud=_MOCK_UNLOCK_BAUD
        ),
    )


def _scaled_package() -> tuple[list[SegmentDescriptor], dict[int, bytes]]:
    """Parse the scaled stock-shaped KEX exactly as the CLI parses a real one."""
    return flash_plan(build_plaintext_kex(scaled_stock_segments()))


# ─── scaled package (runs in every suite run) ───────────────────────────


def test_scaled_stock_package_flashes_every_segment() -> None:
    """Seven segments, production data unit, byte-exact reassembly."""
    segments, payloads = _scaled_package()
    assert len(segments) == 7

    radio, outcome = _flash_package(segments, payloads)

    _assert_package_flashed(
        radio,
        outcome,
        segments,
        payloads,
        session_chunk_size=FlashSession.DEFAULT_CHUNK_SIZE,
    )


def test_scaled_package_streams_more_than_one_chunk_per_segment() -> None:
    """Guard the fixture itself against one-chunk segments.

    A package whose segments are one chunk each would pass every assertion
    above while testing nothing about the chunk loop, which is exactly the
    gap these tests exist to close.
    """
    segments, _ = _scaled_package()
    multi_chunk = [
        descriptor
        for descriptor in segments
        if _chunk_count(descriptor, FlashSession.DEFAULT_CHUNK_SIZE) > 1
    ]
    assert len(multi_chunk) == 5, (
        "the five non-overlay segments must each span several data units"
    )


def test_end_transfer_closes_each_segment_exactly_once() -> None:
    """Pin the production recovery cadence across all seven segments."""
    mode = negotiated_transfer_mode()
    assert mode.ack_each_data_packet is True

    segments, payloads = _scaled_package()
    radio, _outcome = _flash_package(segments, payloads)

    for index, write in enumerate(radio.segment_writes):
        assert write.end_transfers == 1, (
            f"segment {index} closed with {write.end_transfers} END_TRANSFER(s); "
            "the recovery profile owes exactly one per segment"
        )
    assert radio.verb_log.count(int(Verb.END_TRANSFER)) == len(segments)

    # No END_TRANSFER may fall between two data packets of one segment.
    for previous, current in pairwise(radio.verb_log):
        if previous == int(Verb.END_TRANSFER):
            assert current != int(Verb.SEND_CHUNK), (
                "END_TRANSFER appeared mid-segment in a data transfer"
            )


def test_acknowledged_256_byte_profile_ignores_kex_dc_for_end_cadence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`$DC=1024` is host metadata, not an intermediate loader boundary."""
    monkeypatch.setattr(flash_session, "_FLDM_TRANSFER_MODE_CODE", 0x12)
    mode = negotiated_transfer_mode()
    assert mode.ack_each_data_packet is True

    segments, payloads = _scaled_package()
    radio, outcome = _flash_package(segments, payloads)

    _assert_package_flashed(
        radio,
        outcome,
        segments,
        payloads,
        session_chunk_size=FlashSession.DEFAULT_CHUNK_SIZE,
    )
    writes = radio.segment_writes
    for index, (descriptor, write) in enumerate(zip(segments, writes, strict=True)):
        assert write.end_transfers == 1, (
            f"segment {index} sent {write.end_transfers} END_TRANSFER(s); "
            "the proven profile sends one after the whole segment"
        )
        if descriptor.data_length > 32:
            assert descriptor.checksum_chunk == 1024
            assert _chunk_count(descriptor, FlashSession.DEFAULT_CHUNK_SIZE) > 1


def test_loader_rejects_a_frame_it_cannot_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The framing tripwire has to bite, or asserting on it is decoration.

    Corrupt one byte of every frame the host builds and the loader must
    fail at that write, not sit waiting for the rest of a frame that will
    never arrive.
    """

    def corrupting_build_frame(frame: Frame, *, xor_key: int = 0) -> bytes:
        wire = bytearray(build_frame(frame, xor_key=xor_key))
        wire[-1] ^= 0x01
        return bytes(wire)

    monkeypatch.setattr(flash_session, "build_frame", corrupting_build_frame)
    segments, payloads = _scaled_package()

    with pytest.raises(MockRadioProtocolError, match="could not parse"):
        _ = _flash_package(segments, payloads)


# ─── real package (opt-in) ──────────────────────────────────────────────


@pytest.mark.slow
def test_real_stock_package_flashes_end_to_end() -> None:
    """The complete stock V1.03 artifact, ~15.3 MB across seven segments.

    Same assertions as the scaled package, on the bytes an operator would
    actually send to a radio: every segment written, the total equal to the
    sum of ``$DL``, every segment's reassembled image byte-identical to its
    source, and the verb order exactly what the negotiated mode owes.

    Wall-clock is reported because it is also the host-side cost of a real
    flash minus the wire: everything the flasher does per chunk except wait
    for the radio.
    """
    if not REAL_STOCK_KEX.exists():
        pytest.skip(f"{REAL_STOCK_KEX.name} not present (recovery/ is gitignored)")

    parse_start = time.monotonic()
    segments, payloads = flash_plan(REAL_STOCK_KEX.read_bytes())
    parse_seconds = time.monotonic() - parse_start
    assert len(segments) == 7

    flash_start = time.monotonic()
    radio, outcome = _flash_package(segments, payloads)
    flash_seconds = time.monotonic() - flash_start

    _assert_package_flashed(
        radio,
        outcome,
        segments,
        payloads,
        session_chunk_size=FlashSession.DEFAULT_CHUNK_SIZE,
    )
    # The timing report is this opt-in test's deliberate output (shown with
    # ``-s``), written straight to the captured stdout.
    _ = sys.stdout.write(
        f"\nfull-image flash: {outcome.bytes_written:,} bytes in "
        f"{len(segments)} segments, {radio.verb_log.count(int(Verb.SEND_CHUNK)):,} "
        f"data packets\n"
        f"  KEX parse: {parse_seconds:.2f}s\n"
        f"  flash:     {flash_seconds:.2f}s\n"
        f"  total:     {parse_seconds + flash_seconds:.2f}s\n"
    )
