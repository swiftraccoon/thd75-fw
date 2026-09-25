from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.fixtures.mock_radio import MockRadio
from thd75_fw import intel_hex, kex
from thd75_fw._compat import override
from thd75_fw.flash import qualification as qualification_module
from thd75_fw.flash.commands import Verb
from thd75_fw.flash.diagnostics import (
    BANNER_END,
    BANNER_START,
    TRACE_COLUMNS,
    TRACE_FORMAT_VERSION,
    FlashConfig,
    WireTrace,
    flasher_source_digest,
    verb_label,
)
from thd75_fw.flash.qualification import (
    QualificationError,
    main,
    validate_qualification_trace,
)
from thd75_fw.flash.segments import SegmentDescriptor
from thd75_fw.flash.session import (
    FlashRunOptions,
    FlashSession,
    FlashSessionOptions,
    negotiated_transfer_mode,
)

if TYPE_CHECKING:
    from thd75_fw.flash.protocol import Frame

_IMAGE_SHA256 = "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
_IMAGE_DATA_SHA256 = "cd86abd837cd8cdf2b781148eec52d9cb39ce11f8b6b7d13e2f380669d652fb2"
_PRODUCTION_SAMPLE_SHA256 = qualification_module._IMAGE_DATA_SAMPLE_SHA256
_SYNTHETIC_SAMPLE_SHA256 = hashlib.sha256(b"\x01" * (1_408 * 8)).hexdigest()

_BAUD_NOTE = "baud -> 576000 (set before cleartext FPROMOD)"
_UNLOCK_NOTE = "unlocked at baud 576000 via cleartext path"
_FORCE_NOTE = "segment_1 setup=current; qualification force-write"
_SOURCE_DIGEST = flasher_source_digest()


@pytest.fixture(autouse=True)
def accept_synthetic_image_samples(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep synthetic traces compact while production pins real stock samples."""
    monkeypatch.setattr(
        qualification_module,
        "_IMAGE_DATA_SAMPLE_SHA256",
        _SYNTHETIC_SAMPLE_SHA256,
    )


class _SetupSequenceRadio(MockRadio):
    def __init__(self, setup_results: tuple[bytes, ...]) -> None:
        super().__init__(
            responsive_at_bauds=(576_000,),
            framed_acks=True,
            erase_busy_iterations=1,
        )
        self._setup_results = list(setup_results)

    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SETUP_SEGMENT:
            if not self._setup_results:
                msg = "unexpected extra SETUP_SEGMENT"
                raise AssertionError(msg)
            self.setup_result = self._setup_results.pop(0)
        super()._handle_frame(frame)


@dataclass
class _Record:
    direction: str
    verb: int
    payload_length: int
    prefix: bytes


@dataclass(frozen=True)
class _Segment:
    index: int
    setup_length: int
    setup_prefix: bytes
    data_length: int
    verifies: bool
    overlay_prefix: bytes | None = None

    @property
    def chunk_size(self) -> int:
        return min(256, self.data_length)


_SEGMENTS = (
    _Segment(
        0,
        67,
        bytes.fromhex("00 00 20 60 00 00 28 00 00 00 28 00 00 00 00 00"),
        2_621_440,
        verifies=True,
    ),
    _Segment(
        1,
        62,
        bytes.fromhex("00 00 60 60 00 80 05 00 00 00 06 00 00 00 00 00"),
        360_448,
        verifies=True,
    ),
    _Segment(
        2,
        64,
        bytes.fromhex("00 00 e0 60 00 00 10 00 00 00 10 00 00 00 00 00"),
        1_048_576,
        verifies=True,
    ),
    _Segment(
        3,
        52,
        bytes.fromhex("00 00 60 61 00 00 a0 00 00 00 a0 00 00 00 00 00"),
        10_485_760,
        verifies=True,
    ),
    _Segment(
        4,
        56,
        bytes.fromhex("00 00 50 61 00 80 0b 00 00 00 0c 00 00 00 00 00"),
        753_664,
        verifies=True,
    ),
    _Segment(
        5,
        52,
        bytes.fromhex("62 00 20 60 02 00 00 00 00 00 00 00 00 00 00 00"),
        2,
        verifies=False,
        overlay_prefix=b"\xb0\x1d",
    ),
    _Segment(
        6,
        52,
        bytes.fromhex("40 00 20 60 20 00 00 00 00 00 00 00 00 00 00 00"),
        32,
        verifies=False,
        overlay_prefix=b"ZZzo..(-",
    ),
)

#: Stock DATA_0160: its descriptor has no version bytes, so every retained
#: trace records the loader answering mismatch=1 and the plan rewriting it.
_DATA_0160_INDEX = 3

#: Frames in the exact synthetic trace: the IMAGE_DATA and overlay sequence,
#: plus DATA_0160's BEGIN and ACK, 40,960 SEND_CHUNK and ACK pairs, and its
#: END and VERIFY pairs.
_EXACT_TRACE_FRAMES = 2_858 + 2 + 2 * 40_960 + 2 + 2

#: Default for ``_Trace(extra_body_segments=...)``: only the qualification's
#: own IMAGE_DATA and overlay transfers appear.
_NO_EXTRA_BODY_SEGMENTS: frozenset[int] = frozenset()

_CONFIG_ROWS = (
    ("tool_version", "0.0.test"),
    ("git_revision", "0123456789ab"),
    ("source_digest", _SOURCE_DIGEST),
    ("image", "/evidence/TH-D75_V103_stock_plaintext.KEX"),
    ("image_sha256", _IMAGE_SHA256),
    ("image_audit", "official TH-D75 V1.03 stock"),
    ("port", "/dev/cu.usbmodem-test"),
    ("port_open_baud", "576000"),
    ("unlock_path", "cleartext FPROMOD; framed traffic in plaintext (xor_key=0)"),
    (
        "baud_plan",
        "576000 (port open; FPROMOD at same rate); "
        "no further change during the data phase",
    ),
    (
        "baud_and_ack",
        "payload 12 01 = code 0x12 (declares 576000 baud), ack_each_data_packet=1",
    ),
    ("ack_policy", "per-packet ACK: every SEND_CHUNK waits for a loader reply"),
    (
        "reply_timeouts",
        "base 30s; SETUP/VERIFY add $CT; BEGIN adds $ET per response",
    ),
    ("chunk_size", "256 bytes per SEND_CHUNK"),
    ("segment_policy", "skip-current: the loader's SETUP equality answer decides"),
    ("qualification", "stock-selective-image-data"),
    ("forced_segments", "1"),
    (
        "qualification_target",
        "segment 1 IMAGE_DATA: 360448 bytes, 1408 packets, "
        f"payload_sha256={_IMAGE_DATA_SHA256}",
    ),
    ("completion", "0x1DB0 as LE u32 (b0 1d 00 00)"),
    ("plan", "7 segments, 15,269,922 bytes"),
    ("wire_trace", "/evidence/qualification.trace"),
    ("progress_interval", "every 256 chunks"),
)


class _Trace:
    def __init__(
        self,
        *,
        extra_body_segments: frozenset[int] = _NO_EXTRA_BODY_SEGMENTS,
        data_0160_result: int = 1,
    ) -> None:
        super().__init__()
        self.config = dict(_CONFIG_ROWS)
        self.notes: list[tuple[int, str]] = [
            (0, _BAUD_NOTE),
            (0, _UNLOCK_NOTE),
            (12, _FORCE_NOTE),
        ]
        self.records: list[_Record] = []
        self._pair(0x30, b"\x00")
        self._pair(0xA0, b"")
        self._add("TX", 0x31, 0, b"")
        self._add(
            "RX",
            0x32,
            17,
            bytes.fromhex("02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00"),
        )
        self._pair(0x33, b"\x12\x01")

        for segment in _SEGMENTS:
            if segment.index == _DATA_0160_INDEX:
                setup_result = data_0160_result
            elif segment.index in extra_body_segments or segment.index >= 5:
                setup_result = 1
            else:
                setup_result = 0
            self._add(
                "TX",
                0x40,
                segment.setup_length,
                segment.setup_prefix,
            )
            self._add("RX", 0x41, 1, bytes((setup_result,)))
            if segment.index == 1 or setup_result == 1:
                self._transfer(segment)
        self._pair(0x50, b"\xb0\x1d\x00\x00")

    def _add(
        self,
        direction: str,
        verb: int,
        payload_length: int,
        prefix: bytes,
    ) -> None:
        self.records.append(_Record(direction, verb, payload_length, prefix))

    def _ack(self) -> None:
        self._add("RX", 0x06, 0, b"")

    def _pair(self, verb: int, payload: bytes) -> None:
        self._add("TX", verb, len(payload), payload)
        self._ack()

    def _transfer(self, segment: _Segment) -> None:
        self._add("TX", 0x42, 0, b"")
        self._ack()
        chunk_count = segment.data_length // segment.chunk_size
        for chunk_index in range(chunk_count):
            offset = chunk_index * segment.chunk_size
            header = offset.to_bytes(4, "little") + segment.chunk_size.to_bytes(
                4,
                "little",
            )
            if segment.overlay_prefix is None:
                prefix = header + bytes((segment.index,)) * 8
            else:
                prefix = header + segment.overlay_prefix
            self._add("TX", 0x43, 8 + segment.chunk_size, prefix)
            self._ack()
        self._pair(0x44, b"")
        if segment.verifies:
            self._add("TX", 0x45, 0, b"")
            self._add("RX", 0x46, 1, b"\x00")

    def write(self, path: Path) -> None:
        width = max(len(key) for key, _ in _CONFIG_ROWS)
        lines = [
            f"# {TRACE_FORMAT_VERSION}",
            f"# {BANNER_START}",
            *(f"#   {key:<{width}} : {self.config[key]}" for key, _ in _CONFIG_ROWS),
            f"# {BANNER_END}",
            f"# columns: {TRACE_COLUMNS}",
            "# payload bytes are truncated to 16 for size",
        ]
        notes_by_record: dict[int, list[str]] = {}
        for records_before, text in self.notes:
            notes_by_record.setdefault(records_before, []).append(text)
        lines.extend(f"# {text}" for text in notes_by_record.get(0, []))
        for ordinal, record in enumerate(self.records, start=1):
            lines.append(
                f"{ordinal / 1000:.6f},{record.direction},0x{record.verb:02X},"
                f"{verb_label(record.direction, record.verb)},"
                f"{record.payload_length},{record.prefix.hex()}"
            )
            lines.extend(f"# {text}" for text in notes_by_record.get(ordinal, []))
        lines.append(f"# {len(self.records)} frames recorded")
        _ = path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _records(trace: _Trace, direction: str, verb: int) -> list[_Record]:
    return [
        record
        for record in trace.records
        if record.direction == direction and record.verb == verb
    ]


def test_validates_exact_selective_image_data_trace(tmp_path: Path) -> None:
    path = tmp_path / "qualification.trace"
    trace = _Trace()
    trace.write(path)

    result = validate_qualification_trace(path)

    assert result.frame_count == _EXACT_TRACE_FRAMES
    assert result.setup_results == (0, 0, 0, 1, 0, 1, 1)
    assert result.written_segment_indices == (1, 3, 5, 6)
    assert result.written_segment_names == (
        "IMAGE_DATA",
        "DATA_0160",
        "CHECKBYTES",
        "FINAL_ZZZ",
    )
    assert result.written_segment_count == 4
    assert result.chunks_written == 42_370
    assert result.bytes_written == 10_846_242


def test_real_flashconfig_wiretrace_and_session_are_validator_compatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stock_path = (
        Path(__file__).resolve().parents[1]
        / "recovery"
        / "TH-D75_V103_stock_plaintext.KEX"
    )
    if not stock_path.is_file():
        pytest.skip("exact stock plaintext KEX is absent from gitignored recovery/")
    plaintext = stock_path.read_bytes()
    assert hashlib.sha256(plaintext).hexdigest() == _IMAGE_SHA256
    image = kex.parse_kex_bytes(plaintext)
    segments = [SegmentDescriptor.from_kex_block(block) for block in image.blocks]
    segment_data = {
        index: intel_hex.parse(block.records).data
        for index, block in enumerate(image.blocks)
    }
    trace_path = tmp_path / "producer.trace"
    mode = negotiated_transfer_mode()
    config = FlashConfig(
        image=str(stock_path),
        image_sha256=_IMAGE_SHA256,
        image_label="official TH-D75 V1.03 stock",
        port="/dev/cu.usbmodem-test",
        open_baud=576_000,
        unlock_path="cleartext",
        unlock_baud=576_000,
        post_unlock_baud=None,
        baud_ladder=None,
        baud_and_ack_payload=mode.payload,
        transfer_mode_code=mode.code,
        transfer_declared_baud=mode.declared_baud,
        ack_each_data_packet=mode.ack_each_data_packet,
        base_reply_timeout_seconds=30.0,
        chunk_size=256,
        force_all_segments=False,
        forced_segment_indices=(1,),
        qualification="stock-selective-image-data",
        qualification_target=(
            "segment 1 IMAGE_DATA: 360448 bytes, 1408 packets, "
            f"payload_sha256={_IMAGE_DATA_SHA256}"
        ),
        complete_update_value=0x1DB0,
        complete_update_width=4,
        segment_count=7,
        planned_bytes=15_269_922,
        wire_trace_path=str(trace_path),
        progress_every_chunks=0,
        tool_version="0.0.test",
        git_revision="0123456789ab",
        source_digest=_SOURCE_DIGEST,
    )
    # The retained qualification attempt's SETUP answers: DATA_0160 mismatch.
    radio = _SetupSequenceRadio(
        (b"\x00", b"\x00", b"\x00", b"\x01", b"\x00", b"\x01", b"\x01")
    )
    monkeypatch.setattr(
        qualification_module,
        "_IMAGE_DATA_SAMPLE_SHA256",
        _PRODUCTION_SAMPLE_SHA256,
    )

    with WireTrace(trace_path, header_lines=config.comment_lines()) as wire_trace:
        outcome = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, progress_every_chunks=0),
            trace=wire_trace,
        ).flash_segments(
            segments,
            segment_data,
            FlashRunOptions(
                always_flash=False,
                force_segment_indices=frozenset({1}),
                cleartext_unlock=True,
                cleartext_baud=576_000,
            ),
        )

    result = validate_qualification_trace(trace_path)
    assert outcome.segments_written == 4
    assert outcome.bytes_written == 10_846_242
    assert result.written_segment_indices == (1, 3, 5, 6)
    assert result.chunks_written == 42_370
    assert result.bytes_written == 10_846_242


def test_rejects_missing_or_contradictory_runtime_observations(
    tmp_path: Path,
) -> None:
    keyed_path = tmp_path / "keyed.trace"
    trace = _Trace()
    trace.notes[1] = (0, "unlocked at baud 9600 via keyed path")
    trace.write(keyed_path)

    with pytest.raises(QualificationError, match="runtime note"):
        _ = validate_qualification_trace(keyed_path)

    missing_force_path = tmp_path / "missing-force.trace"
    trace = _Trace()
    _ = trace.notes.pop()
    trace.write(missing_force_path)

    with pytest.raises(QualificationError, match="force-write runtime note"):
        _ = validate_qualification_trace(missing_force_path)


def test_rejects_fabricated_visible_image_data_samples(tmp_path: Path) -> None:
    path = tmp_path / "fabricated-visible-data.trace"
    trace = _Trace()
    first_image_chunk = _records(trace, "TX", 0x43)[0]
    first_image_chunk.prefix = first_image_chunk.prefix[:-1] + b"\x02"
    trace.write(path)

    with pytest.raises(QualificationError, match="sample SHA-256"):
        _ = validate_qualification_trace(path)


def test_accepts_busy_frames_before_begin_ack(tmp_path: Path) -> None:
    path = tmp_path / "qualification-with-busy.trace"
    trace = _Trace()
    image_begin = trace.records.index(_records(trace, "TX", 0x42)[0])
    trace.records[image_begin + 1 : image_begin + 1] = [
        _Record("RX", 0x11, 0, b""),
        _Record("RX", 0x11, 0, b""),
    ]
    trace.write(path)

    result = validate_qualification_trace(path)

    assert result.frame_count == _EXACT_TRACE_FRAMES + 2
    assert result.written_segment_indices == (1, 3, 5, 6)


def test_rejects_data_0160_reported_current(tmp_path: Path) -> None:
    path = tmp_path / "qualification-data-0160-current.trace"
    trace = _Trace(data_0160_result=0)
    trace.write(path)

    with pytest.raises(QualificationError, match="DATA_0160 must report mismatch=1"):
        _ = validate_qualification_trace(path)


def test_rejects_additional_stock_body_restoration_as_nonqualification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "qualification-with-font.trace"
    trace = _Trace(extra_body_segments=frozenset({4}))
    trace.write(path)

    with pytest.raises(QualificationError, match="narrow qualification"):
        _ = validate_qualification_trace(path)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("image_sha256", "0" * 64),
        ("image_audit", "unpinned"),
        ("port_open_baud", "9600"),
        ("source_digest", "abcdef012345"),
        ("chunk_size", "1024 bytes per SEND_CHUNK"),
        ("forced_segments", "none"),
        (
            "qualification_target",
            "segment 1 IMAGE_DATA; 360448 bytes; 1408 packets; "
            f"payload_sha256={_IMAGE_DATA_SHA256}",
        ),
        ("completion", "0x1DB0 as LE u16 (b0 1d)"),
    ],
)
def test_rejects_nonqualification_flash_config(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    path = tmp_path / f"bad-{key}.trace"
    trace = _Trace()
    trace.config[key] = value
    trace.write(path)

    with pytest.raises(QualificationError, match=key):
        _ = validate_qualification_trace(path)


def test_rejects_when_local_source_fingerprint_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "no-local-source-fingerprint.trace"
    trace = _Trace()
    trace.write(path)
    monkeypatch.setattr(
        qualification_module,
        "flasher_source_digest",
        lambda: "unavailable",
    )

    with pytest.raises(QualificationError, match="cannot fingerprint"):
        _ = validate_qualification_trace(path)


def test_rejects_select_target_even_when_rest_of_sequence_is_valid(
    tmp_path: Path,
) -> None:
    path = tmp_path / "select.trace"
    trace = _Trace()
    baud_ack_index = trace.records.index(_records(trace, "TX", 0x33)[0])
    trace.records.insert(baud_ack_index + 2, _Record("TX", 0xA3, 0, b""))
    trace.write(path)

    with pytest.raises(QualificationError, match="SELECT_TARGET"):
        _ = validate_qualification_trace(path)


def test_rejects_setup_descriptor_prefix_or_order(tmp_path: Path) -> None:
    path = tmp_path / "wrong-setup.trace"
    trace = _Trace()
    setups = _records(trace, "TX", 0x40)
    setups[0].prefix = _SEGMENTS[1].setup_prefix
    trace.write(path)

    with pytest.raises(QualificationError, match="stock SETUP segment 0"):
        _ = validate_qualification_trace(path)


def test_requires_image_data_to_exercise_selective_current_override(
    tmp_path: Path,
) -> None:
    path = tmp_path / "image-mismatch.trace"
    trace = _Trace()
    _records(trace, "RX", 0x41)[1].prefix = b"\x01"
    trace.write(path)

    with pytest.raises(QualificationError, match="selective force-write"):
        _ = validate_qualification_trace(path)


def test_rejects_nonmonotonic_image_chunk_offset(tmp_path: Path) -> None:
    path = tmp_path / "bad-offset.trace"
    trace = _Trace()
    image_chunks = _records(trace, "TX", 0x43)
    image_chunks[1].prefix = (512).to_bytes(4, "little") + image_chunks[1].prefix[4:]
    trace.write(path)

    with pytest.raises(QualificationError, match="offset 256"):
        _ = validate_qualification_trace(path)


def test_requires_immediate_ack_after_every_image_chunk(tmp_path: Path) -> None:
    path = tmp_path / "late-ack.trace"
    trace = _Trace()
    first_chunk = trace.records.index(_records(trace, "TX", 0x43)[0])
    trace.records[first_chunk + 1], trace.records[first_chunk + 2] = (
        trace.records[first_chunk + 2],
        trace.records[first_chunk + 1],
    )
    trace.write(path)

    with pytest.raises(QualificationError, match="immediate SEND_CHUNK ACK"):
        _ = validate_qualification_trace(path)


def test_rejects_duplicate_end_or_failed_verify(tmp_path: Path) -> None:
    duplicate_end_path = tmp_path / "duplicate-end.trace"
    trace = _Trace()
    first_end = trace.records.index(_records(trace, "TX", 0x44)[0])
    trace.records[first_end + 2 : first_end + 2] = [
        _Record("TX", 0x44, 0, b""),
        _Record("RX", 0x06, 0, b""),
    ]
    trace.write(duplicate_end_path)

    with pytest.raises(QualificationError, match="VERIFY_SEGMENT"):
        _ = validate_qualification_trace(duplicate_end_path)

    failed_verify_path = tmp_path / "failed-verify.trace"
    trace = _Trace()
    _records(trace, "RX", 0x46)[0].prefix = b"\x01"
    trace.write(failed_verify_path)

    with pytest.raises(QualificationError, match="VERIFY_SEGMENT result"):
        _ = validate_qualification_trace(failed_verify_path)


def test_rejects_wrong_overlay_or_completion_payload(tmp_path: Path) -> None:
    overlay_path = tmp_path / "wrong-overlay.trace"
    trace = _Trace()
    # The CHECKBYTES overlay is the one SEND_CHUNK carrying its b0 1d payload.
    checkbytes_chunk = next(
        record
        for record in _records(trace, "TX", 0x43)
        if record.prefix.endswith(b"\xb0\x1d")
    )
    checkbytes_chunk.prefix = b"\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00"
    trace.write(overlay_path)

    with pytest.raises(QualificationError, match="CHECKBYTES SEND_CHUNK"):
        _ = validate_qualification_trace(overlay_path)

    completion_path = tmp_path / "u16-completion.trace"
    trace = _Trace()
    complete = _records(trace, "TX", 0x50)[0]
    complete.payload_length = 2
    complete.prefix = b"\xb0\x1d"
    trace.write(completion_path)

    with pytest.raises(QualificationError, match="u32 stock COMPLETE_UPDATE"):
        _ = validate_qualification_trace(completion_path)


def test_rejects_incomplete_footer_and_cli_returns_nonzero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid_path = tmp_path / "valid.trace"
    trace = _Trace()
    trace.write(valid_path)

    assert main([str(valid_path)]) == 0
    assert capsys.readouterr().out.startswith("VALID:")

    invalid_path = tmp_path / "invalid.trace"
    contents = valid_path.read_text(encoding="utf-8")
    _ = invalid_path.write_text(
        contents.rsplit("\n# ", 1)[0] + "\n",
        encoding="utf-8",
    )
    assert main([str(invalid_path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("INVALID:")
    assert "frames recorded" in captured.err
