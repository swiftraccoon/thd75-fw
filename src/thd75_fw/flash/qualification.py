"""Offline validator for the stock selective IMAGE_DATA qualification trace.

The validator is intentionally narrower than a general wire-trace reader.  A
valid result proves that the completed trace has the exact configuration and
command shape admitted by ``--qualification-rewrite-stock-image-data``:

* the audited stock V1.03 image and direct-open 576000/ACK/256 profile;
* seven stock SETUP descriptors in their original order;
* a selectively forced write of segment 1 (IMAGE_DATA);
* the loader's mismatch=1 answer for segment 3 (DATA_0160), whose stock
  descriptor carries no version bytes, and that segment's stock rewrite;
* current/skipped results for every other stock body segment;
* the two normal stock finalization overlays; and
* the successful u32 completion sequence.

Wire-trace v1 retains only the first 16 payload bytes.  Consequently this file
can prove every command header, length, offset, response and ordering decision,
and pins a hash over the eight retained IMAGE_DATA bytes per chunk, but it
cannot independently hash each chunk's unrecorded bytes.  The FlashConfig image
and qualification hashes pin that full artifact.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .diagnostics import (
    BANNER_END,
    BANNER_START,
    TRACE_COLUMNS,
    TRACE_FORMAT_VERSION,
    TRACE_HEX_PREFIX_BYTES,
    flasher_source_digest,
    verb_label,
)

_ACK: Final[int] = 0x06
_BUSY: Final[int] = 0x11
_ENTER_PROGRAM: Final[int] = 0x30
_QUERY_TARGET: Final[int] = 0x31
_QUERY_TARGET_REPLY: Final[int] = 0x32
_BAUD_AND_ACK: Final[int] = 0x33
_SETUP_SEGMENT: Final[int] = 0x40
_SETUP_SEGMENT_REPLY: Final[int] = 0x41
_BEGIN_TRANSFER: Final[int] = 0x42
_SEND_CHUNK: Final[int] = 0x43
_END_TRANSFER: Final[int] = 0x44
_VERIFY_SEGMENT: Final[int] = 0x45
_VERIFY_SEGMENT_REPLY: Final[int] = 0x46
_COMPLETE_UPDATE: Final[int] = 0x50
_TIMED_SESSION: Final[int] = 0xA0
_SELECT_TARGET: Final[int] = 0xA3

_STOCK_IMAGE_SHA256: Final[str] = (
    "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
)
_STOCK_IMAGE_LABEL: Final[str] = "official TH-D75 V1.03 stock"
_IMAGE_DATA_SHA256: Final[str] = (
    "cd86abd837cd8cdf2b781148eec52d9cb39ce11f8b6b7d13e2f380669d652fb2"
)
_IMAGE_DATA_SAMPLE_SHA256: Final[str] = (
    "442afc3ff3ad56879e8c218e4f8e87ffa44811426144ca1f0f66b4dff0a1f2ab"
)
_QUALIFICATION_NAME: Final[str] = "stock-selective-image-data"
_QUALIFICATION_TARGET: Final[str] = (
    "segment 1 IMAGE_DATA: 360448 bytes, 1408 packets, "
    f"payload_sha256={_IMAGE_DATA_SHA256}"
)
_COMPLETE_PAYLOAD: Final[bytes] = b"\xb0\x1d\x00\x00"
_QUERY_TARGET_PREFIX: Final[bytes] = (
    b"\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
)

_CONFIG_KEYS: Final[tuple[str, ...]] = (
    "tool_version",
    "git_revision",
    "source_digest",
    "image",
    "image_sha256",
    "image_audit",
    "port",
    "port_open_baud",
    "unlock_path",
    "baud_plan",
    "baud_and_ack",
    "ack_policy",
    "reply_timeouts",
    "chunk_size",
    "segment_policy",
    "qualification",
    "forced_segments",
    "qualification_target",
    "completion",
    "plan",
    "wire_trace",
    "progress_interval",
)

_EXACT_CONFIG: Final[dict[str, str]] = {
    "image_sha256": _STOCK_IMAGE_SHA256,
    "image_audit": _STOCK_IMAGE_LABEL,
    "port_open_baud": "576000",
    "unlock_path": "cleartext FPROMOD; framed traffic in plaintext (xor_key=0)",
    "baud_plan": (
        "576000 (port open; FPROMOD at same rate); "
        "no further change during the data phase"
    ),
    "baud_and_ack": (
        "payload 12 01 = code 0x12 (declares 576000 baud), ack_each_data_packet=1"
    ),
    "ack_policy": "per-packet ACK: every SEND_CHUNK waits for a loader reply",
    "reply_timeouts": ("base 30s; SETUP/VERIFY add $CT; BEGIN adds $ET per response"),
    "chunk_size": "256 bytes per SEND_CHUNK",
    "segment_policy": "skip-current: the loader's SETUP equality answer decides",
    "qualification": _QUALIFICATION_NAME,
    "forced_segments": "1",
    "qualification_target": _QUALIFICATION_TARGET,
    "completion": "0x1DB0 as LE u32 (b0 1d 00 00)",
    "plan": "7 segments, 15,269,922 bytes",
}

_CONFIG_ROW_RE: Final[re.Pattern[str]] = re.compile(r"^#   ([a-z][a-z0-9_]*) +: (.*)$")
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(r"^(0|[1-9][0-9]*)\.([0-9]{6})$")
_VERB_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9A-F]{2}$")
_LENGTH_RE: Final[re.Pattern[str]] = re.compile(r"^(0|[1-9][0-9]*)$")
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]*$")
_FOOTER_RE: Final[re.Pattern[str]] = re.compile(r"^# (0|[1-9][0-9]*) frames recorded$")
_SHORT_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{12}$")
_PROGRESS_RE: Final[re.Pattern[str]] = re.compile(r"^(?:off|every [1-9][0-9]* chunks)$")
_BAUD_NOTE: Final[str] = "baud -> 576000 (set before cleartext FPROMOD)"
_UNLOCK_NOTE: Final[str] = "unlocked at baud 576000 via cleartext path"
_FORCE_NOTE: Final[str] = "segment_1 setup=current; qualification force-write"

#: Lines ahead of the first FlashConfig row: the format-version line and the
#: banner opener.
_HEADER_PREAMBLE_LINES: Final[int] = 2

#: Columns in one wire-trace v1 record: ``t_seconds``, ``dir``, ``verb``,
#: ``verb_name``, ``payload_len`` and ``hex_prefix``.
_TRACE_V1_COLUMN_COUNT: Final[int] = 6

#: Records that precede the force-write note: the four two-record entry
#: exchanges (ENTER_PROGRAM, TIMED_SESSION, QUERY_TARGET, BAUD_AND_ACK) and the
#: SETUP request/result pairs of segments 0 and 1.
_FORCE_NOTE_RECORDS_BEFORE: Final[int] = 12

#: Stock body segment the loader requests on every run. Its descriptor has
#: $VL=0 and an empty $VA, so SETUP can never report it current: every
#: retained trace that sends it records mismatch=1, and the stock plan then
#: rewrites it with its unchanged stock payload.
_ALWAYS_REQUESTED_SEGMENT_INDEX: Final[int] = 3

#: Index of the first stock finalization overlay. Segments 5 (CHECKBYTES) and
#: 6 (FINAL_ZZZ) take their normal mismatch=1 transfer path.
_FIRST_OVERLAY_SEGMENT_INDEX: Final[int] = 5

#: SEND_CHUNK packets the qualification writes: IMAGE_DATA's 1,408 and
#: DATA_0160's 40,960 256-byte packets, plus one packet each for CHECKBYTES
#: and FINAL_ZZZ.
_QUALIFICATION_CHUNKS_WRITTEN: Final[int] = 42_370

#: Data bytes the qualification writes: IMAGE_DATA's 360,448 and DATA_0160's
#: 10,485,760 bytes, plus the 2-byte CHECKBYTES and 32-byte FINAL_ZZZ
#: overlays.
_QUALIFICATION_BYTES_WRITTEN: Final[int] = 10_846_242


class QualificationError(ValueError):
    """The trace is incomplete or differs from the qualification contract."""


@dataclass(frozen=True, slots=True)
class QualificationResult:
    """Summary of a successfully validated qualification trace."""

    trace_path: Path
    frame_count: int
    setup_results: tuple[int, ...]
    written_segment_indices: tuple[int, ...]
    written_segment_names: tuple[str, ...]
    chunks_written: int
    bytes_written: int

    @property
    def written_segment_count(self) -> int:
        """Number of segments whose transfer sequence appears in the trace."""
        return len(self.written_segment_indices)


@dataclass(frozen=True, slots=True)
class _StockSegment:
    index: int
    name: str
    setup_payload_length: int
    setup_prefix: bytes
    data_length: int
    verifies: bool
    overlay_prefix: bytes | None = None

    @property
    def chunk_size(self) -> int:
        return min(256, self.data_length)

    @property
    def chunk_count(self) -> int:
        return self.data_length // self.chunk_size


_STOCK_SEGMENTS: Final[tuple[_StockSegment, ...]] = (
    _StockSegment(
        0,
        "FIRMWARE",
        67,
        bytes.fromhex("00 00 20 60 00 00 28 00 00 00 28 00 00 00 00 00"),
        2_621_440,
        verifies=True,
    ),
    _StockSegment(
        1,
        "IMAGE_DATA",
        62,
        bytes.fromhex("00 00 60 60 00 80 05 00 00 00 06 00 00 00 00 00"),
        360_448,
        verifies=True,
    ),
    _StockSegment(
        2,
        "DSP",
        64,
        bytes.fromhex("00 00 e0 60 00 00 10 00 00 00 10 00 00 00 00 00"),
        1_048_576,
        verifies=True,
    ),
    _StockSegment(
        3,
        "DATA_0160",
        52,
        bytes.fromhex("00 00 60 61 00 00 a0 00 00 00 a0 00 00 00 00 00"),
        10_485_760,
        verifies=True,
    ),
    _StockSegment(
        4,
        "FONT",
        56,
        bytes.fromhex("00 00 50 61 00 80 0b 00 00 00 0c 00 00 00 00 00"),
        753_664,
        verifies=True,
    ),
    _StockSegment(
        5,
        "CHECKBYTES",
        52,
        bytes.fromhex("62 00 20 60 02 00 00 00 00 00 00 00 00 00 00 00"),
        2,
        verifies=False,
        overlay_prefix=b"\xb0\x1d",
    ),
    _StockSegment(
        6,
        "FINAL_ZZZ",
        52,
        bytes.fromhex("40 00 20 60 20 00 00 00 00 00 00 00 00 00 00 00"),
        32,
        verifies=False,
        overlay_prefix=b"ZZzo..(-",
    ),
)


@dataclass(frozen=True, slots=True)
class _TraceRecord:
    ordinal: int
    line_number: int
    timestamp_us: int
    direction: str
    verb: int
    payload_length: int
    payload_prefix: bytes

    @property
    def summary(self) -> str:
        return (
            f"{self.direction} 0x{self.verb:02X} "
            f"({verb_label(self.direction, self.verb)})"
        )


@dataclass(frozen=True, slots=True)
class _TraceNote:
    line_number: int
    records_before: int
    text: str


@dataclass(frozen=True, slots=True)
class _ParsedTrace:
    config: dict[str, str]
    records: tuple[_TraceRecord, ...]
    notes: tuple[_TraceNote, ...]
    footer_count: int


class _Cursor:
    def __init__(self, records: tuple[_TraceRecord, ...]) -> None:
        super().__init__()
        self._records = records
        self._position = 0

    @property
    def at_end(self) -> bool:
        return self._position == len(self._records)

    def peek(self) -> _TraceRecord | None:
        if self.at_end:
            return None
        return self._records[self._position]

    def expect(
        self,
        direction: str,
        verb: int,
        *,
        purpose: str,
        payload_length: int,
        payload_prefix: bytes | None = None,
    ) -> _TraceRecord:
        """Consume the next record, requiring its direction, verb and length.

        ``payload_prefix``, when given, must equal the retained prefix
        exactly. A caller that only knows how the prefix starts checks that
        with :func:`_require_prefix_start` on the returned record.

        Raises:
            QualificationError: If the trace ended or the record differs.

        """
        record = self.peek()
        if record is None:
            msg = f"after frame {self._position}: trace ended before {purpose}"
            raise QualificationError(msg)
        expected = f"{direction} 0x{verb:02X} ({verb_label(direction, verb)})"
        if record.direction != direction or record.verb != verb:
            msg = (
                f"frame {record.ordinal} (line {record.line_number}): "
                f"expected {purpose}: {expected}; got {record.summary}"
            )
            raise QualificationError(msg)
        if record.payload_length != payload_length:
            msg = (
                f"frame {record.ordinal} ({purpose}): expected payload length "
                f"{payload_length}, got {record.payload_length}"
            )
            raise QualificationError(msg)
        if payload_prefix is not None and record.payload_prefix != payload_prefix:
            msg = (
                f"frame {record.ordinal} ({purpose}): expected payload prefix "
                f"{payload_prefix.hex(' ') or '<empty>'}, got "
                f"{record.payload_prefix.hex(' ') or '<empty>'}"
            )
            raise QualificationError(msg)
        self._position += 1
        return record

    def require_end(self) -> None:
        record = self.peek()
        if record is not None:
            msg = (
                f"frame {record.ordinal} (line {record.line_number}): "
                f"unexpected record after COMPLETE_UPDATE ACK: {record.summary}"
            )
            raise QualificationError(msg)


def _require_prefix_start(record: _TraceRecord, *, purpose: str, prefix: bytes) -> None:
    """Require a consumed record's retained payload prefix to start with ``prefix``.

    Raises:
        QualificationError: If the retained prefix starts any other way.

    """
    if not record.payload_prefix.startswith(prefix):
        msg = (
            f"frame {record.ordinal} ({purpose}): expected payload prefix "
            f"to start with {prefix.hex(' ')}, got "
            f"{record.payload_prefix.hex(' ') or '<empty>'}"
        )
        raise QualificationError(msg)


def validate_qualification_trace(path: Path | str) -> QualificationResult:
    """Validate one completed stock selective-IMAGE_DATA wire trace.

    Raises:
        OSError: The trace cannot be read.
        UnicodeError: The trace is not valid UTF-8.
        QualificationError: The header, record encoding, or flash sequence
            differs from the exact qualification contract.

    """
    trace_path = Path(path)
    parsed = _parse_trace(trace_path.read_text(encoding="utf-8"))
    _validate_config(parsed.config)

    for record in parsed.records:
        if record.verb == _SELECT_TARGET:
            msg = (
                f"frame {record.ordinal}: SELECT_TARGET is forbidden in the "
                "hardware-proven D75 sequence"
            )
            raise QualificationError(msg)
    _validate_runtime_notes(parsed.notes)

    (
        setup_results,
        written_segments,
        chunks_written,
        bytes_written,
    ) = _validate_records(parsed.records)
    names = tuple(_STOCK_SEGMENTS[index].name for index in written_segments)
    return QualificationResult(
        trace_path=trace_path,
        frame_count=parsed.footer_count,
        setup_results=setup_results,
        written_segment_indices=written_segments,
        written_segment_names=names,
        chunks_written=chunks_written,
        bytes_written=bytes_written,
    )


def _parse_trace(text: str) -> _ParsedTrace:
    lines = text.splitlines()
    if not lines:
        msg = "trace is empty"
        raise QualificationError(msg)
    if any(not line for line in lines):
        msg = "blank lines are not valid wire-trace v1 records"
        raise QualificationError(msg)
    config, first_record_line = _parse_trace_header(lines)
    records, notes, footer_count = _parse_trace_body(lines, first_record_line)
    return _ParsedTrace(config, tuple(records), tuple(notes), footer_count)


def _parse_trace_header(lines: list[str]) -> tuple[dict[str, str], int]:
    """Parse the version line, FlashConfig banner, and column/truncation lines.

    Returns:
        The FlashConfig rows by key, and the index of the first line after
        the header.

    Raises:
        QualificationError: If any header line is missing or non-canonical.

    """
    if lines[0] != f"# {TRACE_FORMAT_VERSION}":
        msg = f"expected first line '# {TRACE_FORMAT_VERSION}', got {lines[0]!r}"
        raise QualificationError(msg)
    if len(lines) < _HEADER_PREAMBLE_LINES or lines[1] != f"# {BANNER_START}":
        msg = "FlashConfig banner is missing after trace version"
        raise QualificationError(msg)

    config, position = _parse_config_banner(lines)
    position += 1
    expected_columns = f"# columns: {TRACE_COLUMNS}"
    if position >= len(lines) or lines[position] != expected_columns:
        msg = f"expected {expected_columns!r} after FlashConfig"
        raise QualificationError(msg)
    position += 1
    expected_truncation = (
        f"# payload bytes are truncated to {TRACE_HEX_PREFIX_BYTES} for size"
    )
    if position >= len(lines) or lines[position] != expected_truncation:
        msg = f"expected {expected_truncation!r} after trace columns"
        raise QualificationError(msg)
    return config, position + 1


def _parse_config_banner(lines: list[str]) -> tuple[dict[str, str], int]:
    """Parse the FlashConfig rows between the banner markers.

    Returns:
        The rows by key, and the index of the banner end marker.

    Raises:
        QualificationError: If a row is malformed or repeated, the end marker
            is missing, or the keys differ from the v1 schema or its order.

    """
    config: dict[str, str] = {}
    config_order: list[str] = []
    position = _HEADER_PREAMBLE_LINES
    while position < len(lines) and lines[position] != f"# {BANNER_END}":
        match = _CONFIG_ROW_RE.fullmatch(lines[position])
        if match is None:
            msg = f"line {position + 1}: malformed FlashConfig row"
            raise QualificationError(msg)
        key, value = match.groups()
        if key in config:
            msg = f"line {position + 1}: duplicate FlashConfig key {key!r}"
            raise QualificationError(msg)
        config[key] = value
        config_order.append(key)
        position += 1
    if position >= len(lines):
        msg = "FlashConfig banner has no end marker"
        raise QualificationError(msg)
    if tuple(config_order) != _CONFIG_KEYS:
        msg = (
            "FlashConfig keys/order differ from the wire-trace v1 qualification "
            f"schema: expected {', '.join(_CONFIG_KEYS)}; got "
            f"{', '.join(config_order) or '<none>'}"
        )
        raise QualificationError(msg)
    return config, position


def _parse_trace_body(
    lines: list[str],
    first_line: int,
) -> tuple[list[_TraceRecord], list[_TraceNote], int]:
    """Parse the records, runtime notes, and frame-count footer after the header.

    Returns:
        The records in order, the notes with their positions, and the footer
        count.

    Raises:
        QualificationError: If a line is malformed, a timestamp moves
            backwards, or the footer is missing, repeated, not last, or
            disagrees with the record count.

    """
    records: list[_TraceRecord] = []
    notes: list[_TraceNote] = []
    footer_count: int | None = None
    previous_timestamp_us = -1
    for line_index in range(first_line, len(lines)):
        line = lines[line_index]
        if line.startswith("#"):
            footer_match = _FOOTER_RE.fullmatch(line)
            if footer_match is not None:
                footer_count = _parse_footer_count(
                    footer_match,
                    line_index=line_index,
                    line_count=len(lines),
                    previous_count=footer_count,
                )
            else:
                notes.append(
                    _parse_note(
                        line, line_index=line_index, records_before=len(records)
                    )
                )
            continue
        if footer_count is not None:
            msg = f"line {line_index + 1}: record appears after frame-count footer"
            raise QualificationError(msg)
        record = _parse_record(
            line,
            line_number=line_index + 1,
            ordinal=len(records) + 1,
        )
        if record.timestamp_us < previous_timestamp_us:
            msg = (
                f"frame {record.ordinal}: timestamp moved backwards "
                f"({record.timestamp_us} < {previous_timestamp_us} microseconds)"
            )
            raise QualificationError(msg)
        previous_timestamp_us = record.timestamp_us
        records.append(record)

    if footer_count is None:
        msg = "completed trace is missing the final '# N frames recorded' footer"
        raise QualificationError(msg)
    if footer_count != len(records):
        msg = f"frame-count footer says {footer_count}, parsed {len(records)} records"
        raise QualificationError(msg)
    return records, notes, footer_count


def _parse_footer_count(
    footer_match: re.Match[str],
    *,
    line_index: int,
    line_count: int,
    previous_count: int | None,
) -> int:
    """Return the frame count of the one footer, which must be the last line.

    Raises:
        QualificationError: If a footer was already seen or this one is not
            the final line.

    """
    if previous_count is not None:
        msg = f"line {line_index + 1}: duplicate frame-count footer"
        raise QualificationError(msg)
    if line_index != line_count - 1:
        msg = f"line {line_index + 1}: frame-count footer must be last"
        raise QualificationError(msg)
    return int(footer_match.group(1))


def _parse_note(line: str, *, line_index: int, records_before: int) -> _TraceNote:
    """Parse one ``# text`` runtime note and remember where it fell.

    Raises:
        QualificationError: If the comment is not in the canonical ``# ``
            form.

    """
    if not line.startswith("# "):
        msg = f"line {line_index + 1}: non-canonical trace comment"
        raise QualificationError(msg)
    return _TraceNote(
        line_number=line_index + 1,
        records_before=records_before,
        text=line[2:],
    )


def _parse_record(line: str, *, line_number: int, ordinal: int) -> _TraceRecord:
    try:
        fields = next(csv.reader([line], strict=True))
    except csv.Error as exc:
        msg = f"line {line_number}: malformed CSV record: {exc}"
        raise QualificationError(msg) from exc
    if len(fields) != _TRACE_V1_COLUMN_COUNT:
        msg = (
            f"line {line_number}: expected {_TRACE_V1_COLUMN_COUNT} trace columns, "
            f"got {len(fields)}"
        )
        raise QualificationError(msg)
    if ",".join(fields) != line:
        msg = f"line {line_number}: quoted or otherwise non-canonical CSV record"
        raise QualificationError(msg)
    timestamp_text, direction, verb_text, name, length_text, prefix_text = fields

    timestamp_us = _parse_timestamp_us(timestamp_text, line_number=line_number)
    if direction not in {"TX", "RX"}:
        msg = f"line {line_number}: direction must be TX or RX, got {direction!r}"
        raise QualificationError(msg)
    if _VERB_RE.fullmatch(verb_text) is None:
        msg = f"line {line_number}: non-canonical verb byte {verb_text!r}"
        raise QualificationError(msg)
    verb = int(verb_text, 0)
    expected_name = verb_label(direction, verb)
    if name != expected_name:
        msg = (
            f"line {line_number}: verb name {name!r} does not match "
            f"{direction} {verb_text} ({expected_name})"
        )
        raise QualificationError(msg)
    if _LENGTH_RE.fullmatch(length_text) is None:
        msg = f"line {line_number}: non-canonical payload length {length_text!r}"
        raise QualificationError(msg)
    payload_length = int(length_text)
    payload_prefix = _parse_payload_prefix(
        prefix_text,
        payload_length=payload_length,
        line_number=line_number,
    )
    return _TraceRecord(
        ordinal,
        line_number,
        timestamp_us,
        direction,
        verb,
        payload_length,
        payload_prefix,
    )


def _parse_timestamp_us(timestamp_text: str, *, line_number: int) -> int:
    """Convert a canonical ``seconds.micros`` timestamp to whole microseconds.

    Raises:
        QualificationError: If the text is not in the canonical six-decimal
            form.

    """
    timestamp_match = _TIMESTAMP_RE.fullmatch(timestamp_text)
    if timestamp_match is None:
        msg = f"line {line_number}: non-canonical timestamp {timestamp_text!r}"
        raise QualificationError(msg)
    return int(timestamp_match.group(1)) * 1_000_000 + int(timestamp_match.group(2))


def _parse_payload_prefix(
    prefix_text: str,
    *,
    payload_length: int,
    line_number: int,
) -> bytes:
    """Decode the retained payload prefix and check its length against the frame.

    Raises:
        QualificationError: If the prefix is not lowercase hex of whole bytes,
            or does not retain ``min(payload_length, 16)`` bytes.

    """
    if _HEX_RE.fullmatch(prefix_text) is None or len(prefix_text) % 2:
        msg = (
            f"line {line_number}: invalid lowercase hex payload prefix {prefix_text!r}"
        )
        raise QualificationError(msg)
    payload_prefix = bytes.fromhex(prefix_text)
    expected_prefix_length = min(payload_length, TRACE_HEX_PREFIX_BYTES)
    if len(payload_prefix) != expected_prefix_length:
        msg = (
            f"line {line_number}: payload length {payload_length} requires "
            f"{expected_prefix_length} retained prefix bytes, got "
            f"{len(payload_prefix)}"
        )
        raise QualificationError(msg)
    return payload_prefix


def _validate_config(config: dict[str, str]) -> None:
    for key, expected in _EXACT_CONFIG.items():
        actual = config[key]
        if actual != expected:
            msg = f"FlashConfig {key!r} must be {expected!r}, got {actual!r}"
            raise QualificationError(msg)
    _validate_build_identity(config)
    _validate_run_identity(config)


def _validate_build_identity(config: dict[str, str]) -> None:
    """Require the tool version, revision and source digest to be well formed.

    The source digest must also match the flasher sources doing the
    validation.

    Raises:
        QualificationError: If any of the three is malformed, or the digest
            cannot be computed locally or differs from the local one.

    """
    if not config["tool_version"] or any(c.isspace() for c in config["tool_version"]):
        msg = "FlashConfig 'tool_version' must be nonempty"
        raise QualificationError(msg)
    git_revision = config["git_revision"]
    if (
        git_revision != "unavailable"
        and _SHORT_DIGEST_RE.fullmatch(git_revision) is None
    ):
        msg = (
            "FlashConfig 'git_revision' must be a 12-digit lowercase hex "
            "revision or 'unavailable'"
        )
        raise QualificationError(msg)
    source_digest = config["source_digest"]
    if _SHORT_DIGEST_RE.fullmatch(source_digest) is None:
        msg = "FlashConfig 'source_digest' must pin 12 lowercase hex digits"
        raise QualificationError(msg)
    expected_source_digest = flasher_source_digest()
    if expected_source_digest == "unavailable":
        msg = "cannot fingerprint the local flasher sources used for validation"
        raise QualificationError(msg)
    if source_digest != expected_source_digest:
        msg = (
            "FlashConfig 'source_digest' does not match the local flasher "
            f"sources: trace has {source_digest}, local code has "
            f"{expected_source_digest}"
        )
        raise QualificationError(msg)


def _validate_run_identity(config: dict[str, str]) -> None:
    """Require the image, port, trace path and progress rows of a real run.

    Raises:
        QualificationError: If any of the four is absent or not in the form
            a qualification run renders.

    """
    if not config["image"].endswith(".KEX"):
        msg = "FlashConfig 'image' must name the stock plaintext .KEX input"
        raise QualificationError(msg)
    if not config["port"] or config["port"] == "<none>":
        msg = "FlashConfig 'port' must name the opened device"
        raise QualificationError(msg)
    if not config["wire_trace"] or config["wire_trace"] == "off":
        msg = "FlashConfig 'wire_trace' must retain the qualification evidence path"
        raise QualificationError(msg)
    if _PROGRESS_RE.fullmatch(config["progress_interval"]) is None:
        msg = "FlashConfig 'progress_interval' has an invalid rendered value"
        raise QualificationError(msg)


def _validate_runtime_notes(notes: tuple[_TraceNote, ...]) -> None:
    transport_notes = (_BAUD_NOTE, _UNLOCK_NOTE)
    if len(notes) < len(transport_notes):
        msg = "trace is missing the runtime 576000/FPROMOD unlock observations"
        raise QualificationError(msg)
    for note, expected in zip(
        notes[: len(transport_notes)], transport_notes, strict=True
    ):
        if note.text != expected or note.records_before != 0:
            msg = (
                f"line {note.line_number}: expected pre-entry runtime note "
                f"{expected!r}, got {note.text!r} after "
                f"{note.records_before} record(s)"
            )
            raise QualificationError(msg)

    for note in notes[len(transport_notes) :]:
        if note.text.startswith(("baud -> ", "unlocked at baud ")):
            msg = (
                f"line {note.line_number}: contradictory or repeated transport "
                f"observation {note.text!r}"
            )
            raise QualificationError(msg)

    force_notes = [note for note in notes if note.text == _FORCE_NOTE]
    if (
        len(force_notes) != 1
        or force_notes[0].records_before != _FORCE_NOTE_RECORDS_BEFORE
    ):
        location = (
            "<missing>"
            if not force_notes
            else ", ".join(str(note.records_before) for note in force_notes)
        )
        msg = (
            "selective force-write runtime note must appear exactly once after "
            f"record {_FORCE_NOTE_RECORDS_BEFORE}; observed at {location}"
        )
        raise QualificationError(msg)


def _segment_should_write(segment: _StockSegment, setup_result: int) -> bool:
    """Apply the qualification's SETUP contract to one stock segment.

    Returns:
        Whether the segment's transfer must follow in the trace.

    Raises:
        QualificationError: if the SETUP result contradicts the contract.

    """
    if segment.index == 1:
        if setup_result != 0:
            msg = (
                "IMAGE_DATA SETUP must report current=0; otherwise the trace "
                "does not exercise the selective force-write override"
            )
            raise QualificationError(msg)
        return True
    if segment.index == _ALWAYS_REQUESTED_SEGMENT_INDEX:
        if setup_result != 1:
            msg = (
                f"stock body segment {segment.index} {segment.name} must "
                "report mismatch=1: its stock descriptor carries no version "
                "bytes, so the loader requests it on every run"
            )
            raise QualificationError(msg)
        return True
    if segment.index >= _FIRST_OVERLAY_SEGMENT_INDEX:
        if setup_result != 1:
            msg = (
                f"stock overlay segment {segment.index} {segment.name} must "
                "take its normal mismatch=1 transfer path"
            )
            raise QualificationError(msg)
        return True
    if setup_result != 0:
        msg = (
            f"stock body segment {segment.index} {segment.name} must "
            "report current=0 and remain skipped; a mismatch-triggered "
            "restoration is safe but is not this narrow qualification"
        )
        raise QualificationError(msg)
    return False


def _validate_records(
    records: tuple[_TraceRecord, ...],
) -> tuple[tuple[int, ...], tuple[int, ...], int, int]:
    cursor = _Cursor(records)
    _expect_tx_ack(
        cursor,
        _ENTER_PROGRAM,
        b"\x00",
        purpose="ENTER_PROGRAM entry pair",
    )
    _expect_tx_ack(
        cursor,
        _TIMED_SESSION,
        b"",
        purpose="TIMED_SESSION entry pair",
    )
    _ = cursor.expect(
        "TX",
        _QUERY_TARGET,
        purpose="QUERY_TARGET request",
        payload_length=0,
        payload_prefix=b"",
    )
    _ = cursor.expect(
        "RX",
        _QUERY_TARGET_REPLY,
        purpose="stock QUERY_TARGET reply",
        payload_length=17,
        payload_prefix=_QUERY_TARGET_PREFIX,
    )
    _expect_tx_ack(
        cursor,
        _BAUD_AND_ACK,
        b"\x12\x01",
        purpose="576000 per-packet-ACK negotiation",
    )

    setup_results: list[int] = []
    written_segments: list[int] = []
    chunks_written = 0
    bytes_written = 0
    for segment in _STOCK_SEGMENTS:
        _ = cursor.expect(
            "TX",
            _SETUP_SEGMENT,
            purpose=f"stock SETUP segment {segment.index} {segment.name}",
            payload_length=segment.setup_payload_length,
            payload_prefix=segment.setup_prefix,
        )
        setup_reply = cursor.expect(
            "RX",
            _SETUP_SEGMENT_REPLY,
            purpose=f"SETUP result for segment {segment.index} {segment.name}",
            payload_length=1,
        )
        setup_result = setup_reply.payload_prefix[0]
        if setup_result not in {0, 1}:
            msg = (
                f"frame {setup_reply.ordinal}: SETUP segment {segment.index} "
                f"returned {setup_result}; only current=0 or mismatch=1 is valid"
            )
            raise QualificationError(msg)
        setup_results.append(setup_result)

        should_write = _segment_should_write(segment, setup_result)

        if should_write:
            _validate_segment_transfer(cursor, segment)
            written_segments.append(segment.index)
            chunks_written += segment.chunk_count
            bytes_written += segment.data_length

    expected_written_segments = [1, 3, 5, 6]
    if (
        written_segments != expected_written_segments
        or chunks_written != _QUALIFICATION_CHUNKS_WRITTEN
        or bytes_written != _QUALIFICATION_BYTES_WRITTEN
    ):
        msg = (
            "qualification write set must be exactly segments [1,3,5,6], "
            f"{_QUALIFICATION_CHUNKS_WRITTEN:,} chunks and "
            f"{_QUALIFICATION_BYTES_WRITTEN:,} bytes"
        )
        raise QualificationError(msg)
    _expect_tx_ack(
        cursor,
        _COMPLETE_UPDATE,
        _COMPLETE_PAYLOAD,
        purpose="u32 stock COMPLETE_UPDATE",
    )
    cursor.require_end()
    return (
        tuple(setup_results),
        tuple(written_segments),
        chunks_written,
        bytes_written,
    )


def _validate_segment_transfer(cursor: _Cursor, segment: _StockSegment) -> None:
    label = f"segment {segment.index} {segment.name}"
    _ = cursor.expect(
        "TX",
        _BEGIN_TRANSFER,
        purpose=f"{label} BEGIN_TRANSFER",
        payload_length=0,
        payload_prefix=b"",
    )
    while True:
        record = cursor.peek()
        if record is None or record.direction != "RX" or record.verb != _BUSY:
            break
        _ = cursor.expect(
            "RX",
            _BUSY,
            purpose=f"{label} erase BUSY",
            payload_length=0,
            payload_prefix=b"",
        )
    _expect_ack(cursor, purpose=f"{label} BEGIN_TRANSFER completion")

    sample_digest = hashlib.sha256() if segment.index == 1 else None
    for chunk_index in range(segment.chunk_count):
        offset = chunk_index * segment.chunk_size
        chunk_header = offset.to_bytes(4, "little") + segment.chunk_size.to_bytes(
            4,
            "little",
        )
        purpose = f"{label} SEND_CHUNK offset {offset}"
        exact_prefix = (
            None
            if segment.overlay_prefix is None
            else chunk_header + segment.overlay_prefix
        )
        chunk_record = cursor.expect(
            "TX",
            _SEND_CHUNK,
            purpose=purpose,
            payload_length=8 + segment.chunk_size,
            payload_prefix=exact_prefix,
        )
        if exact_prefix is None:
            # Body chunks carry image bytes that are not known in advance, so
            # only the offset/length header is pinned here; IMAGE_DATA's
            # retained data bytes are checked through the sample digest.
            _require_prefix_start(chunk_record, purpose=purpose, prefix=chunk_header)
        if sample_digest is not None:
            sample_digest.update(chunk_record.payload_prefix[8:16])
        _expect_ack(
            cursor,
            purpose=f"{label} immediate SEND_CHUNK ACK at offset {offset}",
        )

    if sample_digest is not None:
        actual_sample_sha256 = sample_digest.hexdigest()
        if actual_sample_sha256 != _IMAGE_DATA_SAMPLE_SHA256:
            msg = (
                "IMAGE_DATA retained 8-byte-per-chunk sample SHA-256 must be "
                f"{_IMAGE_DATA_SAMPLE_SHA256}, got {actual_sample_sha256}"
            )
            raise QualificationError(msg)

    _expect_tx_ack(
        cursor,
        _END_TRANSFER,
        b"",
        purpose=f"{label} sole END_TRANSFER",
    )
    if segment.verifies:
        _ = cursor.expect(
            "TX",
            _VERIFY_SEGMENT,
            purpose=f"{label} VERIFY_SEGMENT request",
            payload_length=0,
            payload_prefix=b"",
        )
        _ = cursor.expect(
            "RX",
            _VERIFY_SEGMENT_REPLY,
            purpose=f"{label} VERIFY_SEGMENT result",
            payload_length=1,
            payload_prefix=b"\x00",
        )


def _expect_tx_ack(
    cursor: _Cursor,
    verb: int,
    payload: bytes,
    *,
    purpose: str,
) -> None:
    _ = cursor.expect(
        "TX",
        verb,
        purpose=purpose,
        payload_length=len(payload),
        payload_prefix=payload,
    )
    _expect_ack(cursor, purpose=f"{purpose} ACK")


def _expect_ack(cursor: _Cursor, *, purpose: str) -> None:
    _ = cursor.expect(
        "RX",
        _ACK,
        purpose=purpose,
        payload_length=0,
        payload_prefix=b"",
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``python -m thd75_fw.flash.qualification TRACE``."""
    parser = argparse.ArgumentParser(
        description=(
            "Validate a completed wire-trace v1 file against the exact stock "
            "selective IMAGE_DATA hardware-qualification profile."
        ),
    )
    _ = parser.add_argument("trace", type=Path, help="completed wire-trace v1 file")
    args = parser.parse_args(argv)
    try:
        result = validate_qualification_trace(args.trace)
    except (OSError, UnicodeError, QualificationError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    indices = ",".join(str(index) for index in result.written_segment_indices)
    print(
        "VALID: "
        f"{result.frame_count} frames; "
        f"{result.written_segment_count} written segments [{indices}]; "
        f"{result.chunks_written:,} chunks; "
        f"{result.bytes_written:,} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
