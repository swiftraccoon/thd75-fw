"""Tests for thd75_fw.flash.diagnostics and the evidence the session emits.

The banner and the wire trace exist because past hardware attempts recorded
the image, the port and the outcome and nothing else. These tests pin the
two properties that failure needs: the banner names every setting that had
to be reconstructed from edit timestamps, and the trace's format is stable
and batched.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path, PurePath
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from tests.fixtures.mock_radio import MockRadio
from thd75_fw import __version__, cli, flash_ui
from thd75_fw._compat import override
from thd75_fw.cli import main_flash
from thd75_fw.flash import serial_io as flash_serial_io
from thd75_fw.flash import session as flash_session
from thd75_fw.flash.commands import AckCode, Verb
from thd75_fw.flash.diagnostics import (
    _FINGERPRINTED_SOURCES,
    BANNER_END,
    BANNER_START,
    TRACE_COLUMNS,
    TRACE_FORMAT_VERSION,
    FlashConfig,
    WireTrace,
    flasher_source_digest,
    format_busy_telemetry,
    git_revision,
    verb_label,
)
from thd75_fw.flash.handshake import CLEARTEXT_MAGIC, UNLOCK_REPLY
from thd75_fw.flash.progress import (
    ProgressEvent,
    SegmentErased,
    SegmentProgress,
    TransportBaudChanged,
)
from thd75_fw.flash.segments import SegmentDescriptor
from thd75_fw.flash.session import (
    FlashOutcome,
    FlashRunOptions,
    FlashSession,
    FlashSessionOptions,
    TargetInfo,
    negotiated_transfer_mode,
)
from thd75_fw.kex import parse_encrypted_resource, render

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture(autouse=True)
def enumerated_test_usb_ports(monkeypatch: MonkeyPatch) -> None:
    """Give the CLI-level tests an exact TH-D75 USB identity to accept."""
    ports = [
        (device, 0x2166, 0x9023)
        for device in ("unused", "/dev/null", "/dev/cu.usbmodem-test")
    ]
    monkeypatch.setattr(cli, "_enumerate_fldm_serial_ports", lambda: ports)


class _RecordingListener:
    """ProgressListener that keeps every event for assertions."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[ProgressEvent] = []

    def emit(self, event: ProgressEvent) -> None:
        self.events.append(event)


class _CleartextRadio(MockRadio):
    """MockRadio that accepts the cleartext FPROMOD unlock.

    The stock fixture only implements the keyed probe, and the cleartext
    path is the one a real flash takes, so the baud transition it reports
    has to be exercised through it.
    """

    @override
    def _try_unlock(self) -> None:
        if self._current_baud in self.responsive_at_bauds and bytes(
            self._rx_buf,
        ).startswith(CLEARTEXT_MAGIC):
            del self._rx_buf[: len(CLEARTEXT_MAGIC)]
            self._xor_key = 0
            self._tx_buf.extend(UNLOCK_REPLY)
            self._unlocked = True
            return
        super()._try_unlock()


def _config() -> FlashConfig:
    """Build a banner config with the shape a real cleartext flash uses.

    Tests vary individual fields with :func:`dataclasses.replace`.
    """
    mode = negotiated_transfer_mode()
    return FlashConfig(
        image="/evidence/stock.KEX",
        image_sha256="e62da10cfb0bb42e",
        image_label="official TH-D75 V1.03 stock",
        port="/dev/cu.usbmodem-test",
        open_baud=9600,
        unlock_path="cleartext",
        unlock_baud=576_000,
        post_unlock_baud=None,
        baud_ladder=None,
        baud_and_ack_payload=mode.payload,
        transfer_mode_code=mode.code,
        transfer_declared_baud=mode.declared_baud,
        ack_each_data_packet=mode.ack_each_data_packet,
        base_reply_timeout_seconds=30.0,
        chunk_size=1024,
        force_all_segments=False,
        forced_segment_indices=(),
        qualification=None,
        qualification_target=None,
        complete_update_value=0x1DB0,
        complete_update_width=2,
        segment_count=7,
        planned_bytes=15_335_424,
        wire_trace_path=None,
        progress_every_chunks=256,
        tool_version=__version__,
        git_revision="0a1b2c3d4e5f",
        source_digest="96870cc83b40",
    )


def _single_chunk_plan(
    *,
    chunk_size: int = 256,
    chunks: int = 1,
    erase_length: int | None = None,
) -> tuple[list[SegmentDescriptor], dict[int, bytes]]:
    """One segment sized to an exact number of packets.

    ``target_type_mask`` is all ones so the plan stays compatible with the
    mock radio's target reply under any mask-decoding convention; these
    tests are about diagnostics, not target compatibility.
    """
    data_length = chunk_size * chunks
    descriptor = SegmentDescriptor(
        flash_start_addr=0x00200000,
        data_length=data_length,
        erase_length=data_length if erase_length is None else erase_length,
        target_type_mask=0xFFFFFFFFFFFFFFFF,
        erase_wait_seconds=1,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x3343,
        checksum_start_offset=0,
        checksum_length=data_length,
        checksum_wait_seconds=1,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    return [descriptor], {0: bytes(data_length)}


# ── Configuration banner ────────────────────────────────────────────


class TestConfigurationBanner:
    """Every field a past run log left to be inferred is stated outright."""

    def test_banner_states_each_previously_ambiguous_setting(self) -> None:
        config = _config()
        rendered = config.render()
        rows = dict(config.rows())

        assert rendered.startswith(BANNER_START)
        assert rendered.rstrip().endswith(BANNER_END)
        # The four settings that had to be reconstructed by correlating run
        # timestamps against source edits.
        mode = negotiated_transfer_mode()
        assert rows["chunk_size"] == "1024 bytes per SEND_CHUNK"
        # Derived, never restated: which mode the operator settles on is a
        # hardware decision, and a test that pinned its bytes here would
        # only assert that two copies of the same literal agree.
        assert rows["baud_and_ack"].startswith(f"payload {mode.payload.hex(' ')}")
        assert (
            f"ack_each_data_packet={int(mode.ack_each_data_packet)}"
            in rows["baud_and_ack"]
        )
        assert rows["ack_policy"]
        assert rows["reply_timeouts"] == (
            "base 30s; SETUP/VERIFY add $CT; BEGIN adds $ET per response"
        )
        assert rows["baud_plan"]
        # Plus the run identity and the rest of the write policy.
        assert rows["tool_version"] == __version__
        assert rows["git_revision"] == "0a1b2c3d4e5f"
        assert rows["source_digest"] == "96870cc83b40"
        assert rows["image"] == "/evidence/stock.KEX"
        assert rows["image_sha256"] == "e62da10cfb0bb42e"
        assert rows["image_audit"] == "official TH-D75 V1.03 stock"
        assert rows["port"] == "/dev/cu.usbmodem-test"
        assert rows["port_open_baud"] == "9600"
        assert rows["segment_policy"]
        assert rows["completion"] == "0x1DB0 as LE u16 (b0 1d)"
        assert rows["plan"] == "7 segments, 15,335,424 bytes"
        # Every row reaches the rendered block, one padded line each.
        assert len(rendered.splitlines()) == len(rows) + 2
        for key, value in rows.items():
            assert any(
                line.strip().startswith(f"{key} ") and line.endswith(f": {value}")
                for line in rendered.splitlines()
            ), f"row {key!r} is missing from the rendered banner"

    def test_banner_names_selectively_forced_qualification_segment(self) -> None:
        target = (
            "segment 1 IMAGE_DATA: 360448 bytes, 1408 packets, payload_sha256=cd86abd"
        )
        rows = dict(
            replace(
                _config(),
                forced_segment_indices=(1,),
                qualification="stock-selective-image-data",
                qualification_target=target,
            ).rows()
        )

        assert rows["segment_policy"] == (
            "skip-current: the loader's SETUP equality answer decides"
        )
        assert rows["qualification"] == "stock-selective-image-data"
        assert rows["forced_segments"] == "1"
        assert rows["qualification_target"] == target

    def test_banner_payload_row_is_the_bytes_the_session_will_send(self) -> None:
        """The banner is derived from the same call the session sends from.

        A banner that restated the payload as its own literal could describe
        one protocol while the session ran another, which is the failure
        mode this whole feature exists to prevent.
        """
        mode = negotiated_transfer_mode()
        rendered = _config().render()

        assert f"payload {mode.payload.hex(' ')}" in rendered
        assert f"code 0x{mode.code:02X}" in rendered
        assert f"declares {mode.declared_baud} baud" in rendered
        assert f"ack_each_data_packet={int(mode.ack_each_data_packet)}" in rendered

    def test_banner_ack_policy_explains_the_streaming_consequence(self) -> None:
        streaming = replace(_config(), ack_each_data_packet=False).render()
        acknowledged = replace(_config(), ack_each_data_packet=True).render()

        assert "streaming: the loader answers no SEND_CHUNK" in streaming
        assert "END_TRANSFER" in streaming
        assert "per-packet ACK" in acknowledged

    def test_banner_records_the_cleartext_baud_transition(self) -> None:
        rendered = _config().render()

        assert "9600 (port open) -> 576000 (set before FPROMOD)" in rendered
        assert "no further change during the data phase" in rendered
        assert "cleartext FPROMOD" in rendered
        assert "xor_key=0" in rendered

    def test_banner_records_the_keyed_ladder_and_post_unlock_restore(self) -> None:
        rendered = replace(
            _config(),
            unlock_path="keyed",
            unlock_baud=19_200,
            post_unlock_baud=19_200,
            baud_ladder=(19_200, 4800, 38_400),
        ).render()

        assert "keyed Thd75tw" in rendered
        assert "19200/4800/38400 (keyed unlock ladder)" in rendered
        assert "19200 (restored after unlock)" in rendered

    def test_banner_distinguishes_segment_policies(self) -> None:
        assert "skip-current" in replace(_config(), force_all_segments=False).render()
        assert "force-all" in replace(_config(), force_all_segments=True).render()
        assert "#AF=1" in replace(_config(), force_all_segments=True).render()

    def test_banner_includes_host_omission_only_when_applied(self) -> None:
        omission = "source segment 3 DATA_0160 omitted before SETUP: pinned payload"

        default = _config()
        omitted = replace(_config(), host_omission=omission)

        assert "host_omission" not in dict(default.rows())
        assert "host_omission" not in default.render()
        assert dict(omitted.rows())["host_omission"] == omission
        assert any(
            line.strip().startswith("host_omission") and line.endswith(f": {omission}")
            for line in omitted.render().splitlines()
        )

    def test_banner_states_trace_and_progress_state(self) -> None:
        default = dict(_config().rows())
        traced = dict(
            replace(
                _config(),
                wire_trace_path="/evidence/run.trace",
                progress_every_chunks=0,
            ).rows()
        )

        assert default["wire_trace"] == "off"
        assert default["progress_interval"] == "every 256 chunks"
        assert traced["wire_trace"] == "/evidence/run.trace"
        assert traced["progress_interval"] == "off"

    def test_banner_marks_an_unpinned_image_rather_than_omitting_it(self) -> None:
        rows = dict(replace(_config(), image_label=None, image_sha256=None).rows())

        assert rows["image_audit"] == "unpinned"
        assert rows["image_sha256"] == "n/a"

    def test_banner_marks_a_missing_git_revision_rather_than_omitting_it(self) -> None:
        rows = dict(replace(_config(), git_revision=None).rows())
        assert rows["git_revision"] == "unavailable"

    def test_comment_lines_wrap_every_banner_line_for_a_trace_header(self) -> None:
        config = _config()

        lines = config.comment_lines()

        assert len(lines) == len(config.render().splitlines())
        assert all(line.startswith("# ") for line in lines)
        assert f"# {BANNER_START}" in lines


class TestBuildIdentity:
    """A run log has to identify the code that produced it."""

    def test_source_digest_is_stable_and_short(self) -> None:
        first = flasher_source_digest()

        assert first == flasher_source_digest()
        assert len(first) == 12
        assert first != "unavailable"

    def test_source_digest_tracks_source_content(self, tmp_path: Path) -> None:
        """A dirty tree still identifies itself; a commit id would not.

        The whole reason this exists is that past runs had to be matched to
        code by comparing wall-clock timestamps against edit times, which
        only works if the tree was committed. Editing one flasher source
        must change the digest.
        """
        (tmp_path / "flash").mkdir()
        for name in _FINGERPRINTED_SOURCES:
            _ = (tmp_path / name).write_text(f"# {name}\n", encoding="utf-8")
        before = flasher_source_digest(tmp_path)

        _ = (tmp_path / "flash" / "session.py").write_text(
            "# flash/session.py\n# one edited line\n",
            encoding="utf-8",
        )
        after = flasher_source_digest(tmp_path)

        assert before != "unavailable"
        assert after != before

    def test_source_digest_degrades_instead_of_raising(self, tmp_path: Path) -> None:
        """A missing source must not raise into a flash preflight."""
        assert flasher_source_digest(tmp_path) == "unavailable"

    def test_git_revision_is_hex_or_none(self) -> None:
        revision = git_revision()

        assert revision is None or (
            len(revision) == 12 and all(c in "0123456789abcdef" for c in revision)
        )

    def test_git_revision_reads_a_detached_head_without_a_subprocess(
        self,
        tmp_path: Path,
    ) -> None:
        git_dir = tmp_path / "pkg" / ".git"
        git_dir.mkdir(parents=True)
        _ = (git_dir / "HEAD").write_text("a" * 40 + "\n", encoding="utf-8")

        assert git_revision(tmp_path / "pkg") == "a" * 12

    def test_git_revision_follows_a_branch_ref(self, tmp_path: Path) -> None:
        git_dir = tmp_path / "pkg" / ".git"
        (git_dir / "refs" / "heads").mkdir(parents=True)
        _ = (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        _ = (git_dir / "refs" / "heads" / "main").write_text(
            "b" * 40 + "\n",
            encoding="utf-8",
        )

        assert git_revision(tmp_path / "pkg") == "b" * 12

    def test_git_revision_falls_back_to_packed_refs(self, tmp_path: Path) -> None:
        git_dir = tmp_path / "pkg" / ".git"
        git_dir.mkdir(parents=True)
        _ = (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        _ = (git_dir / "packed-refs").write_text(
            f"# pack-refs with: peeled\n{'c' * 40} refs/heads/main\n",
            encoding="utf-8",
        )

        assert git_revision(tmp_path / "pkg") == "c" * 12


# ── Wire trace file format ──────────────────────────────────────────


def _data_lines(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


class TestWireTraceFormat:
    def test_header_declares_version_and_columns(self, tmp_path: Path) -> None:
        path = tmp_path / "run.trace"

        with WireTrace(path):
            pass

        header = path.read_text(encoding="utf-8").splitlines()
        assert header[0] == f"# {TRACE_FORMAT_VERSION}"
        assert f"# columns: {TRACE_COLUMNS}" in header
        assert any("truncated to 16" in line for line in header)

    def test_header_can_carry_the_configuration_banner(self, tmp_path: Path) -> None:
        """The trace is self-describing: the config travels with the frames."""
        path = tmp_path / "run.trace"

        with WireTrace(path, header_lines=_config().comment_lines()):
            pass

        text = path.read_text(encoding="utf-8")
        assert f"# {BANNER_START}" in text
        assert f"# {BANNER_END}" in text
        assert f"payload {negotiated_transfer_mode().payload.hex(' ')}" in text
        assert "chunk_size" in text

    def test_record_columns_are_time_dir_verb_name_length_prefix(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "run.trace"

        with WireTrace(path) as trace:
            trace.record_tx(int(Verb.SEND_CHUNK), b"\x01\x02\x03\x04")
            trace.record_rx(int(AckCode.ACK), b"")

        rows = [line.split(",") for line in _data_lines(path)]
        assert len(rows) == 2
        assert len(rows[0]) == len(TRACE_COLUMNS.split(","))
        elapsed, direction, verb, verb_name, length, prefix = rows[0]
        assert float(elapsed) >= 0.0
        assert direction == "TX"
        assert verb == "0x43"
        assert verb_name == "SEND_CHUNK"
        assert length == "4"
        assert prefix == "01020304"
        assert rows[1][1:] == ["RX", "0x06", "ACK", "0", ""]

    def test_timestamps_are_monotonic_and_relative_to_the_trace(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "run.trace"

        with WireTrace(path) as trace:
            for _ in range(5):
                trace.record_tx(int(Verb.SEND_CHUNK), b"")

        stamps = [float(line.split(",")[0]) for line in _data_lines(path)]
        assert stamps == sorted(stamps)
        assert stamps[0] < 1.0

    def test_payload_is_truncated_but_the_length_is_exact(
        self,
        tmp_path: Path,
    ) -> None:
        """A 15 MB flash must not produce a 15 MB trace."""
        path = tmp_path / "run.trace"

        with WireTrace(path) as trace:
            trace.record_tx(int(Verb.SEND_CHUNK), bytes(range(256)) * 4)

        _, _, _, _, length, prefix = _data_lines(path)[0].split(",")
        assert length == "1024"
        assert prefix == bytes(range(16)).hex()

    def test_prefix_width_is_configurable(self, tmp_path: Path) -> None:
        path = tmp_path / "run.trace"

        with WireTrace(path, hex_prefix_bytes=2) as trace:
            trace.record_tx(int(Verb.SEND_CHUNK), b"\xaa\xbb\xcc\xdd")

        assert _data_lines(path)[0].endswith(",4,aabb")

    def test_records_are_written_in_batches_not_per_frame(
        self,
        tmp_path: Path,
    ) -> None:
        """Per-frame writes would put a syscall inside the data phase."""
        path = tmp_path / "run.trace"
        trace = WireTrace(path, flush_records=4)

        for _ in range(3):
            trace.record_tx(int(Verb.SEND_CHUNK), b"\x00")
        assert _data_lines(path) == []

        trace.record_tx(int(Verb.SEND_CHUNK), b"\x00")
        assert len(_data_lines(path)) == 4

        trace.close()

    def test_close_flushes_the_partial_batch_and_states_the_total(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "run.trace"
        trace = WireTrace(path, flush_records=100)

        trace.record_tx(int(Verb.ENTER_PROGRAM), b"\x00")
        trace.record_rx(int(AckCode.ACK), b"")
        trace.close()

        assert len(_data_lines(path)) == 2
        assert trace.record_count == 2
        assert "# 2 frames recorded" in path.read_text(encoding="utf-8")

    def test_note_is_ordered_after_everything_already_recorded(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "run.trace"

        with WireTrace(path, flush_records=1000) as trace:
            trace.record_tx(int(Verb.BEGIN_TRANSFER), b"")
            trace.note("erase done")
            trace.record_tx(int(Verb.SEND_CHUNK), b"")

        lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if "BEGIN_TRANSFER" in line or "erase done" in line or "SEND_CHUNK" in line
        ]
        assert [line.split(",")[0] for line in lines][1] == "# erase done"

    def test_rejects_a_zero_batch_size(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="flush_records"):
            _ = WireTrace(tmp_path / "run.trace", flush_records=0)

    def test_exclusive_trace_refuses_to_replace_prior_evidence(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "qualification.trace"
        _ = path.write_text("retained prior run\n", encoding="utf-8")

        with pytest.raises(FileExistsError):
            _ = WireTrace(path, exclusive=True)

        assert path.read_text(encoding="utf-8") == "retained prior run\n"


class TestVerbLabels:
    """The trace names verbs without importing the protocol enums."""

    def test_every_request_verb_is_named_exactly_as_the_enum(self) -> None:
        for verb in Verb:
            assert verb_label("TX", int(verb)) == verb.name

    def test_every_response_code_is_named_exactly_as_the_enum(self) -> None:
        for code in AckCode:
            assert verb_label("RX", int(code)) == code.name

    def test_framed_replies_are_named_after_their_request(self) -> None:
        assert verb_label("RX", int(Verb.QUERY_TARGET) + 1) == "QUERY_TARGET_REPLY"
        assert verb_label("RX", int(Verb.SETUP_SEGMENT) + 1) == "SETUP_SEGMENT_REPLY"

    def test_unknown_bytes_are_labelled_not_guessed(self) -> None:
        assert verb_label("TX", 0xFE) == "UNKNOWN"
        assert verb_label("RX", 0xFE) == "UNKNOWN"


# ── Session integration ─────────────────────────────────────────────


class TestSessionTracing:
    def test_a_traced_flash_records_both_directions(self, tmp_path: Path) -> None:
        path = tmp_path / "run.trace"
        radio = MockRadio(responsive_at_bauds=(9600,))
        segments, segment_data = _single_chunk_plan()

        with WireTrace(path) as trace:
            session = FlashSession(
                radio,
                FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
                trace=trace,
            )
            _ = session.flash_segments(segments, segment_data)

        rows = [line.split(",") for line in _data_lines(path)]
        sent = [row[3] for row in rows if row[1] == "TX"]
        received = [row[3] for row in rows if row[1] == "RX"]
        assert sent[:4] == [
            "ENTER_PROGRAM",
            "TIMED_SESSION",
            "QUERY_TARGET",
            "BAUD_AND_ACK",
        ]
        assert "SEND_CHUNK" in sent
        assert "COMPLETE_UPDATE" in sent
        assert "QUERY_TARGET_REPLY" in received
        assert "ACK" in received

    def test_send_chunk_records_offset_and_length_header(
        self,
        tmp_path: Path,
    ) -> None:
        """The retained prefix covers the fields that prove sequencing."""
        path = tmp_path / "run.trace"
        radio = MockRadio(responsive_at_bauds=(9600,))
        segments, segment_data = _single_chunk_plan(chunks=2)

        with WireTrace(path) as trace:
            session = FlashSession(
                radio,
                FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
                trace=trace,
            )
            _ = session.flash_segments(segments, segment_data)

        chunks = [
            line.split(",")
            for line in _data_lines(path)
            if line.split(",")[3] == "SEND_CHUNK"
        ]
        assert [row[4] for row in chunks] == ["264", "264"]
        assert chunks[0][5].startswith("00000000" + "00010000")
        assert chunks[1][5].startswith("00010000" + "00010000")

    def test_no_trace_file_is_touched_by_default(self, tmp_path: Path) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        segments, segment_data = _single_chunk_plan()

        _ = FlashSession(
            radio, FlashSessionOptions(chunk_size=256, handshake_timeout=0.05)
        ).flash_segments(segments, segment_data)

        assert list(tmp_path.iterdir()) == []


class TestEraseTelemetry:
    """Whether the loader emits BUSY during erase is still an open question."""

    def test_busy_frames_are_counted_with_their_gaps(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,), erase_busy_iterations=3)
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan()

        _ = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
            progress=listener,
        ).flash_segments(segments, segment_data)

        erased = [e for e in listener.events if isinstance(e, SegmentErased)]
        assert len(erased) == 1
        assert erased[0].busy_count == 3
        assert erased[0].first_busy_seconds is not None
        assert erased[0].first_busy_seconds >= 0.0
        # One gap per BUSY after the first.
        assert len(erased[0].busy_intervals) == 2
        assert erased[0].elapsed_seconds >= 0.0

    def test_absence_of_busy_is_reported_as_a_result(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,), erase_busy_iterations=0)
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan()

        _ = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
            progress=listener,
        ).flash_segments(segments, segment_data)

        erased = [e for e in listener.events if isinstance(e, SegmentErased)]
        assert erased[0].busy_count == 0
        assert erased[0].first_busy_seconds is None
        assert erased[0].busy_intervals == ()
        rendered = format_busy_telemetry(
            busy_count=0,
            first_busy_seconds=None,
            busy_intervals=(),
        )
        assert rendered == "no BUSY frames (loader ACKed the erase directly)"

    def test_busy_intervals_are_capped_but_the_count_is_exact(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,), erase_busy_iterations=40)
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan()

        _ = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
            progress=listener,
        ).flash_segments(segments, segment_data)

        erased = [e for e in listener.events if isinstance(e, SegmentErased)]
        assert erased[0].busy_count == 40
        assert len(erased[0].busy_intervals) == 16

    def test_erase_telemetry_reaches_the_trace(self, tmp_path: Path) -> None:
        path = tmp_path / "run.trace"
        radio = MockRadio(responsive_at_bauds=(9600,), erase_busy_iterations=2)
        segments, segment_data = _single_chunk_plan()

        with WireTrace(path) as trace:
            _ = FlashSession(
                radio,
                FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
                trace=trace,
            ).flash_segments(segments, segment_data)

        text = path.read_text(encoding="utf-8")
        assert "BEGIN_TRANSFER[segment_0] completed in" in text
        assert "2 BUSY frames" in text


class TestDataPhaseProgress:
    def test_throughput_is_reported_every_n_chunks(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan(chunks=4)

        _ = FlashSession(
            radio,
            FlashSessionOptions(
                chunk_size=256, handshake_timeout=0.05, progress_every_chunks=2
            ),
            progress=listener,
        ).flash_segments(segments, segment_data)

        samples = [e for e in listener.events if isinstance(e, SegmentProgress)]
        assert [s.chunks_sent for s in samples] == [2, 4]
        assert [s.bytes_sent for s in samples] == [512, 1024]
        assert all(s.elapsed_seconds >= 0.0 for s in samples)
        assert all(s.bytes_per_second >= 0.0 for s in samples)
        assert all(s.name == "segment_0" for s in samples)

    def test_a_trailing_partial_interval_still_closes_the_segment(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan(chunks=3)

        _ = FlashSession(
            radio,
            FlashSessionOptions(
                chunk_size=256, handshake_timeout=0.05, progress_every_chunks=2
            ),
            progress=listener,
        ).flash_segments(segments, segment_data)

        samples = [e for e in listener.events if isinstance(e, SegmentProgress)]
        assert [s.chunks_sent for s in samples] == [2, 3]

    def test_reporting_is_off_by_default(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan(chunks=4)

        _ = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
            progress=listener,
        ).flash_segments(segments, segment_data)

        assert not [e for e in listener.events if isinstance(e, SegmentProgress)]

    def test_a_negative_interval_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="progress_every_chunks"):
            _ = FlashSession(MockRadio(), FlashSessionOptions(progress_every_chunks=-1))


class TestBaudChangeEvents:
    def test_the_cleartext_transition_is_recorded_with_its_reason(self) -> None:
        radio = _CleartextRadio(responsive_at_bauds=(576_000,))
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan()

        _ = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
            progress=listener,
        ).flash_segments(segments, segment_data, FlashRunOptions(cleartext_unlock=True))

        changes = [e for e in listener.events if isinstance(e, TransportBaudChanged)]
        assert [(c.baud, c.reason) for c in changes] == [
            (576_000, "set before cleartext FPROMOD"),
        ]

    def test_the_keyed_post_unlock_restore_is_recorded(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        listener = _RecordingListener()
        segments, segment_data = _single_chunk_plan()

        _ = FlashSession(
            radio,
            FlashSessionOptions(chunk_size=256, handshake_timeout=0.05),
            progress=listener,
        ).flash_segments(segments, segment_data)

        changes = [e for e in listener.events if isinstance(e, TransportBaudChanged)]
        assert [(c.baud, c.reason) for c in changes] == [
            (19_200, "official restore after keyed unlock"),
        ]


# ── CLI wiring ──────────────────────────────────────────────────────


_REAL_RESOURCE = (
    PurePath(__file__).parent.parent
    / "ref"
    / "TH-D75_V103_E"
    / "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
)


@pytest.fixture(scope="module")
def real_stock_plaintext_kex() -> bytes:
    """Render the official encrypted resource into an external plaintext KEX."""
    resource = Path(_REAL_RESOURCE)
    if not resource.is_file():
        pytest.skip("real updater resource absent (ref/ is gitignored)")
    return render(parse_encrypted_resource(resource.read_text(encoding="utf-8")))


def _mocked_hardware_flash(
    monkeypatch: MonkeyPatch,
    *,
    image_path: Path,
    wire_trace_path: Path | None,
) -> None:
    """Drive ``_run_flash`` past every gate without opening a device."""
    context = MagicMock()
    context.__enter__.return_value = object()
    context.__exit__.return_value = None
    monkeypatch.setattr(
        flash_serial_io,
        "ReferenceSerialIO",
        MagicMock(return_value=context),
    )
    session = MagicMock()
    session.flash_segments.return_value = FlashOutcome(
        target=TargetInfo(
            raw_payload=b"\x00" * 17,
            target_mask_bytes=b"\x00" * 8,
            opaque_bytes_8_15=b"\x00" * 8,
            trailing_status=0,
        ),
        segments_written=7,
        bytes_written=2_621_440,
        elapsed_seconds=1.0,
    )
    constructor = MagicMock(return_value=session)
    constructor.D75_V103_COMPLETE_CODE = FlashSession.D75_V103_COMPLETE_CODE
    constructor.validate_plan = FlashSession.validate_plan
    monkeypatch.setattr(flash_session, "FlashSession", constructor)
    monkeypatch.setattr(
        flash_ui,
        "RichProgressListener",
        MagicMock(return_value=object()),
    )

    cli._run_flash(
        cli._FlashRequest(
            input_path=image_path,
            port="/dev/cu.usbmodem-test",
            baud_ladder_text=None,
            skip_prompt=True,
            dry_run=False,
            show_post_hint=False,
            chunk_size=256,
            raw=False,
            flash_addr=None,
            cleartext_unlock=True,
            cleartext_baud=576_000,
            wire_trace_path=wire_trace_path,
            progress_every_chunks=64,
        )
    )


class TestFlashCliDiagnostics:
    def test_a_real_flash_logs_the_banner_before_opening_the_port(
        self,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "stock.KEX"
        _ = image_path.write_bytes(real_stock_plaintext_kex)

        _mocked_hardware_flash(
            monkeypatch,
            image_path=image_path,
            wire_trace_path=None,
        )

        err = capsys.readouterr().err
        assert BANNER_START in err
        assert BANNER_END in err
        assert "256 bytes per SEND_CHUNK" in err
        assert f"payload {negotiated_transfer_mode().payload.hex(' ')}" in err
        assert "cleartext FPROMOD" in err
        assert "576000 (port open; FPROMOD at same rate)" in err
        assert "skip-current" in err
        assert str(image_path) in err
        assert "/dev/cu.usbmodem-test" in err
        assert "official TH-D75 V1.03 stock" in err
        assert "every 64 chunks" in err
        # The banner precedes the session, so a run that dies at open still
        # records what it was about to do.
        assert err.index(BANNER_START) < err.index("MANDATORY: disconnect USB")

    def test_a_traced_flash_writes_the_banner_into_the_trace_header(
        self,
        real_stock_plaintext_kex: bytes,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        image_path = tmp_path / "stock.KEX"
        _ = image_path.write_bytes(real_stock_plaintext_kex)
        trace_path = tmp_path / "run.trace"

        _mocked_hardware_flash(
            monkeypatch,
            image_path=image_path,
            wire_trace_path=trace_path,
        )

        header = trace_path.read_text(encoding="utf-8")
        assert header.startswith(f"# {TRACE_FORMAT_VERSION}")
        assert f"# {BANNER_START}" in header
        assert f"# columns: {TRACE_COLUMNS}" in header
        assert str(trace_path) in capsys.readouterr().err

    def test_flags_are_documented(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["thd75-flash", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 0
        help_text = " ".join(capsys.readouterr().out.split())
        assert "--wire-trace" in help_text
        assert "Off by default" in help_text
        assert "--progress-every" in help_text
        assert "bytes/sec" in help_text

    def test_wire_trace_is_refused_for_a_dry_run(
        self,
        monkeypatch: MonkeyPatch,
        capsys: CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--dry-run",
                "--wire-trace",
                str(tmp_path / "run.trace"),
                "some.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
        assert "--wire-trace records a real flash" in capsys.readouterr().err
        assert not (tmp_path / "run.trace").exists()

    def test_defaults_reach_the_runner(self, monkeypatch: MonkeyPatch) -> None:
        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            ["thd75-flash", "--port", "unused", "some.KEX"],
        )

        cli.main_flash()

        assert runner.call_args.args[0].wire_trace_path is None
        assert runner.call_args.args[0].progress_every_chunks == 256

    def test_flags_reach_the_runner(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        trace_path = tmp_path / "run.trace"
        runner = MagicMock()
        monkeypatch.setattr(cli, "_run_flash", runner)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--wire-trace",
                str(trace_path),
                "--progress-every",
                "32",
                "some.KEX",
            ],
        )

        cli.main_flash()

        assert str(runner.call_args.args[0].wire_trace_path) == str(trace_path)
        assert runner.call_args.args[0].progress_every_chunks == 32

    def test_a_negative_progress_interval_is_rejected(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "thd75-flash",
                "--port",
                "unused",
                "--progress-every",
                "-1",
                "some.KEX",
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main_flash()

        assert exc_info.value.code == 2
