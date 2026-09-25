"""Tests for thd75_fw.flash.session."""

from __future__ import annotations

import contextlib
import hashlib
from dataclasses import InitVar, dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.fixtures.mock_radio import MockRadio, MockRadioFault
from thd75_fw import kex
from thd75_fw._compat import override
from thd75_fw.cli import _extract_fc_tag, _validate_d75_v103_kex_profile
from thd75_fw.flash import session as flash_session
from thd75_fw.flash.commands import UnframedResponse, Verb
from thd75_fw.flash.diagnostics import WireTrace
from thd75_fw.flash.handshake import (
    CLEARTEXT_MAGIC,
    UNLOCK_REPLY,
    HandshakeError,
    HandshakeResult,
    perform_cleartext_unlock,
)
from thd75_fw.flash.protocol import Frame, build_frame
from thd75_fw.flash.segments import (
    STOCK_TARGET_TYPE_MASK_D75_V103,
    SegmentDescriptor,
)
from thd75_fw.flash.session import (
    FlashError,
    FlashOutcome,
    FlashRunOptions,
    FlashSession,
    FlashSessionOptions,
    SetupCalibrationOutcome,
    TargetInfo,
    _setup_calibration_plan,
    _validate_setup_calibration_plan,
    decode_target_info,
)
from thd75_fw.kex import Kex, KexBlock, firmware_checksum

if TYPE_CHECKING:
    from collections.abc import Callable

    from _pytest.monkeypatch import MonkeyPatch


@dataclass(kw_only=True)
class _CleartextSetupRadio(MockRadio):
    """MockRadio extension for the setup-only cleartext test path.

    Every other MockRadio field keeps its default; this path answers with
    framed ACKs, as a real D75 V1.03 loader does, and replays
    ``setup_results`` one per SETUP_SEGMENT.
    """

    framed_acks: bool = True
    setup_results: InitVar[tuple[bytes, ...]] = (b"\x01",)
    baud_log: list[int] = field(default_factory=list[int], init=False)
    setup_payloads: list[bytes] = field(default_factory=list[bytes], init=False)
    command_frames: list[Frame] = field(default_factory=list[Frame], init=False)
    _setup_results: list[bytes] = field(default_factory=list[bytes], init=False)
    _setup_timed_out: bool = field(default=False, init=False)
    _setup_failed: bool = field(default=False, init=False)

    def __post_init__(self, setup_results: tuple[bytes, ...]) -> None:
        self._setup_results = list(setup_results)

    @override
    def set_baud(self, baud: int) -> None:
        self.baud_log.append(baud)
        super().set_baud(baud)

    @override
    def _handle_frame(self, frame: Frame) -> None:
        self.command_frames.append(frame)
        if frame.verb == Verb.SETUP_SEGMENT:
            self.setup_payloads.append(frame.payload)
            if not self._setup_results:
                msg = "unexpected extra SETUP_SEGMENT"
                raise AssertionError(msg)
            self.setup_result = self._setup_results.pop(0)
        super()._handle_frame(frame)


class _TimeoutOnSetupRadio(_CleartextSetupRadio):
    @override
    def read(self, max_bytes: int) -> bytes:
        if self._setup_timed_out:
            msg = "simulated SETUP timeout"
            raise TimeoutError(msg)
        return super().read(max_bytes)

    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SETUP_SEGMENT:
            self._verb_log.append(frame.verb)
            self.setup_payloads.append(frame.payload)
            self._setup_timed_out = True
            return
        super()._handle_frame(frame)


class _TransportErrorOnSetupRadio(_CleartextSetupRadio):
    @override
    def read(self, max_bytes: int) -> bytes:
        if self._setup_failed:
            msg = "simulated USB transport failure"
            raise OSError(msg)
        return super().read(max_bytes)

    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SETUP_SEGMENT:
            self.command_frames.append(frame)
            self._verb_log.append(frame.verb)
            self.setup_payloads.append(frame.payload)
            self._setup_failed = True
            return
        super()._handle_frame(frame)


class _ExtraAckAfterBaudRadio(_CleartextSetupRadio):
    """Inject a second decoded response before the first SETUP command."""

    @override
    def _handle_frame(self, frame: Frame) -> None:
        super()._handle_frame(frame)
        if frame.verb == Verb.BAUD_AND_ACK:
            self._send_raw(b"\x06")


class _FrameErrorOnSetupRadio(_CleartextSetupRadio):
    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SETUP_SEGMENT:
            self.command_frames.append(frame)
            self._verb_log.append(frame.verb)
            self.setup_payloads.append(frame.payload)
            response = bytearray(
                build_frame(
                    Frame(header=0, verb=0x41, payload=b"\x00"),
                )
            )
            response[-1] ^= 0x01
            self._tx_buf.extend(response)
            return
        super()._handle_frame(frame)


class _WrongVerbOnSetupRadio(_CleartextSetupRadio):
    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SETUP_SEGMENT:
            self.command_frames.append(frame)
            self._verb_log.append(frame.verb)
            self.setup_payloads.append(frame.payload)
            self._tx_buf.extend(
                build_frame(
                    Frame(header=0, verb=0x42, payload=b"\x00"),
                )
            )
            return
        super()._handle_frame(frame)


class _ShortFramedWriteRadio(MockRadio):
    """Report a partial write after accepting an otherwise complete frame."""

    @override
    def write(self, data: bytes) -> int:
        was_unlocked = self._unlocked
        written = super().write(data)
        if was_unlocked and len(data) >= 9:
            return written - 1
        return written


class _PostUnlockBaudFailureRadio(MockRadio):
    """Fail the official 19200 restore only after keyed unlock succeeded."""

    @override
    def set_baud(self, baud: int) -> None:
        if baud == 19_200 and self._unlocked:
            msg = "simulated post-unlock baud failure"
            raise OSError(msg)
        super().set_baud(baud)


@dataclass
class _CapturingRadio(MockRadio):
    """Record each decoded frame's payload, keyed by verb.

    ``_handle_frame`` already receives the decoded Frame after MockRadio
    descrambles it, so this captures exactly what the host sent.
    """

    captured_payloads: dict[int, list[bytes]] = field(
        default_factory=dict[int, list[bytes]],
        init=False,
    )

    @override
    def _handle_frame(self, frame: Frame) -> None:
        self.captured_payloads.setdefault(frame.verb, []).append(
            frame.payload,
        )
        super()._handle_frame(frame)


class _ImmediateResponseTimeoutSession(FlashSession):
    """Avoid a 30-second wall-clock wait while testing error translation."""

    @override
    def _read_one_response(
        self,
        *,
        timeout_seconds: float | None = None,
    ) -> Frame | UnframedResponse:
        del timeout_seconds
        msg = "simulated command timeout"
        raise TimeoutError(msg)


class _RecordingReplyTimeoutSession(FlashSession):
    """Record each response window with the verb whose reply it awaited."""

    def __init__(self, transport: MockRadio, *, handshake_timeout: float) -> None:
        super().__init__(
            transport, FlashSessionOptions(handshake_timeout=handshake_timeout)
        )
        self.response_timeouts: list[tuple[Verb, float]] = []
        self._active_verb: Verb | None = None

    @override
    def _send(self, verb: Verb, payload: bytes, *, step: str) -> None:
        self._active_verb = verb
        super()._send(verb, payload, step=step)

    @override
    def _read_one_response(
        self,
        *,
        timeout_seconds: float | None = None,
    ) -> Frame | UnframedResponse:
        assert self._active_verb is not None
        effective_timeout = (
            self._reply_timeout if timeout_seconds is None else timeout_seconds
        )
        self.response_timeouts.append((self._active_verb, effective_timeout))
        return super()._read_one_response(timeout_seconds=timeout_seconds)


def test_target_info_preserves_evidence_supported_byte_roles() -> None:
    payload = (
        (0x01).to_bytes(8, "little") + (0x02).to_bytes(8, "little") + bytes([0x00])
    )
    info = decode_target_info(payload)
    assert info.raw_payload == payload
    assert info.target_mask_bytes == payload[:8]
    # Reply byte 0 is the high byte (f.cs:1523-1524), so the wire bytes
    # 01 00 00 00 00 00 00 00 decode to 0x0100000000000000.
    assert info.target_mask == 0x0100_0000_0000_0000
    assert info.opaque_bytes_8_15 == payload[8:16]
    assert info.trailing_status == 0x00


def test_target_info_exposes_only_first_field_as_mask() -> None:
    payload = (
        (0xDEADBEEF).to_bytes(8, "little")
        + (0xCAFE).to_bytes(8, "little")
        + bytes([0x07])
    )
    info = decode_target_info(payload)
    assert info.target_mask == 0xEFBE_ADDE_0000_0000
    assert info.opaque_bytes_8_15 == (0xCAFE).to_bytes(8, "little")
    assert info.trailing_status == 0x07


@pytest.mark.parametrize(
    "reply_prefix",
    [
        b"\x02\x00\x00\x00\x00\x00\x00\x00",  # the observed stock D75 reply
        b"\x01\x00\x00\x00\x00\x00\x00\x00",
        b"\x08\x00\x00\x00\x00\x00\x00\x00",
        b"\x10\x00\x00\x00\x00\x00\x00\x00",  # disjoint from stock $TT
        b"\x00\x01\x00\x00\x00\x00\x00\x00",  # disjoint from stock $TT
        b"\x00\x00\x00\x00\x00\x00\x00\x0f",  # disjoint from stock $TT
        b"\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
    ],
)
@pytest.mark.parametrize(
    "tt_text",
    [
        b'$TT="0F 00 00 00 00 00 00 00"',  # stock V1.03
        b'$TT="00 00 00 00 00 00 00 0F"',
        b'$TT="03 00 00 00 00 00 00 00"',
        b'$TT="FF FF FF FF FF FF FF FF"',
        b'$TT="00 00 00 00 00 00 00 00"',
    ],
)
def test_target_compatibility_gate_is_convention_independent(
    reply_prefix: bytes,
    tt_text: bytes,
) -> None:
    """The host-side ``$TT`` gate decides the same way under either reading.

    ``$TT`` and the QUERY_TARGET reply are decoded with the *same*
    convention, so ``reply & $TT`` pairs reply byte *i* with ``$TT`` text
    byte *i* whichever end you start from. Reversing both operands cannot
    change whether the AND is zero. This is why adopting the vendor's
    convention moved bytes on the wire without moving this gate.

    Reading the pair little-endian is what this project did before, and is
    still what OpenWood does; it is reproduced here as the control.
    """
    payload = reply_prefix + bytes(8) + b"\x00"
    info = decode_target_info(payload)

    block = KexBlock(
        metadata=(
            b"$SA=0x60200000",
            b"$DL=0x00000010",
            b"$EL=0x00000010",
            tt_text,
            b"$ET=5",
            b"$CB=0xFFFF",
            b"$CA=0x0000",
            b"$CS=0x0",
            b"$CL=0x10",
            b"$CT=10",
            b"$VS=0",
            b"$VL=0",
            b'$VA=""',
        ),
        records=b"",
    )
    descriptor = SegmentDescriptor.from_kex_block(block)

    vendor_compatible = (info.target_mask & descriptor.target_type_mask) != 0

    tt_bytes = bytes.fromhex(tt_text.decode("ascii").split('"')[1].replace(" ", ""))
    prior_compatible = (
        int.from_bytes(reply_prefix, "little") & int.from_bytes(tt_bytes, "little")
    ) != 0

    assert vendor_compatible == prior_compatible


#: One non-canonical edit per SegmentDescriptor field, applied to the first
#: positive-control descriptor; the calibration preflight must reject each.
_NONCANONICAL_FIELD_EDITS: dict[
    str, Callable[[SegmentDescriptor], SegmentDescriptor]
] = {
    "flash_start_addr": lambda d: replace(d, flash_start_addr=0x6000_0000),
    "data_length": lambda d: replace(d, data_length=1),
    "erase_length": lambda d: replace(d, erase_length=1),
    "target_type_mask": lambda d: replace(d, target_type_mask=0x02),
    "erase_wait_seconds": lambda d: replace(d, erase_wait_seconds=1),
    "expected_before_checksum": lambda d: replace(d, expected_before_checksum=1),
    "expected_after_checksum": lambda d: replace(d, expected_after_checksum=1),
    "checksum_start_offset": lambda d: replace(d, checksum_start_offset=1),
    "checksum_length": lambda d: replace(d, checksum_length=1),
    "checksum_wait_seconds": lambda d: replace(d, checksum_wait_seconds=9),
    "version_start_offset": lambda d: replace(d, version_start_offset=1),
    "version_length": lambda d: replace(
        d,
        version_length=2,
        version_check_bytes=b"\x1c\x00",
    ),
    "version_check_bytes": lambda d: replace(d, version_check_bytes=b"\x1d"),
    "chunk_size": lambda d: replace(d, chunk_size=1),
}


def test_target_info_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="17 bytes"):
        _ = decode_target_info(b"\x00" * 16)


class TestTargetInfoD75Validation:
    """matches_d75_v103 accepts only the stock D75 V1.03 baseline.

    It returns True for the empirically-observed healthy stock-D75 V1.03
    baseline and False for anything else. Non-matching values don't
    necessarily mean broken — the operator is alerted to verify manually.
    """

    def _stock_d75_v103_payload(self) -> bytes:
        # Exact bytes a real D75 V1.03 returns on QUERY_TARGET,
        # captured via thd75-flash --probe-target on macOS.
        return bytes.fromhex(
            "02 00 00 00 00 00 00 00"  # bytes used for target compatibility
            "02 00 00 00 00 00 00 00"  # updater leaves bytes 8..15 opaque
            "00".replace(" ", "")  # separately consumed trailing byte
        )

    def test_stock_d75_v103_matches(self) -> None:
        info = decode_target_info(self._stock_d75_v103_payload())
        assert info.matches_d75_v103()
        assert info.d75_mismatch_reasons() == []

    def test_wrong_variant_mask_does_not_match(self) -> None:
        # Variant mask 0x01 instead of 0x02 — could be a D74 or
        # a different D75 sub-variant.
        payload = bytearray(self._stock_d75_v103_payload())
        payload[0] = 0x01
        info = decode_target_info(bytes(payload))
        assert not info.matches_d75_v103()
        reasons = info.d75_mismatch_reasons()
        assert len(reasons) == 1
        assert "target_mask_bytes" in reasons[0]
        assert "01 00 00 00 00 00 00 00" in reasons[0]

    def test_wrong_loader_mask_does_not_match(self) -> None:
        payload = bytearray(self._stock_d75_v103_payload())
        payload[8] = 0x04
        info = decode_target_info(bytes(payload))
        assert not info.matches_d75_v103()
        reasons = info.d75_mismatch_reasons()
        assert any("opaque_bytes_8_15" in r for r in reasons)

    def test_nonzero_status_does_not_match(self) -> None:
        payload = bytearray(self._stock_d75_v103_payload())
        payload[16] = 0x05
        info = decode_target_info(bytes(payload))
        assert not info.matches_d75_v103()
        reasons = info.d75_mismatch_reasons()
        assert any("trailing_status" in r for r in reasons)

    def test_multiple_mismatches_each_reported(self) -> None:
        # Variant + loader + status all wrong: 3 reasons listed.
        payload = bytes([0x99] + [0] * 7 + [0x99] + [0] * 7 + [0xFF])
        info = decode_target_info(payload)
        assert not info.matches_d75_v103()
        assert len(info.d75_mismatch_reasons()) == 3


class TestProbeTargetOnly:
    """probe_target_only is the no-known-write-verb deep probe.

    --probe-target uses it. It validates the framed round trip without any
    segment or COMPLETE verb; target-side loader nonmutation is not asserted.
    """

    def test_returns_decoded_target_info(self) -> None:
        payload = (
            (0xAA).to_bytes(8, "little") + (0xBB).to_bytes(8, "little") + bytes([0x42])
        )
        radio = MockRadio(
            responsive_at_bauds=(9600,),
            target_info_payload=payload,
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        info = session.probe_target_only(baud_ladder=(9600,))
        assert info.target_mask == 0xAA00_0000_0000_0000
        assert info.opaque_bytes_8_15 == (0xBB).to_bytes(8, "little")
        assert info.trailing_status == 0x42

    def test_sends_only_official_entry_through_query_target(self) -> None:
        # No segment, erase, or completion verb is sent.
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        _ = session.probe_target_only(baud_ladder=(9600,))
        # MockRadio's verb_log records framed verbs the radio received.
        assert radio.verb_log == [
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
        ]

    def test_no_nor_writes(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        _ = session.probe_target_only(baud_ladder=(9600,))
        # MockRadio records SEND_CHUNK bytes into .transferred; the
        # The deep probe must never trigger a chunk write.
        assert radio.transferred == b""

    def test_handshake_timeout_overridable(self) -> None:
        # Real hardware needs ~2s default; tests with MockRadio can use
        # 50ms. Verify the timeout flows through.
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(
            radio, FlashSessionOptions(handshake_timeout=0.01)
        )  # very tight
        # 10ms is still enough for MockRadio (instant response).
        _ = session.probe_target_only(baud_ladder=(9600,))

    def test_handshake_failure_propagates(self) -> None:
        radio = MockRadio(responsive_at_bauds=(115200,))  # never matches
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.01))
        with pytest.raises(HandshakeError):
            _ = session.probe_target_only(baud_ladder=(9600, 19200))

    def test_malformed_target_payload_is_a_query_step_failure(self) -> None:
        radio = MockRadio(
            responsive_at_bauds=(9600,),
            target_info_payload=b"\x00" * 16,
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))

        with pytest.raises(FlashError, match="must be 17 bytes") as exc_info:
            _ = session.probe_target_only(baud_ladder=(9600,))

        assert exc_info.value.step == "QUERY_TARGET"
        assert exc_info.value.recoverable is True
        assert radio.verb_log == [
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
        ]


class TestSetupOnlyCalibration:
    """The calibration API exposes only two exact, audited SETUP plans."""

    _allowed_verbs = frozenset(
        {
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
            int(Verb.BAUD_AND_ACK),
            int(Verb.SETUP_SEGMENT),
        }
    )
    _forbidden_verbs = frozenset(
        {
            int(Verb.BEGIN_TRANSFER),
            int(Verb.SEND_CHUNK),
            int(Verb.END_TRANSFER),
            int(Verb.VERIFY_SEGMENT),
            int(Verb.COMPLETE_UPDATE),
            int(Verb.SELECT_TARGET),
        }
    )

    def test_positive_controls_use_exact_prelude_and_allowlist(self) -> None:
        descriptors, _ = _setup_calibration_plan(allow_mismatch_repeat=False)
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x00", b"\x00", b"\x00"),
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))

        outcome = session.calibrate_setup_controls_only()

        assert isinstance(outcome, SetupCalibrationOutcome)
        assert outcome.target.matches_d75_v103()
        assert outcome.setup_results == (0, 0, 0)
        assert radio.verb_log == [
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
            int(Verb.BAUD_AND_ACK),
            int(Verb.SETUP_SEGMENT),
            int(Verb.SETUP_SEGMENT),
            int(Verb.SETUP_SEGMENT),
        ]
        assert set(radio.verb_log) <= self._allowed_verbs
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)
        assert radio.setup_payloads == [item.to_recovery_wire() for item in descriptors]
        assert radio.transferred == b""
        assert radio.wire_writes[0] == CLEARTEXT_MAGIC
        assert radio.baud_log == [576_000]
        assert radio.framed_acks is True
        assert [frame.payload for frame in radio.command_frames[:4]] == [
            b"\x00",  # ENTER_PROGRAM
            b"",  # TIMED_SESSION
            b"",  # QUERY_TARGET
            b"\x12\x01",  # BAUD_AND_ACK: 576000 + per-packet ACK
        ]

    def test_default_stops_after_first_result_one(self) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x01", b"\x00"),
        )

        with pytest.raises(FlashError, match="expected SETUP result 0") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    def test_default_stops_on_later_unexpected_result(self) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x00", b"\x01", b"\x00"),
        )

        with pytest.raises(FlashError, match="refusing any follow-up") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[1]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 2

    def test_explicit_mismatch_repeat_is_exactly_one_follow_up(self) -> None:
        descriptors, _ = _setup_calibration_plan(allow_mismatch_repeat=True)
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x01", b"\x00"),
        )

        outcome = FlashSession(
            radio, FlashSessionOptions(handshake_timeout=0.05)
        ).calibrate_setup_mismatch_repeat_only()

        assert outcome.setup_results == (1, 0)
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 2
        assert radio.setup_payloads == [item.to_recovery_wire() for item in descriptors]
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    @pytest.mark.parametrize(
        ("results", "expected_count"),
        [
            ((b"\x00", b"\x00"), 1),
            ((b"\x01", b"\x01"), 2),
        ],
    )
    def test_explicit_mismatch_repeat_fails_closed_on_deviation(
        self,
        results: tuple[bytes, ...],
        expected_count: int,
    ) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=results,
        )

        with pytest.raises(FlashError, match="expected SETUP result"):
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_mismatch_repeat_only()

        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == expected_count
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    def test_outcome_is_immutable(self) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x00", b"\x00", b"\x00"),
        )
        outcome = FlashSession(
            radio, FlashSessionOptions(handshake_timeout=0.05)
        ).calibrate_setup_controls_only()

        field_name = "setup_results"
        with pytest.raises(AttributeError):
            setattr(outcome, field_name, (1,))

    @pytest.mark.parametrize(
        "field_name",
        [
            "flash_start_addr",
            "data_length",
            "erase_length",
            "target_type_mask",
            "erase_wait_seconds",
            "expected_before_checksum",
            "expected_after_checksum",
            "checksum_start_offset",
            "checksum_length",
            "checksum_wait_seconds",
            "version_start_offset",
            "version_length",
            "version_check_bytes",
            "chunk_size",
        ],
    )
    def test_internal_preflight_rejects_every_noncanonical_field(
        self,
        field_name: str,
    ) -> None:
        descriptors, expected = _setup_calibration_plan(
            allow_mismatch_repeat=False,
        )
        modified = list(descriptors)
        edit = _NONCANONICAL_FIELD_EDITS.get(field_name)
        if edit is None:
            msg = f"unhandled descriptor field: {field_name}"
            raise AssertionError(msg)
        modified[0] = edit(modified[0])

        with pytest.raises(FlashError, match="allowlisted plan") as exc_info:
            _validate_setup_calibration_plan(
                modified,
                expected,
                allow_mismatch_repeat=False,
            )

        assert exc_info.value.step == "SETUP_CALIBRATION_PREFLIGHT"

    def test_internal_preflight_rejects_wrong_expected_results(self) -> None:
        descriptors, _ = _setup_calibration_plan(allow_mismatch_repeat=False)
        with pytest.raises(FlashError, match="expected_results"):
            _validate_setup_calibration_plan(
                descriptors,
                (0, 1, 0),
                allow_mismatch_repeat=False,
            )

    def test_non_d75_target_aborts_before_baud_or_setup(self) -> None:
        non_d75_payload = (
            (0x01).to_bytes(8, "little") + (0x02).to_bytes(8, "little") + b"\x00"
        )
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            target_info_payload=non_d75_payload,
            setup_results=(b"\x00", b"\x00", b"\x00"),
        )

        with pytest.raises(FlashError) as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "TARGET_COMPATIBILITY"
        assert radio.verb_log == [
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
        ]
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    @pytest.mark.parametrize("payload", [b"", b"\x02", b"\x00\x01"])
    def test_malformed_result_aborts_without_following_setup(
        self,
        payload: bytes,
    ) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(payload, b"\x00"),
        )

        with pytest.raises(FlashError, match="one byte 0") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    def test_setup_nak_aborts_without_following_setup(self) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            fault=MockRadioFault.SETUP_SEGMENT_NAK,
        )

        with pytest.raises(FlashError) as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert exc_info.value.recoverable is True
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    def test_setup_timeout_is_wrapped_and_aborts(self) -> None:
        radio = _TimeoutOnSetupRadio(
            responsive_at_bauds=(576_000,),
        )

        with pytest.raises(FlashError, match="simulated SETUP timeout") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1
        assert set(radio.verb_log).isdisjoint(self._forbidden_verbs)

    def test_transport_failure_is_wrapped_with_setup_step(self) -> None:
        radio = _TransportErrorOnSetupRadio(
            responsive_at_bauds=(576_000,),
        )

        with pytest.raises(FlashError, match="simulated USB") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1

    def test_frame_error_is_wrapped_with_setup_step(self) -> None:
        radio = _FrameErrorOnSetupRadio(
            responsive_at_bauds=(576_000,),
        )

        with pytest.raises(FlashError, match="FrameError") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1

    def test_wrong_response_verb_aborts_after_one_setup(self) -> None:
        radio = _WrongVerbOnSetupRadio(
            responsive_at_bauds=(576_000,),
        )

        with pytest.raises(FlashError, match="unexpected response verb") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 1

    def test_stale_decoded_response_blocks_next_command(self) -> None:
        radio = _ExtraAckAfterBaudRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x00", b"\x00", b"\x00"),
        )

        with pytest.raises(FlashError, match="unconsumed response") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 0

    def test_session_reuse_rejected_without_more_io(self) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x00", b"\x00", b"\x00"),
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        _ = session.calibrate_setup_controls_only()
        write_count = len(radio.wire_writes)

        with pytest.raises(FlashError, match="single-use") as exc_info:
            _ = session.calibrate_setup_mismatch_repeat_only()

        assert exc_info.value.step == "SETUP_MISMATCH_REPEAT_PREFLIGHT"
        assert len(radio.wire_writes) == write_count

    def test_failed_session_is_also_consumed(self) -> None:
        radio = _CleartextSetupRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x01",),
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        with pytest.raises(FlashError):
            _ = session.calibrate_setup_controls_only()
        write_count = len(radio.wire_writes)

        with pytest.raises(FlashError, match="single-use"):
            _ = session.calibrate_setup_controls_only()

        assert len(radio.wire_writes) == write_count


class TestD75SendChunkFormat:
    """SEND_CHUNK on D75 has an 8-byte offset + chunk_length header.

    That header precedes the data, vs D74's 4-byte offset-only header. The
    .NET updater (n.cs::a(bool)) writes the chunk_length on every chunk even
    though it's constant per segment. See NOTE in session.py.
    """

    def test_chunks_carry_explicit_length(self) -> None:
        # Trace 1 segment of 2 chunks through MockRadio; verify both
        # offset AND chunk_length are present in each SEND_CHUNK payload.
        radio = MockRadio(responsive_at_bauds=(9600,))
        # Small chunk so 2 chunks fit easily.
        session = FlashSession(
            radio, FlashSessionOptions(chunk_size=128, handshake_timeout=0.05)
        )
        data_len = 256  # 2 x 128
        data = bytes(range(256))
        seg = SegmentDescriptor(
            flash_start_addr=0x00200000,
            data_length=data_len,
            erase_length=data_len,
            target_type_mask=0xFFFFFFFFFFFFFFFF,
            erase_wait_seconds=1,
            expected_before_checksum=0xFFFF,
            expected_after_checksum=firmware_checksum(data),
            checksum_start_offset=0,
            checksum_length=data_len,
            checksum_wait_seconds=1,
            version_start_offset=0,
            version_length=0,
            version_check_bytes=b"",
        )
        # MockRadio.transferred sums up the actual data bytes; if our
        # 8-byte header is correctly stripped, the chunks reassemble
        # into the original 256 bytes.
        radio.target_info_payload = (
            b"\x02" + b"\x00" * 7 + b"\x02" + b"\x00" * 7 + b"\x00"
        )
        # Drive ONLY the chunk parts — full flash includes COMPLETE
        # which the MockRadio doesn't fully simulate. We don't care
        # about completion here; we care that MockRadio's assert in
        # _handle_frame passes (declared_length matches data length).
        # MockRadio may complain about COMPLETE; chunk send is what matters.
        with contextlib.suppress(Exception):
            _ = session.flash_segments([seg], {0: data})
        # MockRadio's transferred property concatenates written bytes.
        # If our chunk format is right, all 256 bytes should be there.
        assert radio.transferred == data

    def test_trims_segment_data_to_descriptor_data_length(self) -> None:
        """Stream only $DL bytes when a KEX payload runs on to $EL.

        KEX-parsed segments often carry more bytes than $DL (the
        intel-hex coverage equals the erase region $EL, which rounds
        up to a 32 KiB sector boundary). The vendor only streams $DL
        bytes per segment — the trailing $EL-$DL bytes are 0xFF
        erase fill the radio never receives. Sending those extra
        bytes would over-shoot the loader's per-segment data
        counter. Verified against stock V1.03: segments 1 and 4 are
        32 KiB bigger in $EL than $DL.
        """
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(
            radio, FlashSessionOptions(chunk_size=256, handshake_timeout=0.05)
        )
        # Segment: $DL=256, $EL=512. We pass 512 bytes of data
        # (matching what intel_hex.parse would return for a vendor
        # segment with this $DL/$EL pair). The flasher should only
        # stream the first 256 bytes via SEND_CHUNK.
        seg = SegmentDescriptor(
            flash_start_addr=0x60200000,
            data_length=256,
            erase_length=512,
            target_type_mask=STOCK_TARGET_TYPE_MASK_D75_V103,
            erase_wait_seconds=1,
            expected_before_checksum=0xFFFF,
            expected_after_checksum=0,
            checksum_start_offset=0,
            checksum_length=256,
            checksum_wait_seconds=1,
            version_start_offset=0,
            version_length=0,
            version_check_bytes=b"",
        )
        full_data = bytes(range(256)) + b"\xff" * 256  # 256 real + 256 erase-pad
        # The mock may not love the VERIFY mismatch; what matters is the chunk
        # stream.
        with contextlib.suppress(Exception):
            _ = session.flash_segments([seg], {0: full_data})
        # Only the first 256 bytes should have been transferred —
        # NOT the trailing 0xFF erase-pad.
        assert radio.transferred == bytes(range(256)), (
            f"flasher streamed {len(radio.transferred)} bytes; "
            f"expected exactly $DL=256. Trim-to-data_length regressed."
        )

    def test_rejects_unproven_short_final_packet_before_io(self) -> None:
        """Refuse a short final packet before any I/O.

        Vendor D75 sends exact $DU packets; short-final D75 support has never
        succeeded on hardware, so raw input must be padded.
        """
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(
            radio, FlashSessionOptions(chunk_size=256, handshake_timeout=0.05)
        )
        seg = SegmentDescriptor(
            flash_start_addr=0x00200000,
            data_length=300,
            erase_length=300,
            target_type_mask=0xFFFFFFFFFFFFFFFF,
            erase_wait_seconds=1,
            expected_before_checksum=0xFFFF,
            expected_after_checksum=0x3343,
            checksum_start_offset=0,
            checksum_length=300,
            checksum_wait_seconds=1,
            version_start_offset=0,
            version_length=0,
            version_check_bytes=b"",
        )
        with pytest.raises(FlashError, match="short-final"):
            _ = session.flash_segments([seg], {0: b"\x00" * 300})

        assert radio.verb_log == []

    @pytest.mark.parametrize("flash_start_addr", [0, 0x6000_0000])
    def test_rejects_low_nor_descriptor_before_io(
        self,
        flash_start_addr: int,
    ) -> None:
        """The session API cannot bypass the CLI's low-NOR prohibition."""
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(
            radio, FlashSessionOptions(chunk_size=256, handshake_timeout=0.05)
        )
        segments, segment_data = _minimal_kex()
        segments[0] = replace(segments[0], flash_start_addr=flash_start_addr)

        with pytest.raises(FlashError, match="forbidden NOR span"):
            _ = session.flash_segments(segments, segment_data)

        assert radio.verb_log == []


class TestD75BaudAndAckPayload:
    """BAUD_AND_ACK (verb 0x33) tells the loader which baud-mode policy to apply.

    For the selected ack-each-packet profile, the official updater does not
    change host line coding after the ACK. The keyed path remains at the
    19200 rate restored after unlock; the local cleartext path was already
    opened at 576000.

    The recovery profile uses baud_code 0x12
    (576000, ack_each_data_packet=True). Together with 256-byte chunks and one
    END_TRANSFER per segment, this completed full stock restores on real D75
    hardware on 2026-07-05 and 2026-07-25.

    Any change to this constant should also update the NOTE block in
    session.py and verify against real hardware (the radio may NAK
    unsupported baud_codes).
    """

    def test_payload_is_576000_with_ack_each_packet(self) -> None:
        # The cleanest way to capture what the host actually sends:
        # a MockRadio that records each frame's payload keyed by verb.
        radio = _CapturingRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        _ = session.flash_segments(segments, segment_data)

        baud_payloads = radio.captured_payloads.get(int(Verb.BAUD_AND_ACK), [])
        assert len(baud_payloads) == 1, (
            f"expected exactly one BAUD_AND_ACK, got {len(baud_payloads)}"
        )
        assert baud_payloads[0] == bytes([0x12, 0x01]), (
            f"BAUD_AND_ACK payload changed from proven 0x12 0x01 to "
            f"{baud_payloads[0].hex(' ')} — that's a hardware-affecting "
            f"change. Update the NOTE block in session.py and re-validate "
            f"against the radio."
        )
        # The flag is not a free choice: it is the ACK policy the loader's
        # own table pairs with that code.
        assert baud_payloads[0][1] == 0x01, (
            "baud code 0x12 pairs with ack_each_data_packet=1 in the loader's table"
        )


class TestD75CompleteUpdatePayload:
    """Keep official u16 and hardware-tested u32 modes explicit."""

    def test_payload_is_4_bytes_le(self) -> None:
        radio = _CapturingRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        # Pass the stock V1.03 #FC value to verify the LE encoding.
        _ = session.flash_segments(
            segments, segment_data, FlashRunOptions(complete_update_value=0x1DB0)
        )

        payloads = radio.captured_payloads.get(int(Verb.COMPLETE_UPDATE), [])
        assert len(payloads) == 1, (
            f"expected exactly one COMPLETE_UPDATE, got {len(payloads)}"
        )
        assert payloads[0] == bytes([0xB0, 0x1D, 0x00, 0x00]), (
            f"COMPLETE_UPDATE payload changed from 4-byte LE u32 to "
            f"{payloads[0].hex(' ')} ({len(payloads[0])} bytes) — the "
            f"hardware-tested OpenWood-compatible format is exactly "
            f"4 LE bytes of the #FC value. Any other size is a "
            f"regression."
        )

    def test_vendor_width_is_2_bytes_le(self) -> None:
        radio = _CapturingRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        _ = session.flash_segments(
            segments,
            segment_data,
            FlashRunOptions(complete_update_value=0x1DB0, complete_update_width=2),
        )

        payloads = radio.captured_payloads.get(int(Verb.COMPLETE_UPDATE), [])
        assert payloads == [b"\xb0\x1d"]

    def test_default_is_hardware_tested_d75_code_as_u32(self) -> None:
        """The library default is the only u32 value proven on this D75."""
        radio = _CapturingRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        _ = session.flash_segments(segments, segment_data)

        payloads = radio.captured_payloads.get(int(Verb.COMPLETE_UPDATE), [])
        assert payloads == [b"\xb0\x1d\x00\x00"]

    def test_rejects_value_outside_u32_range(self) -> None:
        """Reject a completion value that does not fit in a u32, before any I/O.

        A silent .to_bytes overflow would mis-format the wire bytes.
        Validation must happen before handshake or any flash verb.
        """
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        with pytest.raises(FlashError, match="4-byte") as exc_info:
            _ = session.flash_segments(
                segments,
                segment_data,
                FlashRunOptions(complete_update_value=0x1_0000_0000),
            )
        assert exc_info.value.step == "PREFLIGHT"
        assert radio.verb_log == []
        assert radio.transferred == b""

    def test_rejects_u16_overflow_before_io(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError, match="2-byte"):
            _ = session.flash_segments(
                segments,
                segment_data,
                FlashRunOptions(
                    complete_update_value=0x1_0000, complete_update_width=2
                ),
            )

        assert radio.verb_log == []


class TestFlashPreflight:
    """Caller-input failures must be found before handshake or NOR I/O."""

    @staticmethod
    def _assert_no_device_commands(radio: MockRadio) -> None:
        assert radio.verb_log == []
        assert radio.transferred == b""

    def test_empty_plan_is_rejected_before_handshake(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio)

        with pytest.raises(FlashError, match="no segments") as exc_info:
            _ = session.flash_segments([], {})

        assert exc_info.value.step == "PREFLIGHT"
        self._assert_no_device_commands(radio)

    def test_missing_segment_payload_is_rejected_before_handshake(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio)
        segments, _ = _minimal_kex()

        with pytest.raises(FlashError, match="missing payload indices") as exc_info:
            _ = session.flash_segments(segments, {})

        assert exc_info.value.step == "PREFLIGHT"
        self._assert_no_device_commands(radio)

    def test_unexpected_segment_payload_index_is_rejected(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()
        segment_data[1] = b"unexpected"

        with pytest.raises(FlashError, match="unexpected payload indices"):
            _ = session.flash_segments(segments, segment_data)

        self._assert_no_device_commands(radio)

    def test_short_segment_payload_is_rejected_before_handshake(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()
        segment_data[0] = segment_data[0][:-1]

        with pytest.raises(FlashError, match="shorter than descriptor"):
            _ = session.flash_segments(segments, segment_data)

        self._assert_no_device_commands(radio)

    @pytest.mark.parametrize("chunk_size", [0, -1, 2049])
    def test_invalid_chunk_size_is_rejected_without_io(self, chunk_size: int) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))

        with pytest.raises(ValueError, match=r"1\.\.2048"):
            _ = FlashSession(radio, FlashSessionOptions(chunk_size=chunk_size))

        self._assert_no_device_commands(radio)

    @pytest.mark.parametrize("chunk_size", [1, 2048])
    def test_chunk_size_boundaries_are_accepted(self, chunk_size: int) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        _ = FlashSession(radio, FlashSessionOptions(chunk_size=chunk_size))

        self._assert_no_device_commands(radio)


class TestCommandTransportFailures:
    """Post-unlock I/O failures retain the exact command that became uncertain."""

    def test_short_write_stops_before_followup_command(self) -> None:
        radio = _ShortFramedWriteRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError, match="short transport write") as exc_info:
            _ = session.flash_segments(segments, segment_data)

        assert exc_info.value.step == "ENTER_PROGRAM"
        assert radio.verb_log == [int(Verb.ENTER_PROGRAM)]

    def test_response_timeout_is_not_leaked_without_command_context(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = _ImmediateResponseTimeoutSession(
            radio, FlashSessionOptions(handshake_timeout=0.05)
        )
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError, match="simulated command timeout") as exc_info:
            _ = session.flash_segments(segments, segment_data)

        assert exc_info.value.step == "ENTER_PROGRAM"
        assert radio.verb_log == [int(Verb.ENTER_PROGRAM)]

    def test_post_unlock_baud_restore_failure_has_state_context_and_no_frame(
        self,
    ) -> None:
        radio = _PostUnlockBaudFailureRadio(responsive_at_bauds=(38_400,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))

        with pytest.raises(FlashError) as exc_info:
            _ = session.probe_target_only(baud_ladder=(38_400,))

        error = exc_info.value
        assert error.step == "POST_UNLOCK_BAUD_RESTORE"
        assert "after the loader accepted the keyed unlock" in error.cause
        assert "disconnect USB and fully power-cycle" in error.cause
        assert radio.verb_log == []

    def test_reference_response_windows_follow_ct_and_et_per_reply(self) -> None:
        """The proven profile extends only the commands OpenWood extends.

        SETUP and VERIFY each use ``$CT + 30``. BEGIN uses ``$ET + 30`` for
        every response independently, so the BUSY and following ACK each get
        the full window. Host-only ``$EM`` does not narrow that policy.
        """
        radio = MockRadio(
            responsive_at_bauds=(38_400,),
            erase_busy_iterations=1,
        )
        session = _RecordingReplyTimeoutSession(
            radio,
            handshake_timeout=0.05,
        )
        segments, segment_data = _minimal_kex()
        segments[0] = replace(
            segments[0],
            erase_wait_seconds=7,
            checksum_wait_seconds=11,
            erase_budget_seconds=1,
        )

        _ = session.flash_segments(
            segments, segment_data, FlashRunOptions(baud_ladder=(38_400,))
        )

        by_verb = {
            verb: [
                timeout
                for recorded_verb, timeout in session.response_timeouts
                if recorded_verb is verb
            ]
            for verb in Verb
        }
        assert by_verb[Verb.ENTER_PROGRAM] == [30.0]
        assert by_verb[Verb.SETUP_SEGMENT] == [41.0]
        assert by_verb[Verb.BEGIN_TRANSFER] == [37.0, 37.0]
        assert by_verb[Verb.VERIFY_SEGMENT] == [41.0]
        assert by_verb[Verb.COMPLETE_UPDATE] == [30.0]


class TestTargetCompatibilityGate:
    """Target mismatches abort before BAUD_AND_ACK or any per-segment verb.

    They may be discovered only after QUERY_TARGET, but must abort before
    BAUD_AND_ACK or any per-segment write verb.
    """

    def test_non_d75_profile_aborts_before_segment_setup(self) -> None:
        payload = (0x01).to_bytes(8, "little") + (0x02).to_bytes(8, "little") + b"\x00"
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            target_info_payload=payload,
        )
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError) as exc_info:
            _ = session.flash_segments(segments, segment_data)

        assert exc_info.value.step == "TARGET_COMPATIBILITY"
        assert radio.verb_log == [
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
        ]
        assert radio.transferred == b""

    def test_malformed_target_payload_retains_post_handshake_context(self) -> None:
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            target_info_payload=b"\x00" * 16,
        )
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError, match="must be 17 bytes") as exc_info:
            _ = session.flash_segments(segments, segment_data)

        assert exc_info.value.step == "QUERY_TARGET"
        assert exc_info.value.recoverable is True
        assert radio.verb_log == [
            int(Verb.ENTER_PROGRAM),
            int(Verb.TIMED_SESSION),
            int(Verb.QUERY_TARGET),
        ]
        assert int(Verb.BAUD_AND_ACK) not in radio.verb_log
        assert int(Verb.SETUP_SEGMENT) not in radio.verb_log
        assert radio.transferred == b""

    def test_segment_target_mask_mismatch_aborts_before_setup(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()
        segments[0] = replace(segments[0], target_type_mask=0x01)

        with pytest.raises(FlashError, match="does not include radio target mask"):
            _ = session.flash_segments(segments, segment_data)

        assert int(Verb.BAUD_AND_ACK) not in radio.verb_log
        assert int(Verb.SETUP_SEGMENT) not in radio.verb_log
        assert radio.transferred == b""


class TestSetupDecision:
    """SETUP returns one decision byte and #AF controls skip policy."""

    def test_current_segment_is_skipped_when_not_forced(self) -> None:
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            setup_result=b"\x00",
        )
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()

        outcome = session.flash_segments(
            segments, segment_data, FlashRunOptions(always_flash=False)
        )

        assert outcome.segments_written == 0
        assert int(Verb.BEGIN_TRANSFER) not in radio.verb_log
        assert int(Verb.SEND_CHUNK) not in radio.verb_log
        assert radio.verb_log[-1] == int(Verb.COMPLETE_UPDATE)

    def test_current_segment_is_written_when_forced(self) -> None:
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            setup_result=b"\x00",
        )
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()

        outcome = session.flash_segments(
            segments, segment_data, FlashRunOptions(always_flash=True)
        )

        assert outcome.segments_written == 1
        assert int(Verb.BEGIN_TRANSFER) in radio.verb_log
        assert int(Verb.SEND_CHUNK) in radio.verb_log

    def test_only_selected_current_segment_is_written(self, tmp_path: Path) -> None:
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            setup_result=b"\x00",
        )
        trace_path = tmp_path / "run.trace"
        segments, segment_data = _minimal_kex()
        first = segments[0]
        segments.append(
            replace(
                first,
                flash_start_addr=first.flash_start_addr + first.data_length,
            )
        )
        segment_data[1] = segment_data[0]

        with WireTrace(trace_path) as trace:
            outcome = FlashSession(radio, trace=trace).flash_segments(
                segments,
                segment_data,
                FlashRunOptions(
                    always_flash=False, force_segment_indices=frozenset({1})
                ),
            )

        assert outcome.segments_written == 1
        assert len(radio.segment_writes) == 2
        assert radio.segment_writes[0].data == b""
        assert radio.segment_writes[0].begin_transfers == 0
        assert radio.segment_writes[1].data == segment_data[1]
        assert radio.segment_writes[1].begin_transfers == 1
        notes = trace_path.read_text(encoding="utf-8").splitlines()
        assert "# segment_1 setup=current; qualification force-write" in notes

    @pytest.mark.parametrize(
        "forced_indices",
        [
            frozenset({-1}),
            frozenset({1}),
            frozenset({0, 2}),
        ],
    )
    def test_invalid_selective_force_index_fails_before_io(
        self,
        forced_indices: frozenset[int],
    ) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError, match="force_segment_indices") as exc_info:
            _ = session.flash_segments(
                segments,
                segment_data,
                FlashRunOptions(
                    always_flash=False, force_segment_indices=forced_indices
                ),
            )

        assert exc_info.value.step == "PREFLIGHT"
        assert radio.wire_writes == ()
        assert radio.verb_log == []

    @pytest.mark.parametrize("payload", [b"", b"\x02", b"\x00\x01"])
    def test_malformed_setup_result_aborts_before_begin(self, payload: bytes) -> None:
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            setup_result=payload,
        )
        session = FlashSession(radio)
        segments, segment_data = _minimal_kex()

        with pytest.raises(FlashError, match="one byte 0"):
            _ = session.flash_segments(segments, segment_data)

        assert int(Verb.BEGIN_TRANSFER) not in radio.verb_log
        assert int(Verb.SEND_CHUNK) not in radio.verb_log


class TestExtractFcTag:
    """CLI helper that pulls the KEX file's ``#FC=`` completion code.

    The code comes from the top-level metadata so it can be passed through
    to the session as the COMPLETE_UPDATE value.
    """

    def test_extracts_stock_v103_fc_from_canonical_plaintext(self) -> None:
        plaintext_path = Path("recovery/TH-D75_V103_stock_plaintext.KEX")
        if plaintext_path.exists():
            plaintext = plaintext_path.read_bytes()
        else:
            resource_path = Path(
                "ref/TH-D75_V103_E/THD75_Updater_E.Resources.TH-D75_Firm_E.txt"
            )
            if not resource_path.exists():
                pytest.skip("official V1.03 encrypted resource not present")
            plaintext = kex.render(
                kex.parse_encrypted_resource(
                    resource_path.read_text(encoding="utf-8"),
                )
            )
        assert hashlib.sha256(plaintext).hexdigest() == (
            "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"
        )
        kex_image = kex.parse_kex_bytes(plaintext)
        assert _extract_fc_tag(kex_image) == 0x1DB0
        assert _validate_d75_v103_kex_profile(kex_image) is True

    def test_rejects_missing_fc(self) -> None:
        empty_kex = Kex(blocks=(KexBlock(metadata=(), records=b""),))
        with pytest.raises(ValueError, match="#FC"):
            _ = _extract_fc_tag(empty_kex)

    @staticmethod
    def _profile(*, af: int = 1, include_tu: bool = True) -> Kex:
        metadata = [
            b"#TC=0",
            b"#FC=0x1DB0",
            f"#AF={af}".encode(),
            b'#FV="V1.03.000      "',
            b"#DN=7",
            b"#BR=57600,0",
            b"#BR=576000,1",
        ]
        if include_tu:
            metadata.append(b"#TU=1")
        blocks = [KexBlock(metadata=tuple(metadata), records=b"")]
        blocks.extend(KexBlock(metadata=(), records=b"") for _ in range(6))
        return Kex(blocks=tuple(blocks))

    def test_profile_returns_af_policy(self) -> None:
        assert (
            _validate_d75_v103_kex_profile(
                self._profile(af=0),
            )
            is False
        )

    def test_profile_rejects_missing_required_tag(self) -> None:
        with pytest.raises(ValueError, match="#TU"):
            _ = _validate_d75_v103_kex_profile(
                self._profile(include_tu=False),
            )


class TestFramedAckMode:
    """Real D75 V1.03 hardware emits ACKs as framed replies.

    Those are ``Frame(verb=0x06, payload=b"")``, not bare ``0x06`` bytes.
    The mock radio defaults to bare for back-compat with existing
    tests, but ``framed_acks=True`` mirrors the actual radio. These
    tests run the full happy path against the framed-ACK mock to
    catch any regression in our framed-form handling.
    """

    def test_happy_path_with_framed_acks(self) -> None:
        radio = MockRadio(
            responsive_at_bauds=(9600,),
            framed_acks=True,
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        outcome = session.flash_segments(segments, segment_data)
        assert outcome.segments_written == len(segments)
        # Verify the radio actually emitted framed ACKs (verb 0x06)
        # by checking the verb_log includes our expected verbs but
        # the test got through without an UnframedResponse failure.
        assert int(Verb.SETUP_SEGMENT) in radio.verb_log
        assert int(Verb.COMPLETE_UPDATE) in radio.verb_log


class TestExactCountReplyReads:
    """The session must size every reply read from the decoder.

    ``pyserial``'s ``read(n)`` returns early only once *n* bytes exist, so a
    fixed ceiling makes every reply wait out the port timeout instead of the
    radio's round trip. Over a per-packet-ACK data phase that is one timeout
    per chunk. These tests pin the request counts themselves, because the mock
    radio answers instantly and so cannot show the cost.
    """

    @dataclass
    class _RecordingRadio(MockRadio):
        """Mock radio that records the byte count of every read request."""

        read_requests: list[int] = field(default_factory=list[int], init=False)

        @override
        def read(self, max_bytes: int) -> bytes:
            self.read_requests.append(max_bytes)
            return super().read(max_bytes)

    class _OneByteAtATimeRadio(_RecordingRadio):
        """Mock radio that hands back a single byte however much is asked.

        Models a transport that returns mid-frame, which USB-CDC does. The
        response stream must still decode: reassembly across reads is the
        ``ResponseReader``'s job, not something the transport has to avoid.
        """

        @override
        def read(self, max_bytes: int) -> bytes:
            return super().read(min(max_bytes, 1))

    def test_no_reply_read_asks_for_more_than_a_reply_can_be(self) -> None:
        radio = self._RecordingRadio(
            responsive_at_bauds=(9600,),
            framed_acks=True,
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        _ = session.flash_segments(segments, segment_data)

        # The longest reply the loader sends is QUERY_TARGET: a 17-byte
        # payload in a 26-byte frame. Anything larger is a ceiling nobody
        # derived from the wire, and on a real port it costs a full timeout.
        assert radio.read_requests, "no reads were recorded"
        assert max(radio.read_requests) <= 26, (
            f"session requested {max(radio.read_requests)} bytes; reply reads "
            "must be sized from ResponseReader.bytes_needed, not a ceiling"
        )

    def test_framed_reply_is_read_in_exact_stages(self) -> None:
        radio = self._RecordingRadio(
            responsive_at_bauds=(9600,),
            framed_acks=True,
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        _ = session.probe_target_only(baud_ladder=(9600,))

        # The handshake reads the two-byte unlock reply first, asking for the
        # unread remainder of it and nothing more.
        assert radio.read_requests[0] == len(UNLOCK_REPLY)
        reply_reads = radio.read_requests[1:]

        # Then every framed reply follows OpenWood's low-level read cadence:
        # one classifying/first-sync byte, one second-sync byte, the six-byte
        # HH + LL + VV header, then body_length bytes (payload + checksum).
        # A framed ACK has body_length 1, so its exact shape is 1/1/6/1.
        assert reply_reads[:4] == [1, 1, 6, 1], (
            f"ENTER_PROGRAM's framed ACK was read as {reply_reads[:4]}, "
            "expected the staged 1/1/6/1 shape"
        )
        # QUERY_TARGET's body_length is 18 (verb + 17-byte payload), and after
        # OpenWood has already read the verb its final 18-byte read consists
        # of the payload plus checksum.
        assert reply_reads[-4:] == [1, 1, 6, 18]

    def test_an_extra_reply_left_on_the_transport_still_blocks_the_next_verb(
        self,
    ) -> None:
        """Exact-count reads must not cost the desynchronised-link guard.

        Over-sized reads used to hoover an unsolicited extra reply into
        ``_pending``, where the pre-send check found it. Sized reads leave it
        on the transport, so the check has to look there too; otherwise the
        next verb goes out onto an out-of-phase link and its reply is the one
        blamed.
        """
        radio = _ExtraAckAfterBaudRadio(
            responsive_at_bauds=(576_000,),
            setup_results=(b"\x00", b"\x00", b"\x00"),
        )

        with pytest.raises(FlashError, match="waiting on the transport") as exc_info:
            _ = FlashSession(
                radio, FlashSessionOptions(handshake_timeout=0.05)
            ).calibrate_setup_controls_only()

        assert exc_info.value.step == "SETUP_CALIBRATION[0]"
        assert radio.verb_log.count(int(Verb.SETUP_SEGMENT)) == 0, (
            "a command reached the loader after the link was known to be out of phase"
        )

    def test_replies_reassemble_when_the_transport_returns_mid_frame(self) -> None:
        """A transport that never fills a request must not break decoding.

        This is the claim that an inter-byte timeout "dropped" responses
        because the reader had no signal more was coming. The reader treats
        every short buffer as "wait for more", so a full flash completes even
        when every read returns one byte.
        """
        radio = self._OneByteAtATimeRadio(
            responsive_at_bauds=(9600,),
            framed_acks=True,
        )
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.5))
        segments, segment_data = _minimal_kex()
        outcome = session.flash_segments(segments, segment_data)

        assert outcome.segments_written == len(segments)
        assert int(Verb.COMPLETE_UPDATE) in radio.verb_log


class TestEntrySequenceOmissions:
    """The flasher uses the entry sequence that completed a real D75 flash.

    That flash was V1.03. SELECT_TARGET is deliberately omitted; TIMED_SESSION
    is sent once at its proven position. These tests pin both choices.

    See the NOTE block in session.py (just before flash_segments)
    for the full reasoning. Short version: SELECT_TARGET triggers
    "Error Data Error!!" on D75 V1.03 hardware so is permanently
    omitted. TIMED_SESSION was previously omitted on the assumption
    that it was "unnecessary"; it is now sent before QUERY_TARGET to
    match the OpenWood/vendor ordering used for the successful flash.
    """

    def test_flash_segments_omits_select_target(self) -> None:
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        _ = session.flash_segments(segments, segment_data)
        sent = set(radio.verb_log)
        assert int(Verb.SELECT_TARGET) not in sent, (
            "SELECT_TARGET must not be sent — triggers 'Error Data Error!!' "
            "on D75 V1.03. See NOTE in session.py."
        )

    def test_flash_segments_sends_timed_session(self) -> None:
        """Send TIMED_SESSION between ENTER_PROGRAM and QUERY_TARGET.

        TIMED_SESSION must be sent between ENTER_PROGRAM and
        QUERY_TARGET — matches both openwood's hardware-tested D74
        client (``updater.py::update``) AND the .NET D75 updater's
        state machine (``f.cs::a(m)`` state c.e → case 33 →
        ``i()`` which sends ``o.a(160, null)``). The previous
        "Error Data Error!!" hardware failure was caused by sending
        TIMED_SESSION at the WRONG position (after BAUD_AND_ACK
        instead of after ENTER_PROGRAM), not by sending it at all.

        This docstring used to close with "openwood's V1.03 reflash via
        this exact ordering completes cleanly on D75 in ~4 minutes".
        Withdrawn as UNVERIFIED: no flash duration is recorded anywhere
        in this repo, and openwood is a TH-D74 client. What this test
        actually pins is the verb ORDER, which is what the evidence
        above supports.
        """
        radio = MockRadio(responsive_at_bauds=(9600,))
        session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.05))
        segments, segment_data = _minimal_kex()
        _ = session.flash_segments(segments, segment_data)
        sent = set(radio.verb_log)
        assert int(Verb.TIMED_SESSION) in sent, (
            "TIMED_SESSION must be sent — see NOTE in session.py for "
            "the openwood/vendor-validated entry sequence."
        )


def test_session_skips_verify_when_checksum_length_is_zero() -> None:
    """Skip VERIFY_SEGMENT for a descriptor whose $CL is zero.

    Stock-style overlay descriptors use $CL=0 as the state-machine
    signal to proceed directly from END_TRANSFER to the next segment
    or COMPLETE_UPDATE without issuing VERIFY_SEGMENT.
    """
    radio = MockRadio(responsive_at_bauds=(38400,))
    session = FlashSession(radio)
    checked_segments, checked_data = _minimal_kex()
    checked = checked_segments[0]
    overlay = replace(
        checked,
        flash_start_addr=checked.flash_start_addr + checked.data_length,
        erase_length=0,
        checksum_length=0,
    )

    outcome = session.flash_segments(
        [checked, overlay],
        {0: checked_data[0], 1: checked_data[0]},
    )

    assert outcome.segments_written == 2
    assert radio.verb_log.count(int(Verb.BEGIN_TRANSFER)) == 2
    assert radio.verb_log.count(int(Verb.VERIFY_SEGMENT)) == 1
    assert radio.verb_log[-1] == int(Verb.COMPLETE_UPDATE)


def test_flash_error_carries_diagnostic_context() -> None:
    err = FlashError(
        step="SETUP_SEGMENT[FIRMWARE]",
        cause="NAK 0x15 0x02",
        recoverable=True,
    )
    assert err.step == "SETUP_SEGMENT[FIRMWARE]"
    assert err.cause == "NAK 0x15 0x02"
    assert err.recoverable is True
    assert "SETUP_SEGMENT[FIRMWARE]" in str(err)


def test_flash_outcome_is_frozen() -> None:
    info = TargetInfo(
        raw_payload=b"\x00" * 17,
        target_mask_bytes=b"\x01" + b"\x00" * 7,
        opaque_bytes_8_15=b"\x02" + b"\x00" * 7,
        trailing_status=0x00,
    )
    outcome = FlashOutcome(
        target=info,
        segments_written=7,
        bytes_written=41 * 1024 * 1024,
        elapsed_seconds=272.0,
    )
    field_name = "segments_written"
    with pytest.raises(AttributeError):
        setattr(outcome, field_name, 0)


def _minimal_kex() -> tuple[list[SegmentDescriptor], dict[int, bytes]]:
    # Data length must be a multiple of FlashSession.DEFAULT_CHUNK_SIZE
    # (256) because D75 SEND_CHUNK requires equal-sized chunks — the
    # vendor .NET updater enforces the same. Use exactly one chunk's
    # worth of data so the SEND_CHUNK loop runs once.
    data_len = FlashSession.DEFAULT_CHUNK_SIZE  # 256
    segments = [
        SegmentDescriptor(
            flash_start_addr=0x00200000,
            data_length=data_len,
            erase_length=data_len,
            target_type_mask=0xFFFFFFFFFFFFFFFF,
            erase_wait_seconds=1,
            expected_before_checksum=0xFFFF,
            expected_after_checksum=0x3343,
            checksum_start_offset=0,
            checksum_length=data_len,
            checksum_wait_seconds=1,
            version_start_offset=0,
            version_length=0,
            version_check_bytes=b"",
        )
    ]
    return segments, {0: b"\x00" * data_len}


def test_session_happy_path_full_verb_sequence() -> None:
    radio = MockRadio(responsive_at_bauds=(38400,))
    session = FlashSession(radio)
    segments, segment_data = _minimal_kex()
    outcome = session.flash_segments(segments, segment_data)
    assert outcome.segments_written == 1
    # Verb sequence: matches openwood's hardware-tested D74 client
    # AND the .NET D75 updater's state machine. SELECT_TARGET (0xA3)
    # is permanently omitted because it triggers "Error Data Error!!"
    # on D75 V1.03 hardware. TIMED_SESSION (0xA0) goes between
    # ENTER_PROGRAM and QUERY_TARGET — this is the order that
    # produces a successful ~4-minute V1.03 reflash on real D75
    # hardware (proved via openwood's fldm.py on May 25, 2026).
    assert radio.verb_log == [
        Verb.ENTER_PROGRAM,
        Verb.TIMED_SESSION,
        Verb.QUERY_TARGET,
        Verb.BAUD_AND_ACK,
        Verb.SETUP_SEGMENT,
        Verb.BEGIN_TRANSFER,
        Verb.SEND_CHUNK,
        Verb.END_TRANSFER,
        Verb.VERIFY_SEGMENT,
        Verb.COMPLETE_UPDATE,
    ]


def test_session_proven_path_uses_cleartext_unlock_and_30s_base(
    monkeypatch: MonkeyPatch,
) -> None:
    observed_unlock_timeouts: list[float] = []

    def recording_unlock(
        transport: MockRadio,
        *,
        baud: int,
        timeout: float,
    ) -> HandshakeResult:
        observed_unlock_timeouts.append(timeout)
        return perform_cleartext_unlock(
            transport,
            baud=baud,
            timeout=timeout,
        )

    monkeypatch.setattr(
        flash_session,
        "perform_cleartext_unlock",
        recording_unlock,
    )
    radio = MockRadio(
        responsive_at_bauds=(576_000,),
        framed_acks=True,
    )
    session = FlashSession(radio, FlashSessionOptions(handshake_timeout=0.001))
    segments, segment_data = _minimal_kex()

    outcome = session.flash_segments(
        segments,
        segment_data,
        FlashRunOptions(cleartext_unlock=True, cleartext_baud=576_000),
    )

    assert outcome.segments_written == 1
    assert observed_unlock_timeouts == [30.0]
    assert radio.wire_writes[0] == CLEARTEXT_MAGIC
    assert radio.transfer_mode == (576_000, True)
    assert radio.transferred == segment_data[0]


def test_cleartext_two_segment_golden_raw_wire_transcript() -> None:
    """Pin every host write for a body plus a zero-erase overlay.

    The expected tuple is deliberately literal: no frame builder, descriptor
    serializer, or checksum helper participates in producing the golden bytes.
    """
    body = bytes.fromhex("10 20 30 40")
    overlay_data = bytes.fromhex("aa 55")
    body_descriptor = SegmentDescriptor(
        flash_start_addr=0x0020_0000,
        data_length=4,
        erase_length=4,
        target_type_mask=STOCK_TARGET_TYPE_MASK_D75_V103,
        erase_wait_seconds=1,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x6040,
        checksum_start_offset=0,
        checksum_length=4,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    overlay_descriptor = SegmentDescriptor(
        flash_start_addr=0x0020_0004,
        data_length=2,
        erase_length=0,
        target_type_mask=STOCK_TARGET_TYPE_MASK_D75_V103,
        erase_wait_seconds=0,
        expected_before_checksum=0x55AA,
        expected_after_checksum=0x55AA,
        checksum_start_offset=0,
        checksum_length=0,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
        chunk_size=2,
    )
    radio = MockRadio(
        responsive_at_bauds=(576_000,),
        framed_acks=True,
        verify_checksum=True,
    )

    outcome = FlashSession(radio, FlashSessionOptions(chunk_size=4)).flash_segments(
        [body_descriptor, overlay_descriptor],
        {0: body, 1: overlay_data},
        FlashRunOptions(
            always_flash=False, cleartext_unlock=True, cleartext_baud=576_000
        ),
    )

    expected_writes = (
        bytes.fromhex("46 50 52 4f 4d 4f 44"),  # FPROMOD
        bytes.fromhex("ab ab 00 02 00 00 00 30 00 32"),  # ENTER
        bytes.fromhex("ab ab 00 01 00 00 00 a0 a1"),  # TIMED
        bytes.fromhex("ab ab 00 01 00 00 00 31 32"),  # QUERY
        bytes.fromhex("ab ab 00 03 00 00 00 33 12 01 49"),  # BAUD
        bytes.fromhex(  # body SETUP
            "ab ab 00 35 00 00 00 40 "
            "00 00 20 00 04 00 00 00 04 00 00 00 00 00 00 00 "
            "0f 00 00 00 00 00 00 00 01 00 00 00 ff ff 40 60 "
            "00 00 00 00 04 00 00 00 02 00 00 00 00 00 00 00 "
            "00 00 00 00 51"
        ),
        bytes.fromhex("ab ab 00 01 00 00 00 42 43"),  # body BEGIN
        bytes.fromhex(  # body DATA
            "ab ab 00 0d 00 00 00 43 00 00 00 00 04 00 00 00 10 20 30 40 f4"
        ),
        bytes.fromhex("ab ab 00 01 00 00 00 44 45"),  # body END
        bytes.fromhex("ab ab 00 01 00 00 00 45 46"),  # body VERIFY
        bytes.fromhex(  # overlay SETUP ($EL=0, $CL=0)
            "ab ab 00 35 00 00 00 40 "
            "04 00 20 00 02 00 00 00 00 00 00 00 00 00 00 00 "
            "0f 00 00 00 00 00 00 00 00 00 00 00 aa 55 aa 55 "
            "00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 "
            "00 00 00 00 aa"
        ),
        bytes.fromhex("ab ab 00 01 00 00 00 42 43"),  # overlay BEGIN
        bytes.fromhex(  # overlay DATA
            "ab ab 00 0b 00 00 00 43 00 00 00 00 02 00 00 00 aa 55 4f"
        ),
        bytes.fromhex("ab ab 00 01 00 00 00 44 45"),  # overlay END
        bytes.fromhex("ab ab 00 05 00 00 00 50 b0 1d 00 00 22"),  # COMPLETE u32
    )

    assert outcome.segments_written == 2
    assert radio.wire_writes == expected_writes


def test_session_aborts_on_setup_nak() -> None:
    radio = MockRadio(
        responsive_at_bauds=(38400,),
        fault=MockRadioFault.SETUP_SEGMENT_NAK,
    )
    session = FlashSession(radio)
    segments, segment_data = _minimal_kex()
    with pytest.raises(FlashError) as exc_info:
        _ = session.flash_segments(segments, segment_data)
    assert "SETUP_SEGMENT" in exc_info.value.step
    assert exc_info.value.recoverable is True


def test_session_aborts_on_verify_failure_status() -> None:
    """VERIFY returns one status byte: zero succeeds, one fails."""
    radio = MockRadio(
        responsive_at_bauds=(38400,),
        fault=MockRadioFault.VERIFY_FAILED,
    )
    session = FlashSession(radio)
    segments, segment_data = _minimal_kex()

    with pytest.raises(FlashError, match="checksum did not match") as exc_info:
        _ = session.flash_segments(segments, segment_data)

    assert exc_info.value.step.startswith("VERIFY_SEGMENT")
    assert int(Verb.COMPLETE_UPDATE) not in radio.verb_log


# ─── Streamed data phase (ack_each_data_packet = 0) ────────────────────────


#: Chunk size the streaming tests flash at, small enough to keep fixtures
#: readable and large enough that a segment is several packets rather than
#: one, which is what makes "between chunks" a real place.
_STREAM_CHUNK = 256


def _streamed_segment(
    *,
    chunks: int,
    flash_start_addr: int = 0x0020_0000,
    fill: int = 0xA5,
) -> tuple[SegmentDescriptor, bytes]:
    """One erasable, verifiable segment of exactly ``chunks`` data packets.

    ``$CA`` is computed from the payload so a loader that actually
    checksums (``MockRadio.verify_checksum``) agrees with a complete
    transfer and disagrees with an incomplete one.
    """
    data = bytes([fill]) * (_STREAM_CHUNK * chunks)
    descriptor = SegmentDescriptor(
        flash_start_addr=flash_start_addr,
        data_length=len(data),
        erase_length=len(data),
        target_type_mask=0xFFFFFFFFFFFFFFFF,
        erase_wait_seconds=1,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=firmware_checksum(data),
        checksum_start_offset=0,
        checksum_length=len(data),
        checksum_wait_seconds=1,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
        chunk_size=_STREAM_CHUNK,
        checksum_chunk=_STREAM_CHUNK,
    )
    return descriptor, data


def _use_acknowledged_mode(monkeypatch: MonkeyPatch) -> None:
    """Select the 576000/ACK-every-packet mode for the whole session.

    The mode is a module constant rather than a parameter because a real
    flash must not be able to choose one, so a test that needs the *other*
    branch swaps the constant. Both sides read the same
    ``_FLDM_BAUD_MODES`` table for the paired ACK policy, so this flips the
    host and the loader together and cannot produce a combination the
    hardware would never see.
    """
    monkeypatch.setattr(flash_session, "_FLDM_TRANSFER_MODE_CODE", 0x12)


def _use_streaming_mode(monkeypatch: MonkeyPatch) -> None:
    """Select the unacknowledged 115200 diagnostic branch."""
    monkeypatch.setattr(flash_session, "_FLDM_TRANSFER_MODE_CODE", 0x0A)


@dataclass
class _StreamEventRadio(MockRadio):
    """Record reads, decoded verbs, and waiting-byte checks in one order."""

    events: list[str] = field(default_factory=list[str], init=False)

    @override
    def read(self, max_bytes: int) -> bytes:
        self.events.append("read")
        return super().read(max_bytes)

    @override
    def pending_input(self) -> int:
        self.events.append("pending_input")
        return super().pending_input()

    @override
    def _handle_frame(self, frame: Frame) -> None:
        self.events.append(f"verb:{frame.verb:#04x}")
        super()._handle_frame(frame)


@dataclass(kw_only=True)
class _NakOnNthChunkRadio(MockRadio):
    """Reject exactly one data packet, by position within the segment."""

    nak_chunk_index: int
    _chunks_seen: int = field(default=0, init=False)

    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SEND_CHUNK:
            index = self._chunks_seen
            self._chunks_seen += 1
            if index == self.nak_chunk_index:
                self._verb_log.append(frame.verb)
                self._record_chunk(frame.payload)
                self._send_raw(b"\x15\x03")  # data packet/write rejected
                return
        super()._handle_frame(frame)


@dataclass(kw_only=True)
class _DropLastChunkRadio(MockRadio):
    """Lose the final data packet of a segment in transit.

    The loader never sees it, so those bytes stay erased and the segment's
    checksum cannot match. Dropping the *last* packet keeps every packet
    that does arrive contiguous, so the fixture's offset-ordering rule
    still holds and the only thing under test is the missing data.
    """

    drop_after_chunks: int
    _chunks_seen: int = field(default=0, init=False)

    @override
    def _handle_frame(self, frame: Frame) -> None:
        if frame.verb == Verb.SEND_CHUNK:
            self._chunks_seen += 1
            if self._chunks_seen > self.drop_after_chunks:
                return
        super()._handle_frame(frame)


class _NoPendingInputTransport:
    """A transport with every SerialIO method except the waiting-byte one."""

    def __init__(self, radio: MockRadio) -> None:
        super().__init__()
        self._radio = radio

    def write(self, data: bytes) -> int:
        return self._radio.write(data)

    def read(self, max_bytes: int) -> bytes:
        return self._radio.read(max_bytes)

    def set_baud(self, baud: int) -> None:
        self._radio.set_baud(baud)

    def discard_input(self) -> None:
        self._radio.discard_input()


class TestStreamedDataPhase:
    """The non-default ``ack_each_data_packet=0`` diagnostic mode.

    In this mode the loader answers no data packet at all, so the host
    writes chunks back to back and the only synchronisation points are
    END_TRANSFER and the segment VERIFY. Everything here pins a property
    that only holds because of that: what the data phase must not do, what
    it must still notice, and what still catches a bad segment when no
    packet is acknowledged.
    """

    @pytest.fixture(autouse=True)
    def _select_streaming_mode(self, monkeypatch: MonkeyPatch) -> None:
        """Keep streaming tests explicit now that recovery defaults to ACK."""
        _use_streaming_mode(monkeypatch)

    def test_data_phase_never_reads_between_chunks(self) -> None:
        """A read here would cost the port timeout on every single chunk.

        The loader owes nothing until END_TRANSFER, so a read between
        chunks cannot return early; it waits out the transport timeout and
        then returns empty. Once per chunk, that is the difference between
        a minute-scale flash and an hours-scale one.
        """
        radio = _StreamEventRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        _ = session.flash_segments([descriptor], {0: data})

        chunk_verb = f"verb:{int(Verb.SEND_CHUNK):#04x}"
        end_verb = f"verb:{int(Verb.END_TRANSFER):#04x}"
        events = radio.events
        data_phase = events[events.index(chunk_verb) : events.index(end_verb)]

        assert data_phase.count(chunk_verb) == 4, (
            f"expected a four-packet data phase, saw {data_phase}"
        )
        assert "read" not in data_phase, (
            "the streamed data phase read from the transport; in this mode "
            "the loader replies to nothing, so every such read waits out the "
            f"port timeout. Events: {data_phase}"
        )

    def test_streaming_checks_for_waiting_bytes_between_chunks(self) -> None:
        """The one thing the data phase does do: glance, without blocking.

        Every chunk must be followed by a waiting-byte check before the next
        one goes out, and the last chunk by one before END_TRANSFER takes
        the port. The count is not pinned, only the placement: a rejected
        chunk has to be noticed while there is still a segment left to
        stop sending.
        """
        radio = _StreamEventRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        _ = session.flash_segments([descriptor], {0: data})

        chunk_verb = f"verb:{int(Verb.SEND_CHUNK):#04x}"
        end_verb = f"verb:{int(Verb.END_TRANSFER):#04x}"
        events = radio.events
        data_phase = events[events.index(chunk_verb) : events.index(end_verb)]

        # Split the phase at each chunk: every resulting gap is what
        # happened between that chunk and the next thing on the wire.
        gaps = [
            segment.split()
            for segment in " ".join(data_phase).split(chunk_verb)
            if segment.strip()
        ]
        assert len(gaps) == 4, f"expected four post-chunk gaps, saw {data_phase}"
        assert all("pending_input" in gap for gap in gaps), (
            f"a chunk was followed by no waiting-byte check: {data_phase}"
        )

    def test_acknowledged_mode_reads_a_reply_for_every_chunk(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """The contrast that makes the no-read assertion above meaningful.

        In the acknowledged mode a read per chunk is the protocol, not a
        bug: the loader owes an ACK for each data packet and the host must
        collect it. That is exactly the cost the streamed mode avoids.
        """
        _use_acknowledged_mode(monkeypatch)
        radio = _StreamEventRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        _ = session.flash_segments([descriptor], {0: data})

        chunk_verb = f"verb:{int(Verb.SEND_CHUNK):#04x}"
        end_verb = f"verb:{int(Verb.END_TRANSFER):#04x}"
        events = radio.events
        first_chunk = events.index(chunk_verb)
        data_phase = events[first_chunk : events.index(end_verb, first_chunk)]

        assert "read" in data_phase, (
            "the acknowledged mode must read each chunk's ACK; if it stopped "
            "doing so the replies would accumulate unread"
        )

    def test_end_transfer_is_once_per_segment_while_streaming(self) -> None:
        """The OEM's non-acknowledged writer emits no 0x44 until the end.

        Its acknowledged writer flags end-of-cluster every ``$DC`` bytes and
        sends 0x44 there; the streaming one has no cluster handshake to
        perform, so a per-packet END would be an invention.
        """
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        _ = session.flash_segments([descriptor], {0: data})

        assert radio.verb_log.count(int(Verb.SEND_CHUNK)) == 4
        assert radio.verb_log.count(int(Verb.END_TRANSFER)) == 1, (
            "streaming sent more than one END_TRANSFER for one segment; the "
            f"per-$DC cadence belongs to the acknowledged mode. Verbs: "
            f"{[hex(v) for v in radio.verb_log]}"
        )
        assert radio.segment_writes[0].end_transfers == 1

    def test_acknowledged_mode_ends_once_per_segment(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """The proven ACK profile still ends only after the final packet."""
        _use_acknowledged_mode(monkeypatch)
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        _ = session.flash_segments([descriptor], {0: data})

        assert radio.verb_log.count(int(Verb.SEND_CHUNK)) == 4
        assert radio.verb_log.count(int(Verb.END_TRANSFER)) == 1

    def test_mid_stream_nak_is_blamed_on_the_chunk_not_end_transfer(
        self,
    ) -> None:
        """The regression this check exists for.

        Nothing in a streamed data phase reads, so a rejected chunk's NAK
        used to sit in the receive queue until END_TRANSFER's read consumed
        it — reporting the failure against END_TRANSFER, after the rest of
        the segment had already been written into a loader that had stopped
        accepting it.
        """
        radio = _NakOnNthChunkRadio(
            nak_chunk_index=1,
            responsive_at_bauds=(38400,),
        )
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=8)

        with pytest.raises(FlashError) as exc_info:
            _ = session.flash_segments([descriptor], {0: data})

        error = exc_info.value
        assert error.step == f"SEND_CHUNK[segment_0]@{_STREAM_CHUNK}", (
            f"a rejected chunk was reported against {error.step!r}"
        )
        assert "END_TRANSFER" not in error.step
        # Alive and refusing a write is a recoverable condition: the
        # operator power-cycles and diagnoses, rather than being told the
        # bootloader may be damaged.
        assert error.recoverable is True

    def test_mid_stream_nak_stops_the_rest_of_the_segment(self) -> None:
        """Detection is worth nothing if the remaining chunks still go out."""
        radio = _NakOnNthChunkRadio(
            nak_chunk_index=1,
            responsive_at_bauds=(38400,),
        )
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=8)

        with pytest.raises(FlashError):
            _ = session.flash_segments([descriptor], {0: data})

        assert radio.verb_log.count(int(Verb.SEND_CHUNK)) == 2, (
            "the host kept streaming after the loader rejected a chunk; "
            f"verbs: {[hex(v) for v in radio.verb_log]}"
        )
        assert int(Verb.END_TRANSFER) not in radio.verb_log
        assert int(Verb.VERIFY_SEGMENT) not in radio.verb_log
        assert int(Verb.COMPLETE_UPDATE) not in radio.verb_log

    def test_nak_on_the_final_chunk_is_still_a_chunk_failure(self) -> None:
        """The last packet has no next chunk to be checked before.

        Its rejection is caught by the look taken after the loop and before
        END_TRANSFER, so it is still reported as a data-phase failure at the
        right offset.
        """
        radio = _NakOnNthChunkRadio(
            nak_chunk_index=3,
            responsive_at_bauds=(38400,),
        )
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        with pytest.raises(FlashError) as exc_info:
            _ = session.flash_segments([descriptor], {0: data})

        assert exc_info.value.step == f"SEND_CHUNK[segment_0]@{_STREAM_CHUNK * 3}"
        assert int(Verb.END_TRANSFER) not in radio.verb_log

    @pytest.mark.parametrize("acknowledged", [False, True])
    def test_write_chunk_nak_fault_aborts_in_either_mode(
        self,
        monkeypatch: MonkeyPatch,
        *,
        acknowledged: bool,
    ) -> None:
        """The fixture's own rejection fault, which nothing exercised before.

        ``WRITE_CHUNK_NAK`` refuses every data packet, so the abort lands on
        the first one. It says the same thing in both transfer modes, by two
        different routes: the acknowledged mode reads the NAK where it
        expected an ACK, and the streamed mode finds it waiting after a write
        it never intended to read for.
        """
        if acknowledged:
            _use_acknowledged_mode(monkeypatch)
        radio = MockRadio(
            responsive_at_bauds=(38400,),
            fault=MockRadioFault.WRITE_CHUNK_NAK,
        )
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        with pytest.raises(FlashError) as exc_info:
            _ = session.flash_segments([descriptor], {0: data})

        error = exc_info.value
        assert error.step == "SEND_CHUNK[segment_0]@0"
        assert error.recoverable is True
        assert radio.verb_log.count(int(Verb.SEND_CHUNK)) == 1, (
            "a rejected first packet did not stop the segment; verbs: "
            f"{[hex(v) for v in radio.verb_log]}"
        )
        assert int(Verb.END_TRANSFER) not in radio.verb_log
        assert int(Verb.COMPLETE_UPDATE) not in radio.verb_log

    def test_acknowledged_mode_mid_stream_nak_fails_at_the_chunk(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """The same rejection in the mode that reads every reply.

        This path never needed the waiting-byte check, and it still does not
        — the NAK arrives where an ACK was expected. Pinned alongside the
        streamed case so both modes are known to fail at the same place.
        """
        _use_acknowledged_mode(monkeypatch)
        radio = _NakOnNthChunkRadio(
            nak_chunk_index=1,
            responsive_at_bauds=(38400,),
        )
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=8)

        with pytest.raises(FlashError) as exc_info:
            _ = session.flash_segments([descriptor], {0: data})

        error = exc_info.value
        assert error.step == f"SEND_CHUNK[segment_0]@{_STREAM_CHUNK}"
        assert error.recoverable is True
        assert radio.verb_log.count(int(Verb.SEND_CHUNK)) == 2
        assert int(Verb.VERIFY_SEGMENT) not in radio.verb_log
        assert int(Verb.COMPLETE_UPDATE) not in radio.verb_log

    def test_verify_passes_a_complete_streamed_segment(self) -> None:
        """Positive control for the checksum-accurate loader.

        Without this, a loader that failed every verify would make the next
        test pass for the wrong reason.
        """
        radio = MockRadio(responsive_at_bauds=(38400,), verify_checksum=True)
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        outcome = session.flash_segments([descriptor], {0: data})

        assert outcome.segments_written == 1
        assert radio.segment_writes[0].data == data
        assert radio.verb_log[-1] == int(Verb.COMPLETE_UPDATE)

    def test_verify_catches_a_chunk_lost_in_transit(self) -> None:
        """Streaming cannot silently pass a corrupt segment.

        No data packet is acknowledged in this mode, so a packet that never
        arrives leaves no trace in the exchange at all. What catches it is
        the segment checksum: the loader sums what it can read back over
        ``$CS..$CS+$CL``, the missing bytes are still erased, and the sum
        cannot match the ``$CA`` computed from the complete image.
        """
        radio = _DropLastChunkRadio(
            drop_after_chunks=3,
            responsive_at_bauds=(38400,),
            verify_checksum=True,
        )
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        descriptor, data = _streamed_segment(chunks=4)

        with pytest.raises(FlashError, match="checksum did not match") as exc_info:
            _ = session.flash_segments([descriptor], {0: data})

        assert exc_info.value.step == "VERIFY_SEGMENT[segment_0]"
        assert len(radio.segment_writes[0].data) == _STREAM_CHUNK * 3
        assert int(Verb.COMPLETE_UPDATE) not in radio.verb_log, (
            "a segment with a missing chunk completed the update"
        )

    def test_streaming_is_refused_without_a_waiting_byte_check(self) -> None:
        """Fail closed, and fail before anything has been erased.

        A transport that cannot report waiting bytes cannot notice a
        rejected chunk, because nothing else in the data phase reads. The
        session refuses at BAUD_AND_ACK rather than discovering it mid
        segment, which would mean discovering it after an erase.

        The transport is duck-typed, so the type checker's refusal below is
        the static half of the same statement and is suppressed rather than
        worked around: the point is that the runtime refuses too, instead of
        raising ``AttributeError`` on a chunk after the erase.
        """
        radio = MockRadio(responsive_at_bauds=(38400,))
        session = FlashSession(
            # Deliberately violates the transport Protocol: the runtime refusal
            # is what this test pins (see the docstring).
            _NoPendingInputTransport(radio),  # type: ignore[arg-type]
        )
        descriptor, data = _streamed_segment(chunks=2)

        with pytest.raises(FlashError, match="pending_input") as exc_info:
            _ = session.flash_segments([descriptor], {0: data})

        assert exc_info.value.step == "BAUD_AND_ACK"
        assert int(Verb.BAUD_AND_ACK) not in radio.verb_log, (
            "the mode was declared to the loader before the host checked it "
            "could run it"
        )
        assert int(Verb.SETUP_SEGMENT) not in radio.verb_log
        assert int(Verb.BEGIN_TRANSFER) not in radio.verb_log

    def test_multi_segment_stream_sends_the_exact_verb_sequence(self) -> None:
        """A full streamed flash of an erasable segment plus an overlay.

        This is the stock shape in miniature: a body segment that erases,
        streams, ends, and verifies, followed by an overlay that declares
        ``$EL=0`` and ``$CL=0``. The proven OpenWood sequence still sends
        BEGIN for that overlay, but skips VERIFY.
        The whole point of the streamed mode is visible in the sequence:
        four data packets and exactly one END_TRANSFER for the body, with
        nothing from the loader in between.
        """
        radio = MockRadio(responsive_at_bauds=(38400,), verify_checksum=True)
        session = FlashSession(radio, FlashSessionOptions(chunk_size=_STREAM_CHUNK))
        body, body_data = _streamed_segment(chunks=4)
        overlay_data = b"\x5a" * 32
        overlay = SegmentDescriptor(
            flash_start_addr=body.flash_start_addr + 0x40,
            data_length=len(overlay_data),
            erase_length=0,
            target_type_mask=0xFFFFFFFFFFFFFFFF,
            erase_wait_seconds=0,
            expected_before_checksum=firmware_checksum(overlay_data),
            expected_after_checksum=firmware_checksum(overlay_data),
            checksum_start_offset=0,
            checksum_length=0,  # no VERIFY_SEGMENT
            checksum_wait_seconds=10,
            version_start_offset=0,
            version_length=0,
            version_check_bytes=b"",
            chunk_size=len(overlay_data),
            checksum_chunk=len(overlay_data),
        )

        outcome = session.flash_segments(
            [body, overlay],
            {0: body_data, 1: overlay_data},
        )

        assert outcome.segments_written == 2
        assert radio.verb_log == [
            Verb.ENTER_PROGRAM,
            Verb.TIMED_SESSION,
            Verb.QUERY_TARGET,
            Verb.BAUD_AND_ACK,
            Verb.SETUP_SEGMENT,
            Verb.BEGIN_TRANSFER,
            Verb.SEND_CHUNK,
            Verb.SEND_CHUNK,
            Verb.SEND_CHUNK,
            Verb.SEND_CHUNK,
            Verb.END_TRANSFER,
            Verb.VERIFY_SEGMENT,
            Verb.SETUP_SEGMENT,
            Verb.BEGIN_TRANSFER,
            Verb.SEND_CHUNK,
            Verb.END_TRANSFER,
            Verb.COMPLETE_UPDATE,
        ]
        assert radio.transfer_mode == (115_200, False)
        assert radio.segment_writes[0].data == body_data
        assert radio.segment_writes[1].data == overlay_data
