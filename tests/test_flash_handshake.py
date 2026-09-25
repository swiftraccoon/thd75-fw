"""Tests for thd75_fw.flash.handshake."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.fixtures.mock_radio import MockRadio
from thd75_fw.flash.handshake import (
    BAUD_LADDER,
    CLEARTEXT_MAGIC,
    MAGIC,
    UNLOCK_REPLY,
    AmbiguousUnlockError,
    HandshakeError,
    HandshakeResult,
    Probe,
    build_probe,
    derive_xor_key,
    perform_cleartext_unlock,
    perform_handshake,
)


class _RecordingTransport:
    def __init__(
        self,
        *,
        write_result: int | None = None,
        write_error: BaseException | None = None,
        read_error: BaseException | None = None,
        fail_set_call: int | None = None,
        fail_discard_call: int | None = None,
    ) -> None:
        super().__init__()
        self.write_result = write_result
        self.write_error = write_error
        self.read_error = read_error
        self.fail_set_call = fail_set_call
        self.fail_discard_call = fail_discard_call
        self.calls: list[tuple[str, object]] = []
        self._set_calls = 0
        self._discard_calls = 0

    def write(self, data: bytes) -> int:
        self.calls.append(("write", data))
        if self.write_error is not None:
            raise self.write_error
        return len(data) if self.write_result is None else self.write_result

    def read(self, max_bytes: int) -> bytes:
        self.calls.append(("read", max_bytes))
        if self.read_error is not None:
            raise self.read_error
        return b""

    def set_baud(self, baud: int) -> None:
        self._set_calls += 1
        self.calls.append(("set_baud", baud))
        if self._set_calls == self.fail_set_call:
            msg = "simulated set_baud failure"
            raise OSError(msg)

    def discard_input(self) -> None:
        self._discard_calls += 1
        self.calls.append(("discard_input", None))
        if self._discard_calls == self.fail_discard_call:
            msg = "simulated discard failure"
            raise OSError(msg)


class TestConstants:
    def test_magic(self) -> None:
        assert MAGIC == b"Thd75tw"
        assert len(MAGIC) == 7

    def test_unlock_reply_is_two_raw_bytes(self) -> None:
        # The on-wire reply after a successful unlock is exactly two
        # raw bytes — 0x16 (unlock ACK) then 0x06 (mode-change OK).
        # NOT the "TH-D75  " string an earlier (broken) version of
        # this code waited for; that string is only used inside
        # derive_xor_key as the sum-derivation constant.
        # Verified on real D75 V1.03 hardware: after a successful
        # keyed-unlock probe, the loader sends exactly these two raw
        # bytes back, in this order, not XOR-scrambled. They arrive
        # together (or with a brief gap; perform_handshake accumulates
        # within its per-baud timeout).
        assert UNLOCK_REPLY == b"\x16\x06"
        assert len(UNLOCK_REPLY) == 2

    def test_baud_ladder_matches_dotnet_updater(self) -> None:
        # f.cs:600-630 baud rates, in the order the .NET updater tries
        assert BAUD_LADDER == (19200, 4800, 38400, 57600, 9600)


class TestProbe:
    def test_construction(self) -> None:
        p = Probe(prefix=b"\x00\x00", minute=42, second=15)
        assert p.prefix == b"\x00\x00"
        assert p.minute == 42
        assert p.second == 15

    def test_to_wire_length(self) -> None:
        wire = Probe(prefix=b"\x12\x34", minute=42, second=15).to_wire()
        assert len(wire) == 11

    def test_to_wire_layout(self) -> None:
        wire = Probe(prefix=b"\x12\x34", minute=42, second=15).to_wire()
        assert wire == b"\x12\x34" + b"Thd75tw" + bytes([42, 15])

    def test_rejects_wrong_prefix_length(self) -> None:
        with pytest.raises(ValueError, match="prefix must be 2 bytes"):
            _ = Probe(prefix=b"\x00", minute=0, second=0).to_wire()


class TestBuildProbe:
    def test_uses_clock_minute_and_second(self) -> None:
        now = datetime(2026, 5, 20, 14, 33, 42, tzinfo=timezone.utc)
        p = build_probe(now)
        assert p.minute == 33
        assert p.second == 42

    def test_default_prefix(self) -> None:
        p = build_probe(datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc))
        assert p.prefix == b"\x00\x00"


class TestDeriveXorKey:
    """D75 XOR-key derivation, fully RE'd from TH-D75_V103_e.exe f.cs.

    Formula: key = ((-(minute + second)) ^ sum(derivation_string)) & 0xFF,
    with a 0x75 fallback when the result is 0. The D75 derivation string
    is "TH-D75  " (sum 0xB9); D74's is "TH-D74  " (sum 0xB8).
    """

    def test_sum_of_d75_derivation_is_0xb9(self) -> None:
        # The magic constant is not arbitrary — it is the byte sum of
        # the model-name string "TH-D75  " (f.cs case 8).
        assert sum(b"TH-D75  ") & 0xFF == 0xB9

    def test_known_formula(self) -> None:
        # minute=0, second=0 → b3 = (-(0)) & 0xFF = 0; key = 0 ^ 0xB9 = 0xB9
        p = Probe(prefix=b"\x00\x00", minute=0, second=0)
        assert derive_xor_key(p) == 0xB9

    def test_nonzero_timestamp(self) -> None:
        # minute=10, second=5 → sum=15; b3 = (-15) & 0xFF = 0xF1
        # key = 0xF1 ^ 0xB9 = 0x48
        p = Probe(prefix=b"\x00\x00", minute=10, second=5)
        assert derive_xor_key(p) == (((-15) & 0xFF) ^ 0xB9)

    def test_fallback_when_derivation_is_zero(self) -> None:
        # Choose minute+second so that (-(m+s)) ^ 0xB9 == 0, i.e.
        # (-(m+s)) & 0xFF == 0xB9  →  (m+s) & 0xFF == (-0xB9) & 0xFF == 0x47.
        # minute=0x40, second=0x07 sum to 0x47.
        p = Probe(prefix=b"\x00\x00", minute=0x40, second=0x07)
        assert derive_xor_key(p) == 0x75  # fallback, not 0

    def test_derivation_string_is_not_on_wire(self) -> None:
        # The string "TH-D75  " is a derivation constant only; the
        # loader never sends it back. Verify the XOR result does NOT
        # depend on the on-wire UNLOCK_REPLY bytes — those are
        # totally separate.
        p = Probe(prefix=b"\x00\x00", minute=3, second=4)
        from_default = derive_xor_key(p)
        from_unlock_bytes = (
            (-(p.minute + p.second)) ^ (sum(UNLOCK_REPLY) & 0xFF)
        ) & 0xFF
        # These would only be equal by coincidence; for m=3,s=4 they differ.
        assert from_default != from_unlock_bytes
        # The default is what derive_xor_key actually computes.
        assert from_default == (((-(p.minute + p.second)) & 0xFF) ^ 0xB9)

    def test_derivation_string_is_the_only_per_model_variable(self) -> None:
        # The formula is ``((-(m+s)) ^ sum(derivation_string)) & 0xFF``
        # with a model-specific fallback when the result is zero. The
        # `derivation` parameter to ``derive_xor_key`` exists so the
        # same code can be re-targeted to a future radio model by
        # swapping only the model-name string (everything else in the
        # formula is fixed). This test demonstrates the parameter
        # actually changes the output as intended — substituting a
        # different model-name string gives a different XOR key for
        # the same probe timestamp.
        p = Probe(prefix=b"\x00\x00", minute=21, second=37)
        alt = b"TH-XXXX "
        expected_alt = ((-(p.minute + p.second)) ^ (sum(alt) & 0xFF)) & 0xFF
        assert derive_xor_key(p, alt) == expected_alt
        # Different derivation string → different key, same probe.
        assert derive_xor_key(p, alt) != derive_xor_key(p)


class TestHandshakeResult:
    def test_construction(self) -> None:
        p = Probe(prefix=b"\x00\x00", minute=42, second=15)
        result = HandshakeResult(baud=38400, probe=p, reply=UNLOCK_REPLY, xor_key=0x4A)
        assert result.baud == 38400
        assert result.xor_key == 0x4A

    def test_frozen(self) -> None:
        p = Probe(prefix=b"\x00\x00", minute=0, second=0)
        result = HandshakeResult(baud=9600, probe=p, reply=UNLOCK_REPLY, xor_key=0)
        field_name = "baud"
        with pytest.raises(AttributeError):
            setattr(result, field_name, 38400)


class TestHandshakeError:
    def test_is_runtime_error(self) -> None:
        assert issubclass(HandshakeError, RuntimeError)

    def test_ambiguous_unlock_is_a_handshake_error(self) -> None:
        assert issubclass(AmbiguousUnlockError, HandshakeError)


class TestPerformHandshake:
    def test_walks_baud_ladder_until_match(self) -> None:
        radio = MockRadio(responsive_at_bauds=(38400,))
        result = perform_handshake(
            radio,
            baud_ladder=(9600, 19200, 38400),
            per_baud_timeout=0.05,
        )
        assert result.baud == 38400
        # The key is derived from the probe perform_handshake built;
        # re-derive against that same probe to confirm. derive_xor_key
        # no longer takes the reply bytes (they were never the basis
        # of the derivation; it's a model-name constant).
        assert result.xor_key == derive_xor_key(result.probe)
        # The on-wire reply is the two-byte UNLOCK_REPLY, not a string.
        assert result.reply == UNLOCK_REPLY

    def test_raises_when_no_baud_responds(self) -> None:
        radio = MockRadio(responsive_at_bauds=(115200,))
        with pytest.raises(HandshakeError, match="no reply"):
            _ = perform_handshake(
                radio,
                baud_ladder=(9600, 19200, 38400),
                per_baud_timeout=0.05,
            )

    @pytest.mark.parametrize(
        ("write_result", "write_error"),
        [
            (10, None),
            (None, OSError("simulated write failure")),
        ],
    )
    def test_keyed_ambiguous_write_aborts_without_any_followup_io(
        self,
        write_result: int | None,
        write_error: BaseException | None,
    ) -> None:
        transport = _RecordingTransport(
            write_result=write_result,
            write_error=write_error,
        )

        with pytest.raises(AmbiguousUnlockError, match="MANDATORY"):
            _ = perform_handshake(
                transport,
                baud_ladder=(9600, 19200),
                per_baud_timeout=0.001,
            )

        assert [name for name, _ in transport.calls] == [
            "set_baud",
            "discard_input",
            "write",
        ]

    def test_keyed_post_write_read_failure_aborts_before_next_baud(self) -> None:
        transport = _RecordingTransport(read_error=OSError("simulated read failure"))

        with pytest.raises(
            AmbiguousUnlockError,
            match=r"keyed unlock reply read.*state is ambiguous",
        ):
            _ = perform_handshake(
                transport,
                baud_ladder=(9600, 19200),
                per_baud_timeout=0.01,
            )

        assert [name for name, _ in transport.calls] == [
            "set_baud",
            "discard_input",
            "write",
            "read",
        ]

    @pytest.mark.parametrize(
        ("fail_set_call", "fail_discard_call", "expected_tail"),
        [
            (2, None, ["set_baud"]),
            (None, 2, ["set_baud", "discard_input"]),
        ],
    )
    def test_keyed_next_attempt_transport_failure_retains_post_write_state(
        self,
        fail_set_call: int | None,
        fail_discard_call: int | None,
        expected_tail: list[str],
    ) -> None:
        transport = _RecordingTransport(
            fail_set_call=fail_set_call,
            fail_discard_call=fail_discard_call,
        )

        with pytest.raises(AmbiguousUnlockError, match="earlier complete unlock"):
            _ = perform_handshake(
                transport,
                baud_ladder=(9600, 19200),
                per_baud_timeout=0.001,
            )

        call_names = [name for name, _ in transport.calls]
        first_write = call_names.index("write")
        assert call_names[first_write + 1 :][-len(expected_tail) :] == expected_tail
        assert call_names.count("write") == 1


class TestPerformCleartextUnlock:
    @pytest.mark.parametrize(
        ("write_result", "write_error"),
        [
            (len(CLEARTEXT_MAGIC) - 1, None),
            (None, OSError("simulated write failure")),
        ],
    )
    def test_ambiguous_write_aborts_without_read_or_other_followup(
        self,
        write_result: int | None,
        write_error: BaseException | None,
    ) -> None:
        transport = _RecordingTransport(
            write_result=write_result,
            write_error=write_error,
        )

        with pytest.raises(AmbiguousUnlockError, match="MANDATORY"):
            _ = perform_cleartext_unlock(transport, baud=576_000, timeout=0.01)

        assert [name for name, _ in transport.calls] == [
            "discard_input",
            "write",
        ]

    def test_post_write_read_failure_is_ambiguous(self) -> None:
        transport = _RecordingTransport(read_error=OSError("simulated read failure"))

        with pytest.raises(
            AmbiguousUnlockError,
            match=r"cleartext unlock reply read.*state is ambiguous",
        ):
            _ = perform_cleartext_unlock(transport, baud=576_000, timeout=0.01)

        assert [name for name, _ in transport.calls] == [
            "discard_input",
            "write",
            "read",
        ]
