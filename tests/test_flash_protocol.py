"""Tests for thd75_fw.flash.protocol."""

from __future__ import annotations

import pytest

from tests.fixtures.synthetic_kex import SeededByteStream
from thd75_fw.flash.commands import AckCode, NakSubcode, UnframedResponse
from thd75_fw.flash.protocol import (
    SYNC,
    Frame,
    FrameError,
    ResponseReader,
    build_frame,
    descramble,
    parse_frame,
    scramble,
    sum8,
    xor_with_key,
)


class TestSum8:
    """8-bit unsigned sum of every byte."""

    def test_empty(self) -> None:
        assert sum8(b"") == 0

    def test_single(self) -> None:
        assert sum8(b"\x42") == 0x42

    def test_wraps_at_256(self) -> None:
        # 0xFF + 0xFF = 0x1FE; & 0xFF = 0xFE
        assert sum8(b"\xff\xff") == 0xFE

    def test_known_reference_frame_example(self) -> None:
        # Reference frame for verb 0x31 (QUERY_TARGET) with empty
        # payload — the wire bytes the D75 host transmits in
        # cleartext mode are:
        #   ab ab 00 01 00 00 00 31 32
        # checksum input = HH + LL..LL + VV = 00 01 00 00 00 31 = 0x32
        assert sum8(b"\x00\x01\x00\x00\x00\x31") == 0x32

    def test_matches_the_plain_byte_sum_over_many_payloads(self) -> None:
        """Pin ``sum8`` to the plain byte-sum definition across block boundaries.

        ``sum8`` reads block sums out of Adler-32 instead of adding one
        byte at a time in Python. That is only valid while a block cannot
        reach Adler-32's 65521 modulus, and while splitting a long buffer
        into blocks cannot lose a carry. Both are pinned here against the
        plain definition: every length around the 256-byte block boundary,
        the saturating all-0xFF pattern, and randomized payloads out to
        data-unit scale.
        """
        rng = SeededByteStream(0xD75)
        sizes = [
            *range(10),
            *range(250, 264),
            511,
            512,
            513,
            767,
            768,
            769,
            1024,
            1032,
            1038,
            2048,
            2056,
        ]
        for size in sizes:
            for payload in (
                b"\xff" * size,
                b"\x00" * size,
                bytes(i & 0xFF for i in range(size)),
                rng.take(size),
            ):
                assert sum8(payload) == sum(payload) & 0xFF, (
                    f"sum8 diverged from the byte sum at {size} bytes"
                )
        for _ in range(2000):
            payload = rng.take(rng.below(2100))
            assert sum8(payload) == sum(payload) & 0xFF, (
                f"sum8 diverged from the byte sum at {len(payload)} bytes"
            )

    def test_saturated_blocks_stay_exact(self) -> None:
        """Keep a saturated all-0xFF block exact.

        256 bytes of 0xFF is the worst case one block has to survive:
        its sum is 65280, one short of the modulus that would reduce it.
        """
        assert sum8(b"\xff" * 256) == 0  # 65280 & 0xFF
        assert sum8(b"\xff" * 257) == 0xFF  # first multi-block length
        assert sum8(b"\xff" * 512) == 0


class TestCipher:
    """D75 4-step cipher, and its identity when key == 0.

    Add-key → S-box → XOR-key → rotate-left-3 on TX; the exact inverse on RX.
    """

    def test_zero_key_is_identity(self) -> None:
        data = b"\x01\x02\x03"
        # key == 0 must return the SAME object, not just equal bytes,
        # so the optimization is observable in tests.
        assert scramble(data, 0) is data
        assert descramble(data, 0) is data

    def test_nonzero_key_is_not_just_xor(self) -> None:
        # Critical: the cipher is more than XOR. With key 0xFF, plain
        # XOR would give b"\xFE\xFD\xFC". The S-box step makes it
        # something completely different. This test exists to catch
        # any future regression that re-introduces pure XOR.
        out = scramble(b"\x01\x02\x03", 0xFF)
        plain_xor = bytes(b ^ 0xFF for b in b"\x01\x02\x03")
        assert out != plain_xor, "cipher must not be plain XOR"
        assert len(out) == 3

    def test_round_trip(self) -> None:
        data = bytes(range(256))
        for key in (1, 0x4A, 0xB8, 0xFF):
            assert descramble(scramble(data, key), key) == data

    def test_round_trip_all_keys(self) -> None:
        # Exhaustive verification: every (byte, key) pair round-trips.
        # Same property the .NET-updater extraction script verified.
        for key in range(256):
            for b in range(256):
                rt = descramble(scramble(bytes([b]), key), key)
                assert rt == bytes([b]), f"round-trip FAIL key=0x{key:02X} b=0x{b:02X}"

    def test_key_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"key must be 0\.\.255"):
            _ = scramble(b"", 256)
        with pytest.raises(ValueError, match=r"key must be 0\.\.255"):
            _ = descramble(b"", -1)

    def test_xor_with_key_is_backwards_compat_alias_for_scramble(self) -> None:
        # Old name preserved so external callers don't break, but it
        # invokes the full D75 cipher, not just XOR. The name is now
        # misleading but kept until all in-tree call sites migrate.
        for key in (0, 1, 0x4A, 0xFF):
            assert xor_with_key(b"\x42\x55", key) == scramble(b"\x42\x55", key)


class TestFrame:
    """Frame holds the cleartext view; validates byte ranges at construction."""

    def test_construction(self) -> None:
        f = Frame(header=0x00, verb=0x31, payload=b"")
        assert f.header == 0x00
        assert f.verb == 0x31
        assert f.payload == b""

    def test_body_length(self) -> None:
        assert Frame(0, 0x31, b"").body_length == 1
        assert Frame(0, 0x40, b"\x01\x02\x03").body_length == 4

    def test_frozen(self) -> None:
        f = Frame(0, 0, b"")
        field_name = "verb"
        with pytest.raises(AttributeError):
            setattr(f, field_name, 1)

    def test_rejects_out_of_range_header(self) -> None:
        with pytest.raises(ValueError, match=r"header must be 0\.\.255"):
            _ = Frame(header=256, verb=0, payload=b"")

    def test_rejects_out_of_range_verb(self) -> None:
        with pytest.raises(ValueError, match=r"verb must be 0\.\.255"):
            _ = Frame(header=0, verb=256, payload=b"")

    def test_rejects_oversized_payload(self) -> None:
        with pytest.raises(ValueError, match="payload too large"):
            _ = Frame(header=0, verb=0, payload=b"\x00" * (0xFFFF + 1))


class TestBuildFrame:
    def test_matches_reference_frame_example(self) -> None:
        # The D75 cleartext frame for verb 0x31 with empty payload
        # encodes exactly as: ab ab 00 01 00 00 00 31 32 — the same
        # bytes the cleartext-mode sum8 test asserts in TestSum8.
        wire = build_frame(Frame(header=0, verb=0x31, payload=b""))
        assert wire == bytes.fromhex("abab00010000003132")

    def test_cipher_encrypts_when_key_nonzero(self) -> None:
        # build_frame applies the D75 cipher (NOT plain XOR — that
        # was a D74-era assumption). Verify the encrypted bytes
        # match what scramble() would produce on the cleartext frame.
        f = Frame(0, 0x31, b"")
        plain = build_frame(f, xor_key=0)
        encrypted = build_frame(f, xor_key=0x4A)
        assert encrypted == scramble(plain, 0x4A)
        # And: encrypted is NOT the same as a plain-XOR encoding.
        assert encrypted != bytes(b ^ 0x4A for b in plain)

    def test_matches_the_concatenated_definition_over_many_frames(self) -> None:
        """Pin ``build_frame`` to literal concatenation over random frames.

        The wire buffer is filled by one join and its checksum is taken
        over the payload in place, rather than over a materialised
        ``header + length + verb + payload`` copy. Both are optimisations
        of the same definition, so pin the definition: literal
        concatenation, checksummed with a plain byte sum, for randomized
        headers, verbs and payload lengths.
        """
        rng = SeededByteStream(0x0D75_0F1A)
        for i in range(500):
            frame = Frame(
                header=rng.below(256),
                verb=rng.below(256),
                payload=rng.take(rng.below(2100)),
            )
            checked_body = (
                bytes([frame.header])
                + frame.body_length.to_bytes(4, "little")
                + bytes([frame.verb])
                + frame.payload
            )
            expected = SYNC + checked_body + bytes([sum(checked_body) & 0xFF])
            assert build_frame(frame) == expected, (
                f"cleartext frame diverged for a {len(frame.payload)}-byte payload"
            )
            # The cipher pass is per byte and slow, so exercise the keyed
            # path on a sample of short frames rather than every frame.
            if i % 50 == 0:
                short = Frame(
                    header=frame.header,
                    verb=frame.verb,
                    payload=frame.payload[:64],
                )
                key = 1 + rng.below(255)
                assert build_frame(short, xor_key=key) == scramble(
                    build_frame(short, xor_key=0),
                    key,
                )


class TestParseFrame:
    def test_round_trip_with_zero_key(self) -> None:
        f = Frame(0, 0x40, b"\x10\x20\x30")
        parsed, rest = parse_frame(build_frame(f))
        assert parsed == f
        assert rest == b""

    def test_round_trip_with_xor_key(self) -> None:
        f = Frame(0, 0x43, bytes(range(64)))
        parsed, rest = parse_frame(build_frame(f, xor_key=0x4A), xor_key=0x4A)
        assert parsed == f
        assert rest == b""

    def test_returns_trailing_bytes(self) -> None:
        f = Frame(0, 0x31, b"")
        wire = build_frame(f) + b"\x06\x06"  # frame + 2 unframed ACKs
        parsed, rest = parse_frame(wire)
        assert parsed == f
        assert rest == b"\x06\x06"

    def test_rejects_short_frame(self) -> None:
        with pytest.raises(FrameError, match="too short"):
            _ = parse_frame(b"\xab\xab")

    def test_rejects_bad_sync(self) -> None:
        with pytest.raises(FrameError, match="missing sync"):
            _ = parse_frame(b"\xff\xff\x00\x01\x00\x00\x00\x31\x32")

    def test_rejects_truncated_body(self) -> None:
        # LL says 0x100 body but only 4 payload bytes follow
        bad = b"\xab\xab\x00\x00\x01\x00\x00\x31\x01\x02\x03\x04\x99"
        with pytest.raises(FrameError, match="truncated"):
            _ = parse_frame(bad)

    def test_rejects_bad_checksum(self) -> None:
        wire = bytearray(build_frame(Frame(0, 0x31, b"")))
        wire[-1] ^= 0xFF  # corrupt cksum
        with pytest.raises(FrameError, match="checksum"):
            _ = parse_frame(bytes(wire))

    def test_rejects_zero_body_length(self) -> None:
        bad = b"\xab\xab\x00\x00\x00\x00\x00\x00\x00"
        with pytest.raises(FrameError, match="body length"):
            _ = parse_frame(bad)


class TestResponseReader:
    def test_decodes_unframed_ack_in_chunks(self) -> None:
        reader = ResponseReader()
        assert reader.feed(b"") == []
        result = reader.feed(b"\x06")
        assert result == [UnframedResponse(AckCode.ACK)]

    def test_decodes_unframed_nak_with_subcode(self) -> None:
        reader = ResponseReader()
        assert reader.feed(b"\x15") == []  # waits for subcode
        result = reader.feed(b"\x01")
        assert result == [
            UnframedResponse(AckCode.NAK, NakSubcode.UNSUPPORTED_COMMAND),
        ]

    def test_decodes_frame_split_across_feeds(self) -> None:
        reader = ResponseReader(xor_key=0x4A)
        wire = build_frame(Frame(0, 0x32, b"\x01\x02\x03"), xor_key=0x4A)
        assert reader.feed(wire[:5]) == []
        result = reader.feed(wire[5:])
        assert len(result) == 1
        assert result[0] == Frame(0, 0x32, b"\x01\x02\x03")

    def test_decodes_mixed_unframed_and_framed(self) -> None:
        # Post-unlock, EVERY byte from the radio is cipher-encoded
        # (including unframed ACK/BUSY/NAK markers). Build the test
        # stream the way a real radio would — each cleartext piece
        # passed through scramble() with the active key.
        reader = ResponseReader(xor_key=0x4A)
        frame_wire = build_frame(Frame(0, 0x32, b""), xor_key=0x4A)
        ack_wire = scramble(b"\x06", 0x4A)
        busy_wire = scramble(b"\x11", 0x4A)
        nak_wire = scramble(b"\x15\x03", 0x4A)
        data = ack_wire + frame_wire + busy_wire + nak_wire
        result = reader.feed(data)
        assert result == [
            UnframedResponse(AckCode.ACK),
            Frame(0, 0x32, b""),
            UnframedResponse(AckCode.BUSY),
            UnframedResponse(AckCode.NAK, NakSubcode.DATA_WRITE_REJECTED),
        ]

    def test_has_partial(self) -> None:
        reader = ResponseReader()
        assert not reader.has_partial()
        _ = reader.feed(b"\x15")  # waits for NAK subcode
        assert reader.has_partial()

    def test_rejects_invalid_xor_key(self) -> None:
        with pytest.raises(ValueError, match=r"xor_key must be 0\.\.255"):
            _ = ResponseReader(xor_key=256)


class TestBytesNeeded:
    """The staged byte count callers size their serial reads with.

    ``pyserial``'s ``read(n)`` returns early only when *n* bytes have arrived,
    so an over-estimate here costs a whole port timeout per reply and an
    accidental under-estimate costs an extra low-level read. The deliberate
    OpenWood boundaries are pinned because each read re-applies the custom
    macOS baud ioctl.
    """

    def test_empty_reader_needs_one_classifying_byte(self) -> None:
        assert ResponseReader().bytes_needed() == 1

    def test_drained_reader_is_back_to_needing_one_classifying_byte(self) -> None:
        reader = ResponseReader()
        assert reader.feed(b"\x06") == [UnframedResponse(AckCode.ACK)]
        assert not reader.has_partial()
        assert reader.bytes_needed() == 1

    def test_an_undrained_complete_response_needs_nothing_further(self) -> None:
        """Pins the guard that keeps a complete reply from sizing a new read.

        ``feed`` drains every complete response, so this state cannot arise
        from the public API and the buffer is seeded directly. The guard still
        earns its place: without it a buffered one-byte ACK falls through to
        the framed-reply branch and asks for another sync byte that is never
        coming, which on a real port is a whole timeout.
        """
        for complete in (b"\x06", b"\x11", b"\x15\x01"):
            reader = ResponseReader()
            reader._buf.extend(complete)
            assert reader.bytes_needed() == 0

    def test_nak_awaiting_its_subcode_needs_exactly_one_more(self) -> None:
        reader = ResponseReader()
        assert reader.feed(b"\x15") == []
        assert reader.bytes_needed() == 1

    def test_frame_opener_matches_openwood_header_stages(self) -> None:
        # OpenWood scans the two sync bytes one at a time, then reads the
        # six-byte HH + LL + VV header in one call.
        wire = build_frame(Frame(0, 0x32, b"\x01\x02\x03"))
        expected = {
            1: 1,
            2: 6,
            3: 5,
            4: 4,
            5: 3,
            6: 2,
            7: 1,
        }
        for consumed, needed in expected.items():
            reader = ResponseReader()
            assert reader.feed(wire[:consumed]) == []
            assert reader.bytes_needed() == needed

    def test_readable_header_needs_the_exact_remainder(self) -> None:
        payload = bytes(range(17))  # QUERY_TARGET, the longest real reply
        wire = build_frame(Frame(0, 0x32, payload))
        for consumed in range(8, len(wire)):
            reader = ResponseReader()
            assert reader.feed(wire[:consumed]) == []
            assert reader.bytes_needed() == len(wire) - consumed

    def test_counts_are_relative_to_the_next_response_only(self) -> None:
        # A batched arrival is drained by feed(); what remains is the partial
        # tail, and the count describes that tail alone.
        reader = ResponseReader()
        wire = build_frame(Frame(0, 0x32, b"\x01"))
        assert reader.feed(b"\x06" + wire[:2]) == [UnframedResponse(AckCode.ACK)]
        assert reader.bytes_needed() == 6

    def test_reads_the_length_field_through_the_active_cipher(self) -> None:
        # The count is derived from descrambled header bytes; reading them raw
        # would size the read off ciphertext.
        payload = b"\x01\x02\x03\x04\x05"
        wire = build_frame(Frame(0, 0x32, payload), xor_key=0x4A)
        reader = ResponseReader(xor_key=0x4A)
        assert reader.feed(wire[:8]) == []
        assert reader.bytes_needed() == len(wire) - 8

    def test_framed_ack_uses_openwood_read_boundaries(self) -> None:
        wire = build_frame(Frame(0, AckCode.ACK.value, b""))
        reader = ResponseReader()
        cursor = 0
        requests: list[int] = []
        decoded: list[Frame | UnframedResponse] = []
        while not decoded:
            want = reader.bytes_needed()
            requests.append(want)
            decoded = reader.feed(wire[cursor : cursor + want])
            cursor += want

        assert decoded == [Frame(0, AckCode.ACK.value, b"")]
        assert requests == [1, 1, 6, 1]

    def test_requested_counts_reassemble_a_frame_exactly(self) -> None:
        """Driving a reader purely from its own counts consumes no extra byte.

        This is the loop ``session._read_one_response`` runs. If the count
        ever over-reports, a real port pays a timeout here; if it
        under-reports, the response never completes.
        """
        wire = build_frame(Frame(0, 0x32, bytes(range(17))), xor_key=0x4A)
        reader = ResponseReader(xor_key=0x4A)
        stream = wire + b"\xde\xad"  # trailing bytes must stay unread
        cursor = 0
        requests: list[int] = []
        decoded: list[Frame | UnframedResponse] = []
        while not decoded:
            want = reader.bytes_needed()
            assert want > 0
            requests.append(want)
            decoded = reader.feed(stream[cursor : cursor + want])
            cursor += want

        assert decoded == [Frame(0, 0x32, bytes(range(17)))]
        assert cursor == len(wire), "read past the end of the frame"
        assert requests == [1, 1, 6, len(wire) - 8]
