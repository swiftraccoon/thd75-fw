"""Tests for the file-storage cipher."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from thd75_fw.file_cipher import (
    DecryptedResource,
    RollingKeyState,
    decrypt_line,
    decrypt_resource,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    # Type alias for the encrypt_resource fixture's signature.
    EncryptResource = Callable[[list[tuple[bytes, list[bytes]]]], str]


class TestRollingKeyState:
    """The rolling-key state's invariants: key in 0..255, advance wraps,
    construction validates inputs."""

    def test_initial_value(self) -> None:
        state = RollingKeyState()
        assert state.key == 39

    def test_advance(self) -> None:
        state = RollingKeyState(key=39, step=39)
        state.advance()
        assert state.key == 78
        state.advance()
        assert state.key == 117

    def test_wraps_at_256(self) -> None:
        state = RollingKeyState(key=250, step=39)
        state.advance()
        assert state.key == (250 + 39) & 0xFF

    def test_rejects_out_of_range_key(self) -> None:
        # Construction must reject values outside 0..255 explicitly rather
        # than silently masking with & 0xFF (which would turn key=300 into
        # key=44, a footgun for the worst possible failure mode).
        with pytest.raises(ValueError, match=r"key must be 0\.\.255"):
            RollingKeyState(key=300)
        with pytest.raises(ValueError, match=r"key must be 0\.\.255"):
            RollingKeyState(key=-1)

    def test_rejects_out_of_range_step(self) -> None:
        with pytest.raises(ValueError, match=r"step must be 0\.\.255"):
            RollingKeyState(step=256)


class TestDecryptLine:
    """Single-line decryption: type-marker dispatch, state advancement
    per pair, and strict rejection of malformed input that would otherwise
    desync the rolling key."""

    def test_empty_line(self) -> None:
        state = RollingKeyState()
        line_type, output = decrypt_line("", state)
        assert line_type == ""
        assert output == b""

    def test_marker_only_line_does_not_advance_state(self) -> None:
        state = RollingKeyState(key=39)
        line_type, output = decrypt_line("D", state)
        assert line_type == "D"
        assert output == b""
        assert state.key == 39  # No pairs processed → no advance.

    def test_metadata_prefix(self) -> None:
        state = RollingKeyState()
        line_type, _ = decrypt_line("$AABBCC", state)
        assert line_type == "$"

    def test_data_prefix(self) -> None:
        state = RollingKeyState()
        line_type, _ = decrypt_line("XAABBCCDD", state)
        assert line_type == "D"

    def test_key_advances_across_calls(self) -> None:
        state = RollingKeyState(key=0, step=1)
        decrypt_line("$AABB", state)
        key_after_first: int = state.key
        decrypt_line("XCCDD", state)
        assert state.key > key_after_first

    def test_odd_length_data_raises(self) -> None:
        # A line with odd-length hex data after the marker is malformed.
        # The old implementation silently dropped the trailing nibble,
        # which desyncs the rolling key. Now it raises.
        state = RollingKeyState()
        with pytest.raises(ValueError, match="odd-length"):
            # marker "D" + 3 chars of data "ABC" → odd
            decrypt_line("DABC", state)

    def test_non_hex_chars_raise(self) -> None:
        # Non-hex characters indicate stream corruption; raise rather
        # than silently truncating mid-line (which desyncs the key).
        state = RollingKeyState()
        with pytest.raises(ValueError, match="Non-hex"):
            decrypt_line("DAAZZ", state)


class TestDecryptResource:
    """Whole-resource decryption: dataclass shape, empty input handling,
    and corruption propagation."""

    def test_returns_dataclass(self) -> None:
        # Both lines are well-formed: $AABB (metadata, 2 pairs) and
        # DCCDDEEFF (data marker D, 4 pairs).
        result: DecryptedResource = decrypt_resource("$AABB\nDCCDDEEFF\n")
        assert isinstance(result, DecryptedResource)
        assert isinstance(result.metadata, tuple)

    def test_empty_input(self) -> None:
        result = decrypt_resource("")
        assert result.data == b""
        assert result.metadata == ()

    def test_corrupt_line_propagates(self) -> None:
        # Cipher stream corruption inside decrypt_resource must not
        # be silently swallowed — fail loud or risk silent corruption
        # of every subsequent line via a desynced rolling key.
        with pytest.raises(ValueError):
            decrypt_resource("$AABB\nDABZZ\n")


class TestMultiBlockContinuity:
    """Pin the multi-block boundary in ``decrypt_resource`` and the
    rolling key's continuity across blocks. The previous test suite
    only exercised single-block resources, so a regression that
    duplicated/dropped blocks at the boundary or reset the key on a
    new ``$`` line would have passed unnoticed."""

    def test_two_blocks_round_trip(
        self, encrypt_resource: EncryptResource,
    ) -> None:
        # Encrypt two distinct blocks with the canonical encoder,
        # then decrypt and check both blocks come back intact AND in order.
        meta_a = b"$SA=0x60200000"
        data_a = b"\x11\x22\x33\x44"
        meta_b = b"$SA=0x60E00000"
        data_b = b"\xAA\xBB\xCC\xDD\xEE\xFF"

        encrypted = encrypt_resource([
            (meta_a, [data_a]),
            (meta_b, [data_b]),
        ])
        result = decrypt_resource(encrypted)

        assert len(result.blocks) == 2
        assert result.blocks[0].data == data_a
        assert result.blocks[1].data == data_b
        # Metadata is decoded as ASCII
        assert result.blocks[0].metadata == ("$SA=0x60200000",)
        assert result.blocks[1].metadata == ("$SA=0x60E00000",)

    def test_rolling_key_continuous_across_blocks(
        self, encrypt_resource: EncryptResource,
    ) -> None:
        # The cipher's documented invariant: the rolling key is
        # continuous across all lines, including the $-prefixed boundary
        # between blocks. If decrypt_resource accidentally reset the key
        # on a new $ line, block B would decrypt to garbage.
        # Same plaintext in both blocks — but the encryption is
        # different bytes because the rolling key has advanced.
        # Decryption must produce identical plaintext for both.
        plaintext = b"REPEATME"
        encrypted = encrypt_resource([
            (b"$M1", [plaintext]),
            (b"$M2", [plaintext]),
        ])
        result = decrypt_resource(encrypted)
        assert result.blocks[0].data == plaintext
        assert result.blocks[1].data == plaintext

    def test_concatenated_data_property(
        self, encrypt_resource: EncryptResource,
    ) -> None:
        # DecryptedResource.data should concat all blocks' data in order.
        encrypted = encrypt_resource([
            (b"$A", [b"\x01\x02"]),
            (b"$B", [b"\x03\x04"]),
            (b"$C", [b"\x05\x06"]),
        ])
        result = decrypt_resource(encrypted)
        assert result.data == b"\x01\x02\x03\x04\x05\x06"
