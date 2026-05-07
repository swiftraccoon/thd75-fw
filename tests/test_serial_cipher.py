"""Tests for the serial transfer cipher."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from thd75_fw.serial_cipher import (
    _SUBST_TABLE,
    SubstitutionTable,
    decrypt,
    encrypt,
    verify_round_trip,
)


class TestRoundTrip:
    """Encrypt followed by decrypt with the same key always recovers the
    original plaintext — the cipher's defining correctness property."""

    @pytest.mark.parametrize("byte_value", range(256))
    def test_single_byte_round_trips(self, byte_value: int) -> None:
        # Parametrized so a future regression reports the exact byte that
        # broke (instead of "test_all_single_bytes failed somewhere in 0..255").
        plaintext = bytes([byte_value])
        assert decrypt(encrypt(plaintext)) == plaintext

    def test_full_range_block_round_trips(self) -> None:
        plaintext = bytes(range(256))
        assert decrypt(encrypt(plaintext)) == plaintext

    def test_verify_round_trip_does_not_raise(self) -> None:
        # verify_round_trip raises AssertionError on any failure, so a
        # successful call IS the assertion. This pins both the default
        # key (0x75) and an arbitrary other key.
        verify_round_trip()
        verify_round_trip(key=0xAB)


class TestKeyBehavior:
    """Key parameter semantics: 0 disables the cipher (passthrough),
    different keys produce different output."""

    def test_zero_key_passthrough(self) -> None:
        data = b"ABC"
        assert encrypt(data, key=0) == data
        assert decrypt(data, key=0) == data

    def test_different_keys_differ(self) -> None:
        plain = b"KENWOOD TH-D75"
        assert encrypt(plain, key=0x75) != encrypt(plain, key=0xAB)

    def test_encrypt_changes_data(self) -> None:
        plain = b"\x00" * 16
        assert encrypt(plain) != plain


class TestSubstitutionTable:
    """The 256-byte substitution table is a true permutation, validated
    at construction; from_bytes rejects non-permutations."""

    def test_is_permutation(self) -> None:
        assert sorted(_SUBST_TABLE) == list(range(256))

    def test_from_bytes_validates(self) -> None:
        table = SubstitutionTable.from_bytes(_SUBST_TABLE)
        assert len(table.forward) == 256
        assert len(table.reverse) == 256

    def test_reverse_inverts_forward(self) -> None:
        table = SubstitutionTable.from_bytes(_SUBST_TABLE)
        for i in range(256):
            assert table.reverse[table.forward[i]] == i

    def test_non_permutation_rejected(self) -> None:
        # All-zeros isn't a permutation; from_bytes must refuse it.
        with pytest.raises(ValueError, match="permutation"):
            SubstitutionTable.from_bytes(b"\x00" * 256)

    def test_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="permutation"):
            SubstitutionTable.from_bytes(b"\x00" * 255)


class TestEdgeCases:
    """Boundary inputs (empty, large, all-same-byte) the round-trip
    parametrization doesn't reach."""

    def test_empty_input(self) -> None:
        assert encrypt(b"") == b""
        assert decrypt(b"") == b""

    def test_large_block(self) -> None:
        plain = bytes(range(256)) * 16  # 4 KB
        assert decrypt(encrypt(plain)) == plain

    def test_all_same_byte(self) -> None:
        plain = b"\xAA" * 1024
        # Even with a uniform plaintext, ciphertext should not be uniform
        # (the cipher's index-driven substitution depends on the key).
        ct = encrypt(plain)
        assert ct != plain
        assert decrypt(ct) == plain


class TestRoundTripProperty:
    """Property-based test using hypothesis. Shrinks to the minimal
    failing example for any future regression."""

    @given(
        data=st.binary(min_size=0, max_size=4096),
        key=st.integers(min_value=0, max_value=255),
    )
    def test_decrypt_inverts_encrypt(self, data: bytes, key: int) -> None:
        assert decrypt(encrypt(data, key=key), key=key) == data

    # Note: there's deliberately no "encrypt always changes data"
    # property here. Substitution ciphers always have fixed points —
    # hypothesis can find e.g. encrypt(b"\x07", key=99) == b"\x07".
    # The round-trip invariant above is the meaningful one.
