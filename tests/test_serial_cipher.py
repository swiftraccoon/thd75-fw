"""Tests for the serial transfer cipher."""

from __future__ import annotations

from thd75_fw.serial_cipher import (
    _SUBST_TABLE,
    SubstitutionTable,
    decrypt,
    encrypt,
    verify_round_trip,
)


class TestRoundTrip:
    def test_all_single_bytes(self) -> None:
        for b in range(256):
            plain = bytes([b])
            assert decrypt(encrypt(plain)) == plain

    def test_full_range_block(self) -> None:
        plain = bytes(range(256))
        assert decrypt(encrypt(plain)) == plain

    def test_verify_function(self) -> None:
        verify_round_trip()
        verify_round_trip(key=0xAB)


class TestKeyBehavior:
    def test_zero_key_passthrough(self) -> None:
        data = b"\x41\x42\x43"
        assert encrypt(data, key=0) == data
        assert decrypt(data, key=0) == data

    def test_different_keys_differ(self) -> None:
        plain = b"KENWOOD TH-D75"
        assert encrypt(plain, key=0x75) != encrypt(plain, key=0xAB)

    def test_encrypt_changes_data(self) -> None:
        plain = b"\x00" * 16
        assert encrypt(plain) != plain


class TestSubstitutionTable:
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
