"""Tests for the file-storage cipher."""

from __future__ import annotations

from thd75_fw.file_cipher import (
    DecryptedResource,
    RollingKeyState,
    decrypt_line,
    decrypt_resource,
)


class TestRollingKeyState:
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

    def test_reset(self) -> None:
        state = RollingKeyState(key=100, step=39)
        state.reset()
        assert state.key == 39


class TestDecryptLine:
    def test_empty_line(self) -> None:
        state = RollingKeyState()
        line_type, output = decrypt_line("", state)
        assert line_type == ""
        assert output == ""

    def test_short_line(self) -> None:
        state = RollingKeyState()
        line_type, _output = decrypt_line("AB", state)
        assert line_type == ""

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


class TestDecryptResource:
    def test_returns_dataclass(self) -> None:
        result: DecryptedResource = decrypt_resource("$AABB\nCCDDEEFF\n")
        assert isinstance(result, DecryptedResource)
        assert isinstance(result.metadata, tuple)

    def test_empty_input(self) -> None:
        result = decrypt_resource("")
        assert result.data_hex == ""
        assert result.metadata == ()
