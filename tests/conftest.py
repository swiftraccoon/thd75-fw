"""Shared pytest fixtures for the thd75-fw test suite.

This module is auto-discovered by pytest. Tests can request any
fixture defined here by adding it as a parameter — no explicit import
needed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from thd75_fw.file_cipher import RollingKeyState

if TYPE_CHECKING:
    from collections.abc import Callable

# ── Cipher encoder helpers ──────────────────────────────────────────
#
# These are inverses of file_cipher.decrypt_line / decrypt_resource,
# used to construct test inputs that exercise the full
# cipher → parser pipeline without needing a real firmware blob.


@pytest.fixture
def encrypt_line() -> Callable[[bytes, str, RollingKeyState], str]:
    """Provide a function that encrypts one line of plaintext bytes.

    The returned function is the inverse of ``file_cipher.decrypt_line``.
    Mutates the ``state`` argument exactly as the decrypt direction does,
    so callers can chain encrypt-then-decrypt and recover the original.

    Algorithm (inverse of the documented decrypt loop)::

        xored = (plaintext_byte + rolling_key) & 0xFF
        raw_byte = xored ^ ((1-based-index & 1) * 0xFF)
        emit = f"{raw_byte:02X}"
        rolling_key = (rolling_key + step) & 0xFF
    """

    def _encrypt_line(
        plaintext: bytes, prefix: str, state: RollingKeyState,
    ) -> str:
        pieces: list[str] = [prefix]
        for one_based_index, plaintext_byte in enumerate(plaintext, start=1):
            xored = (plaintext_byte + state.key) & 0xFF
            raw_byte = xored ^ ((one_based_index & 1) * 0xFF)
            pieces.append(f"{raw_byte:02X}")
            state.advance()
        return "".join(pieces)

    return _encrypt_line


@pytest.fixture
def encrypt_resource(
    encrypt_line: Callable[[bytes, str, RollingKeyState], str],
) -> Callable[[list[tuple[bytes, list[bytes]]]], str]:
    """Provide a function that builds a complete encrypted resource string.

    Each input block is ``(metadata_bytes, [data_record_bytes_per_line, ...])``.
    The metadata line gets a ``$`` prefix; each data line gets ``D``.
    Lines are joined with ``\\n`` (matching what the real updater
    emits in its embedded resource).
    """

    def _encrypt_resource(
        blocks: list[tuple[bytes, list[bytes]]],
    ) -> str:
        state = RollingKeyState()
        lines: list[str] = []
        for metadata_bytes, data_records in blocks:
            lines.append(encrypt_line(metadata_bytes, "$", state))
            for record in data_records:
                lines.append(encrypt_line(record, "D", state))
        return "\n".join(lines) + "\n"

    return _encrypt_resource


@pytest.fixture
def intel_hex_record() -> Callable[..., bytes]:
    """Provide a function that builds a single packed Intel HEX record.

    The TH-D75 firmware's records are this packed binary form, not the
    standard ``:LLAAAATT...`` ASCII representation.
    """

    def _intel_hex_record(
        byte_count: int,
        addr: int,
        rec_type: int,
        data: bytes = b"",
        checksum: int = 0,
    ) -> bytes:
        return bytes(
            [byte_count, (addr >> 8) & 0xFF, addr & 0xFF, rec_type, *data, checksum]
        )

    return _intel_hex_record
