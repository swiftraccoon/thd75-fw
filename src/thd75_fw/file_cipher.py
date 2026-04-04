"""File-storage cipher for the TH-D75 firmware updater.

Reverse-engineered from class ``j`` in THD75_Updater_E v1.03.000
(.NET Framework 4.8, Dotfuscator-obfuscated), decompiled with ILSpy.

Algorithm (per hex pair at 1-based index ``i`` within a line)::

    raw_byte     = int(hex_pair, 16)
    xored        = raw_byte ^ ((i & 1) * 0xFF)
    plaintext    = (xored - rolling_key) & 0xFF
    rolling_key  = (rolling_key + step) & 0xFF

The rolling key is *continuous* across all lines. Every line — data and
metadata alike — advances the key. Initial values (from ``j.__init__``):
``key = 39``, ``step = 39``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__: list[str] = [
    "DecryptedBlock",
    "DecryptedResource",
    "RollingKeyState",
    "decrypt_line",
    "decrypt_resource",
]

_DEFAULT_KEY: int = 39
_DEFAULT_STEP: int = 39


@dataclass
class RollingKeyState:
    """Mutable state for the rolling-key cipher.

    The key advances by ``step`` after every byte processed.
    It wraps at 256 (single-byte arithmetic).
    """

    key: int = _DEFAULT_KEY
    step: int = _DEFAULT_STEP

    def advance(self) -> None:
        """Advance the rolling key by one step."""
        self.key = (self.key + self.step) & 0xFF

    def reset(self) -> None:
        """Reset to initial state."""
        self.key = _DEFAULT_KEY


def decrypt_line(line: str, state: RollingKeyState) -> tuple[str, str]:
    """Decrypt a single line from the firmware resource.

    Args:
        line: One line of text (stripped of trailing newline).
        state: Rolling cipher state — mutated in place.

    Returns:
        A ``(line_type, hex_output)`` tuple where ``line_type`` is
        ``"$"`` for metadata lines, ``"D"`` for data lines, or
        ``""`` for empty/invalid lines. ``hex_output`` is the
        decrypted content as an uppercase hex string.
    """
    if len(line) < 3:
        return ("", "")

    line_type: str = "$" if line[0] == "$" else "D"
    hex_parts: list[str] = []
    pair_index: int = 1  # 1-based per the original C#

    pos: int = 1  # skip the first char (type marker)
    while pos + 1 < len(line):
        try:
            raw: int = int(line[pos : pos + 2], 16)
        except ValueError:
            break

        xored: int = raw ^ ((pair_index & 1) * 0xFF)
        plain: int = (xored - state.key) & 0xFF
        hex_parts.append(f"{plain:02X}")
        state.advance()

        pos += 2
        pair_index += 1

    return (line_type, "".join(hex_parts))


@dataclass(frozen=True, slots=True)
class DecryptedBlock:
    """One firmware section's decrypted data and metadata."""

    data_hex: str
    """Hex string of Intel HEX records for this section."""

    metadata: tuple[str, ...]
    """Decrypted metadata strings for this section."""


@dataclass(frozen=True, slots=True)
class DecryptedResource:
    """Result of decrypting an entire firmware resource."""

    blocks: tuple[DecryptedBlock, ...]
    """Each block corresponds to one firmware section."""

    @property
    def data_hex(self) -> str:
        """Concatenated hex from all blocks (for single-stream parsing)."""
        return "".join(b.data_hex for b in self.blocks)

    @property
    def metadata(self) -> tuple[str, ...]:
        """All metadata from all blocks, flattened."""
        result: list[str] = []
        for b in self.blocks:
            result.extend(b.metadata)
        return tuple(result)


def decrypt_resource(resource_text: str) -> DecryptedResource:
    """Decrypt an entire firmware resource file.

    The resource contains multiple blocks, each preceded by ``$``
    metadata lines. Each block corresponds to one firmware section.

    Args:
        resource_text: Full text content of the embedded resource.

    Returns:
        A ``DecryptedResource`` with per-block data and metadata.
    """
    state = RollingKeyState()
    blocks: list[DecryptedBlock] = []
    current_meta: list[str] = []
    current_data: list[str] = []

    for line in resource_text.split("\n"):
        line = line.strip("\r").strip()
        if not line:
            continue

        line_type, hex_output = decrypt_line(line, state)

        if line_type == "$":
            # New metadata line — if we have accumulated data, finalize block
            if current_data:
                blocks.append(DecryptedBlock(
                    data_hex="".join(current_data),
                    metadata=tuple(current_meta),
                ))
                current_meta = []
                current_data = []
            try:
                meta_bytes: bytes = bytes.fromhex(hex_output)
                current_meta.append(
                    meta_bytes.decode("ascii", errors="replace")
                )
            except ValueError:
                current_meta.append(hex_output)
        elif line_type == "D":
            current_data.append(hex_output)

    # Finalize the last block
    if current_data:
        blocks.append(DecryptedBlock(
            data_hex="".join(current_data),
            metadata=tuple(current_meta),
        ))

    return DecryptedResource(blocks=tuple(blocks))
