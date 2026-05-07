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


class RollingKeyState:
    """Mutable state for the rolling-key cipher.

    The key advances by ``step`` after every byte processed and wraps at 256.
    Both fields are kept private to enforce the single-byte invariant
    (``0 <= value < 256``); read them via the ``key`` and ``step`` properties.
    Mutate only through ``advance()``. To start a new stream, construct a
    fresh ``RollingKeyState()`` instance.
    """

    __slots__ = ("_key", "_step")

    def __init__(self, key: int = _DEFAULT_KEY, step: int = _DEFAULT_STEP) -> None:
        if not 0 <= key < 256:
            raise ValueError(f"key must be 0..255, got {key}")
        if not 0 <= step < 256:
            raise ValueError(f"step must be 0..255, got {step}")
        self._key: int = key
        self._step: int = step

    @property
    def key(self) -> int:
        """Current rolling key value (0-255)."""
        return self._key

    @property
    def step(self) -> int:
        """Step amount applied by ``advance()`` (0-255)."""
        return self._step

    def advance(self) -> None:
        """Advance the rolling key by one step."""
        self._key = (self._key + self._step) & 0xFF


def decrypt_line(line: str, state: RollingKeyState) -> tuple[str, bytes]:
    """Decrypt a single line from the firmware resource.

    Args:
        line: One line of text (stripped of trailing newline).
        state: Rolling cipher state — mutated in place.

    Returns:
        A ``(line_type, decrypted)`` tuple where ``line_type`` is
        ``"$"`` for metadata lines, ``"D"`` for data lines, or
        ``""`` for empty input. ``decrypted`` is the plaintext bytes.

    Raises:
        ValueError: If the line has odd-length data or contains
            non-hex characters. Both indicate stream corruption;
            silently skipping would desync the rolling key for all
            subsequent lines.
    """
    if not line:
        return ("", b"")

    line_type: str = "$" if line[0] == "$" else "D"
    data_chars: str = line[1:]
    if not data_chars:
        return (line_type, b"")

    if len(data_chars) % 2:
        raise ValueError(
            f"Encrypted line has odd-length data ({len(data_chars)} chars "
            f"after type marker): {line!r}"
        )

    decrypted = bytearray()
    # Iterate over consecutive 2-char hex pairs in the line's data section
    # (everything after the type marker at index 0). The 1-based pair_index
    # matches the original C# code's loop counter, used to alternate the
    # 0x00/0xFF inversion mask per pair.
    for pair_index, pair_start in enumerate(
        range(1, len(line), 2), start=1,
    ):
        hex_pair = line[pair_start : pair_start + 2]
        try:
            raw_byte: int = int(hex_pair, 16)
        except ValueError as exc:
            raise ValueError(
                f"Non-hex characters at position {pair_start} in encrypted "
                f"line: {hex_pair!r}"
            ) from exc

        xored: int = raw_byte ^ ((pair_index & 1) * 0xFF)
        plaintext_byte: int = (xored - state.key) & 0xFF
        decrypted.append(plaintext_byte)
        state.advance()

    return (line_type, bytes(decrypted))


@dataclass(frozen=True, slots=True)
class DecryptedBlock:
    """One firmware section's decrypted data and metadata."""

    data: bytes
    """Raw plaintext bytes of Intel HEX records for this section.

    Pass to ``thd75_fw.intel_hex.parse()`` to reconstruct the section's
    in-memory image from the packed records.
    """

    metadata: tuple[str, ...]
    """Decrypted metadata strings for this section.

    Includes ``$SA=`` (start address) among other fields; see
    ``cli._extract_flash_address`` for parsing.
    """


@dataclass(frozen=True, slots=True)
class DecryptedResource:
    """Result of decrypting an entire firmware resource."""

    blocks: tuple[DecryptedBlock, ...]
    """Each block corresponds to one firmware section."""

    @property
    def data(self) -> bytes:
        """Concatenated bytes from all blocks (for single-stream parsing)."""
        return b"".join(b.data for b in self.blocks)

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
    pending_metadata: list[str] = []
    pending_data = bytearray()

    for raw_line in resource_text.split("\n"):
        stripped = raw_line.strip("\r").strip()
        if not stripped:
            continue

        line_type, line_bytes = decrypt_line(stripped, state)

        if line_type == "$":
            # A new metadata line marks the boundary between blocks. If we've
            # accumulated data for the previous block, finalize it before
            # starting fresh accumulators for the new block.
            if pending_data:
                blocks.append(DecryptedBlock(
                    data=bytes(pending_data),
                    metadata=tuple(pending_metadata),
                ))
                pending_metadata = []
                pending_data = bytearray()
            pending_metadata.append(line_bytes.decode("ascii", errors="replace"))
        elif line_type == "D":
            pending_data.extend(line_bytes)

    # Finalize the last block (no trailing $ line follows it).
    if pending_data:
        blocks.append(DecryptedBlock(
            data=bytes(pending_data),
            metadata=tuple(pending_metadata),
        ))

    return DecryptedResource(blocks=tuple(blocks))
