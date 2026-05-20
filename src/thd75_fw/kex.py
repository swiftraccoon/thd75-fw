"""Patching of TH-D75 ``.KEX`` firmware files.

The TH-D75 updater flashes either its embedded (encrypted) firmware
resource or an external plaintext ``.KEX`` file opened from disk. A
``.KEX`` file is the decrypted resource rendered as text: ``#``/``$``/
``;`` metadata lines and ``:``-prefixed Intel HEX data records,
grouped into one block per firmware section. The updater applies its
file-storage cipher (rolling-key XOR + alternating inversion) only to
the embedded resource — an external file is read verbatim, so a
plaintext ``.KEX`` needs no encryption.

This module turns the encrypted updater resource into a plaintext
``.KEX`` file with a small, targeted firmware patch applied. Every
untouched byte stays identical to the official image; the affected
Intel HEX record checksums and the block ``$CA`` checksum are
recomputed so the updater and radio accept the result.

Reverse-engineered from class ``j`` in THD75_Updater_E v1.03.000.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import file_cipher, intel_hex

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .patch import ByteChange

__all__: list[str] = [
    "Kex",
    "KexBlock",
    "firmware_checksum",
    "parse_resource",
    "patch_kex",
    "patch_resource",
    "render",
]


@dataclass(frozen=True, slots=True)
class KexBlock:
    """One block of a .KEX firmware file — a single flashable section.

    ``metadata`` holds the block's ``#``/``$``/``;`` lines as raw bytes.
    They are kept as bytes, not str, so a few non-ASCII comment bytes in
    the real firmware survive a decrypt-and-re-emit round trip intact.
    ``records`` is the block's packed Intel HEX data — hand it to the
    ``intel_hex`` module to parse, patch, or re-emit.
    """

    metadata: tuple[bytes, ...]
    records: bytes


@dataclass(frozen=True, slots=True)
class Kex:
    """A TH-D75 ``.KEX`` firmware file: an ordered list of blocks."""

    blocks: tuple[KexBlock, ...]


def firmware_checksum(image: bytes) -> int:
    """Compute a firmware region's 16-bit checksum (the .KEX ``$CA``).

    The updater verifies each flashed section against the ``$CA`` value
    in its block metadata. The algorithm is a sum of the region's
    16-bit little-endian words, taken modulo 0x10000. An odd trailing
    byte is treated as the low byte of a final word (high byte zero) —
    real firmware regions are even-length, so this is only a
    well-definedness guarantee.

    Args:
        image: The firmware region bytes — for the FIRMWARE block, the
            flat image reconstructed by ``intel_hex.parse``.

    Returns:
        The 16-bit checksum, 0x0000-0xFFFF.
    """
    total: int = 0
    for i in range(0, len(image) - 1, 2):
        total += image[i] | (image[i + 1] << 8)
    if len(image) % 2:
        total += image[-1]
    return total & 0xFFFF


def parse_resource(resource_text: str) -> Kex:
    """Decrypt an encrypted updater resource into a ``Kex`` model.

    The resource is the ciphered text embedded in the updater
    executable. Each block is a run of metadata lines followed by a run
    of Intel HEX data lines; the file header travels with the first
    block. Every line is kept as raw bytes so non-ASCII content
    round-trips intact.

    Args:
        resource_text: The full encrypted resource text.

    Returns:
        A ``Kex`` with one ``KexBlock`` per section, in resource order.
    """
    state = file_cipher.RollingKeyState()
    blocks: list[KexBlock] = []
    metadata: list[bytes] = []
    records = bytearray()

    for raw_line in resource_text.split("\n"):
        stripped = raw_line.strip("\r").strip()
        if not stripped:
            continue
        line_type, line_bytes = file_cipher.decrypt_line(stripped, state)
        if line_type == "$":
            # A metadata line after data closes the previous block.
            if records:
                blocks.append(
                    KexBlock(metadata=tuple(metadata), records=bytes(records))
                )
                metadata = []
                records = bytearray()
            metadata.append(line_bytes)
        elif line_type == "D":
            records.extend(line_bytes)

    if metadata or records:
        blocks.append(KexBlock(metadata=tuple(metadata), records=bytes(records)))

    return Kex(blocks=tuple(blocks))


def render(kex: Kex) -> bytes:
    """Render a ``Kex`` model as a plaintext ``.KEX`` file.

    Metadata lines are emitted verbatim; each packed Intel HEX record
    becomes one textual ``:``-prefixed line. Lines are CRLF-terminated,
    matching the updater's resource. The updater reads an external
    ``.KEX`` file without deciphering it, so this plaintext is ready to
    flash as-is.

    Args:
        kex: The firmware model to render.

    Returns:
        The complete ``.KEX`` file content as bytes.
    """
    lines: list[bytes] = []
    for block in kex.blocks:
        lines.extend(block.metadata)
        lines.extend(
            line.encode("ascii") for line in intel_hex.to_text_lines(block.records)
        )
    return b"\r\n".join(lines) + b"\r\n"


# $SA (physical start address) of the FIRMWARE block — the section that
# holds executable code, and the only block patch_kex targets. It is the
# OMAP-L138 NOR flash base (0x6000_0000) plus the FIRMWARE section's flash
# offset (0x0020_0000).
_FIRMWARE_START_ADDRESS: int = 0x6020_0000


def patch_kex(resource_text: str, changes: Iterable[ByteChange]) -> bytes:
    """Decrypt an updater resource and emit a patched plaintext .KEX.

    Applies firmware byte changes to the FIRMWARE block, fixes the
    Intel HEX record checksums of the records that changed, recomputes
    that block's ``$CA`` checksum over its ``$CS``/``$CL`` region, and
    renders the result. Every other byte of every block stays identical
    to the official image.

    Args:
        resource_text: The encrypted updater resource text.
        changes: The byte changes to apply to the FIRMWARE block. Each
            declares its expected current byte; the engine verifies and
            raises ``PatchVerificationError`` on mismatch before writing.

    Returns:
        The patched ``.KEX`` file as bytes.

    Raises:
        ValueError: if the resource has no FIRMWARE block, that block
            lacks ``$CS=``/``$CL=``/``$CA=`` metadata, or a change's
            offset is invalid (see ``intel_hex.patch_image``).
        PatchVerificationError: if any change's ``expect`` does not
            match the current firmware byte.
    """
    kex = parse_resource(resource_text)
    firmware_index = _firmware_block_index(kex)
    firmware = kex.blocks[firmware_index]

    patched_records = intel_hex.patch_image(firmware.records, changes)

    region_start = _metadata_value(firmware.metadata, b"$CS=")
    region_length = _metadata_value(firmware.metadata, b"$CL=")
    if region_start is None or region_length is None:
        msg = "FIRMWARE block is missing $CS= / $CL= checksum metadata"
        raise ValueError(msg)
    # Surface any Intel HEX parse errors rather than computing $CA over
    # a silently-truncated image (which would emit a "valid-looking" .KEX
    # whose $CA fails at flash time). Matches the v0.1.0 _run_extract
    # contract that introduced ParseResult.errors.
    parsed = intel_hex.parse(patched_records)
    if parsed.errors:
        msg = (
            "FIRMWARE block has Intel HEX parse errors: "
            + "; ".join(parsed.errors)
        )
        raise ValueError(msg)
    image = parsed.data
    if region_start + region_length > len(image):
        # $CS/$CL declare a region larger than the actual image — Python
        # slicing would silently truncate to len(image), producing a $CA
        # computed over fewer bytes than the radio's flash-time verifier
        # will sum. Brick risk; refuse loudly.
        msg = (
            f"$CS=0x{region_start:X}+$CL=0x{region_length:X} exceeds firmware "
            f"image length 0x{len(image):X}; metadata may be corrupt"
        )
        raise ValueError(msg)
    new_ca = firmware_checksum(image[region_start : region_start + region_length])

    patched_block = KexBlock(
        metadata=_rewrite_ca(firmware.metadata, new_ca),
        records=patched_records,
    )
    blocks = list(kex.blocks)
    blocks[firmware_index] = patched_block
    return render(Kex(blocks=tuple(blocks)))


def _firmware_block_index(kex: Kex) -> int:
    """Return the index of the FIRMWARE block in ``kex``.

    Raises:
        ValueError: if no block carries the FIRMWARE ``$SA=`` address.
    """
    for index, block in enumerate(kex.blocks):
        if _metadata_value(block.metadata, b"$SA=") == _FIRMWARE_START_ADDRESS:
            return index
    msg = f"resource has no FIRMWARE block ($SA=0x{_FIRMWARE_START_ADDRESS:08X})"
    raise ValueError(msg)


def _metadata_value(metadata: tuple[bytes, ...], tag: bytes) -> int | None:
    """Return the integer value of the first ``tag`` metadata line.

    ``tag`` includes the trailing ``=`` (for example ``b"$CA="``). The
    value is hexadecimal, optionally ``0x``-prefixed. Returns ``None`` if
    no metadata line starts with ``tag``.

    Raises:
        ValueError: if the line starts with ``tag`` but its value is
            not parseable hexadecimal. The error names ``tag`` so the
            caller can tell which metadata field is malformed.
    """
    for line in metadata:
        if line.startswith(tag):
            value_str = line[len(tag) :].decode("ascii", errors="replace").strip()
            try:
                return int(value_str, 16)
            except ValueError as exc:
                tag_name = tag.decode("ascii", errors="replace").rstrip("=")
                msg = (
                    f"metadata line for {tag_name} has unparseable value "
                    f"{value_str!r}"
                )
                raise ValueError(msg) from exc
    return None


def _rewrite_ca(metadata: tuple[bytes, ...], new_ca: int) -> tuple[bytes, ...]:
    """Return ``metadata`` with the ``$CA=`` line set to ``new_ca``.

    The rewritten line preserves the hex-digit width of the original
    value (e.g. ``$CA=0x3313`` stays 4 digits; ``$CA=0x00003313`` would
    stay 8). The whole point of ``patch_resource`` is a same-length
    splice — drifting the ``$CA=`` line's width would desync the cipher
    for every subsequent line.

    Raises:
        ValueError: if there is no ``$CA=`` line to rewrite.
    """
    rewritten: list[bytes] = []
    replaced = False
    for line in metadata:
        if line.startswith(b"$CA="):
            # Preserve the original value's hex digit width.
            original_value = line[len(b"$CA=") :].decode("ascii", errors="replace")
            digits = len(original_value.removeprefix("0x"))
            # Default to 4 digits (the V1.03 width) if the original is
            # blank or malformed — keeps the cipher length invariant in
            # the common case.
            width = digits if digits > 0 else 4
            rewritten.append(b"$CA=0x%0*X" % (width, new_ca))
            replaced = True
        else:
            rewritten.append(line)
    if not replaced:
        msg = "FIRMWARE block has no $CA= metadata line"
        raise ValueError(msg)
    return tuple(rewritten)


def patch_resource(resource_text: str, changes: Iterable[ByteChange]) -> str:
    """Patch the FIRMWARE block of an *encrypted* updater resource in place.

    Decrypts the resource line by line — preserving every line, its exact
    marker character, blank lines, and CRLF endings — applies the firmware
    byte patches, recomputes the affected record checksums and the block
    ``$CA``, then re-ciphers. The result is byte-length-identical to the
    input and differs only where the patch lands, so it can be spliced
    straight back into the updater ``.exe``.

    Args:
        resource_text: The encrypted updater resource text.
        changes: The byte changes to apply to the FIRMWARE block. Each
            declares its expected current byte; the engine verifies and
            raises ``PatchVerificationError`` on mismatch before writing.

    Returns:
        The re-ciphered resource text.

    Raises:
        ValueError: if the resource has no FIRMWARE block, that block
            lacks ``$CS=``/``$CL=``/``$CA=`` metadata, the patched
            Intel HEX stream has parse errors, the ``$CS``/``$CL``
            region exceeds the firmware image, or a change's offset is
            invalid (see ``intel_hex.patch_image``).
        PatchVerificationError: if any change's ``expect`` does not
            match the current firmware byte.
    """
    state = file_cipher.RollingKeyState()
    decoded: list[tuple[str | None, bytes, bool]] = []
    for segment in resource_text.split("\n"):
        has_cr = segment.endswith("\r")
        body = segment[:-1] if has_cr else segment
        if not body:
            decoded.append((None, b"", has_cr))
            continue
        _, plaintext = file_cipher.decrypt_line(body, state)
        decoded.append((body[0], plaintext, has_cr))

    firmware = _locate_firmware(decoded)

    blob = b"".join(decoded[i][1] for i in firmware.data_indices)
    patched_blob = intel_hex.patch_image(blob, changes)
    # Surface any Intel HEX parse errors rather than computing $CA over
    # a silently-truncated image. (See patch_kex for the same guard.)
    parsed = intel_hex.parse(patched_blob)
    if parsed.errors:
        msg = (
            "FIRMWARE block has Intel HEX parse errors: "
            + "; ".join(parsed.errors)
        )
        raise ValueError(msg)
    image = parsed.data
    if firmware.region_start + firmware.region_length > len(image):
        msg = (
            f"$CS=0x{firmware.region_start:X}+$CL=0x{firmware.region_length:X} "
            f"exceeds firmware image length 0x{len(image):X}; "
            f"metadata may be corrupt"
        )
        raise ValueError(msg)
    region = image[
        firmware.region_start : firmware.region_start + firmware.region_length
    ]
    new_ca = firmware_checksum(region)

    # Preserve the original $CA= line's hex-digit width so the
    # re-encrypted line is the same byte length as the line it replaces
    # — the splice-back-into-.exe step is a same-length operation.
    original_ca_line = decoded[firmware.ca_index][1]
    ca_value = original_ca_line[len(b"$CA=") :].decode("ascii", errors="replace")
    ca_digits = len(ca_value.removeprefix("0x"))
    ca_width = ca_digits if ca_digits > 0 else 4
    replacements: dict[int, bytes] = {
        firmware.ca_index: b"$CA=0x%0*X" % (ca_width, new_ca),
    }
    cursor = 0
    for i in firmware.data_indices:
        length = len(decoded[i][1])
        replacements[i] = patched_blob[cursor : cursor + length]
        cursor += length

    out_state = file_cipher.RollingKeyState()
    out: list[str] = []
    for index, (marker, plaintext, has_cr) in enumerate(decoded):
        if marker is None:
            out.append("\r" if has_cr else "")
            continue
        encoded = file_cipher.encrypt_line(
            replacements.get(index, plaintext), marker, out_state
        )
        out.append(encoded + "\r" if has_cr else encoded)
    return "\n".join(out)


@dataclass(frozen=True, slots=True)
class _FirmwareLocation:
    """Where the FIRMWARE block sits within a decoded resource line list."""

    data_indices: tuple[int, ...]
    ca_index: int
    region_start: int
    region_length: int


def _locate_firmware(
    decoded: list[tuple[str | None, bytes, bool]],
) -> _FirmwareLocation:
    """Segment a decoded resource into blocks and locate the FIRMWARE one.

    A block is a run of ``$`` metadata lines followed by a run of data
    lines; blank lines are ignored for this segmentation.

    Raises:
        ValueError: if there is no FIRMWARE block, or it lacks the
            ``$CA=``/``$CS=``/``$CL=`` metadata.
    """
    blocks: list[tuple[list[int], list[int]]] = []
    meta: list[int] = []
    data: list[int] = []
    for index, (marker, _, _) in enumerate(decoded):
        if marker is None:
            continue
        if marker == "$":
            if data:
                blocks.append((meta, data))
                meta, data = [], []
            meta.append(index)
        else:
            data.append(index)
    if meta or data:
        blocks.append((meta, data))

    for meta_indices, data_indices in blocks:
        metadata = tuple(decoded[i][1] for i in meta_indices)
        if _metadata_value(metadata, b"$SA=") != _FIRMWARE_START_ADDRESS:
            continue
        region_start = _metadata_value(metadata, b"$CS=")
        region_length = _metadata_value(metadata, b"$CL=")
        if region_start is None or region_length is None:
            msg = "FIRMWARE block is missing $CS= / $CL= checksum metadata"
            raise ValueError(msg)
        ca_index = next(
            (i for i in meta_indices if decoded[i][1].startswith(b"$CA=")),
            None,
        )
        if ca_index is None:
            msg = "FIRMWARE block has no $CA= metadata line"
            raise ValueError(msg)
        return _FirmwareLocation(
            data_indices=tuple(data_indices),
            ca_index=ca_index,
            region_start=region_start,
            region_length=region_length,
        )
    msg = f"resource has no FIRMWARE block ($SA=0x{_FIRMWARE_START_ADDRESS:08X})"
    raise ValueError(msg)
