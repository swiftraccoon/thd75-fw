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

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, TypeAlias

# Sibling modules are imported directly, never through the package root:
# ``thd75_fw/__init__.py`` imports this module, so ``from . import ...`` here
# would close an import cycle through the package.
from .file_cipher import RollingKeyState, decrypt_line, encrypt_line
from .intel_hex import RecordType, iter_records, patch_image, to_text_lines
from .intel_hex import parse as parse_intel_hex
from .patch import Patch
from .sections import FLASH_BASE, lookup_by_name

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from .patch import ByteChange

__all__: list[str] = [
    "Kex",
    "KexBlock",
    "firmware_checksum",
    "is_d75_v103_nonstandard_overlay_stream",
    "parse_encrypted_resource",
    "parse_kex_bytes",
    "parse_resource",
    "patch_kex",
    "patch_kex_stack",
    "patch_resource",
    "patch_resource_stack",
    "render",
    "section_image",
]


_UPPER_HEX_BYTES: frozenset[int] = frozenset(b"0123456789ABCDEF")
_RESOURCE_HEX_BYTES: frozenset[int] = frozenset(b"0123456789abcdefABCDEF")

_RECORD_OVERHEAD: Final[int] = 5
"""Bytes of an Intel HEX record besides its data: count, address, type, checksum."""

_QUOTED_VALUE_MIN_LENGTH: Final[int] = 2
"""Length of the shortest quoted ``$VA=`` value, ``""``: its two quote bytes."""

_DecodedLine: TypeAlias = tuple[str | None, bytes, bool]
"""One encrypted-resource line after decryption: its marker character (``None``
for a blank line), its plaintext bytes, and whether it ended in CR."""

# The official V1.03 CHECKBYTES and FINAL_ZZZ post-write blocks carry four
# nonstandard record-checksum bytes. They are not reconstruction errors: these
# are the exact decrypted embedded-resource streams, and the hardware-tested
# vendor update uses them. Admit only these complete block-index/stream pairs;
# every other textual or packed-record checksum mismatch remains fatal.
_D75_V103_NONSTANDARD_OVERLAY_STREAMS: dict[tuple[int, int], bytes] = {
    (5, 0x6020_0062): bytes.fromhex(
        "02 00 00 04 00 00 7A 02 00 00 00 B0 1D 31 00 00 00 01 FF"
    ),
    (6, 0x6020_0040): bytes.fromhex(
        "02 00 00 04 00 00 7A "
        "10 00 00 00 5A 5A 7A 6F 2E 2E 28 2D 5F 2D 20 29 20 45 58 2D A3 "
        "10 00 10 00 35 32 31 30 20 32 30 32 32 2D 30 37 2D 32 30 00 CF "
        "00 00 00 01 FF"
    ),
}
_D75_V103_NONSTANDARD_RECORDS: frozenset[bytes] = frozenset(
    bytes.fromhex(encoded)
    for encoded in (
        "02 00 00 04 00 00 7A",
        "10 00 00 00 5A 5A 7A 6F 2E 2E 28 2D 5F 2D 20 29 20 45 58 2D A3",
        "10 00 10 00 35 32 31 30 20 32 30 32 32 2D 30 37 2D 32 30 00 CF",
    )
)


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


def is_d75_v103_nonstandard_overlay_stream(
    *,
    block_index: int,
    physical_address: int | None,
    records: bytes,
) -> bool:
    """Recognize one complete stock V1.03 nonstandard overlay stream.

    The exception is intentionally keyed by block order, physical ``$SA``
    address, and every packed Intel HEX byte. It is shared by plaintext-KEX
    validation and updater extraction so neither path grows a broader
    checksum-waiver policy.
    """
    if physical_address is None:
        return False
    return (
        _D75_V103_NONSTANDARD_OVERLAY_STREAMS.get((block_index, physical_address))
        == records
    )


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


def parse_encrypted_resource(resource_text: str) -> Kex:
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
    state = RollingKeyState()
    blocks: list[KexBlock] = []
    metadata: list[bytes] = []
    records = bytearray()

    for raw_line in resource_text.split("\n"):
        stripped = raw_line.strip("\r").strip()
        if not stripped:
            continue
        line_type, line_bytes = decrypt_line(stripped, state)
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


def parse_resource(resource_text: str) -> Kex:
    """Backward-compatible name for :func:`parse_encrypted_resource`.

    This function accepts the ASCII-hex text embedded inside the updater
    executable. It does *not* accept an external plaintext ``.KEX`` file;
    callers loading one from disk must use :func:`parse_kex_bytes`.
    """
    return parse_encrypted_resource(resource_text)


def parse_kex_bytes(data: bytes) -> Kex:
    """Parse one external plaintext ``.KEX`` artifact without decoding text.

    Kenwood opens an external file with the encrypted-resource flag disabled
    (V1.03 updater ``j.cs`` constructor and its line decoder), so its Intel HEX
    records are literal ``:`` lines. Some otherwise-ignored stock comment/header
    bytes are not valid UTF-8, which makes a byte API mandatory.

    The accepted artifact is deliberately canonical and fail-closed: CRLF on
    every line including the last, opaque byte-preserved metadata, uppercase
    textual Intel HEX, one structurally valid record per data line, exactly one
    EOF per block, and no duplicate segment tags. Checksum failures are fatal
    except for the two exact official V1.03 post-write overlay streams pinned
    below. Encrypted embedded-resource text is identified and rejected rather
    than silently decrypted.

    Args:
        data: Exact external-KEX file bytes.

    Returns:
        A validated ``Kex`` model whose rendering is byte-identical to ``data``.

    Raises:
        ValueError: if the bytes are encrypted-resource text, non-canonical,
            structurally ambiguous, or contain malformed Intel HEX records.

    """
    _check_plaintext_envelope(data)

    raw_lines = data.split(b"\r\n")
    if raw_lines[-1] != b"":  # pragma: no cover - guarded by endswith
        msg = "CRLF split invariant"
        raise AssertionError(msg)

    builder = _PlaintextBlockBuilder()
    for line_number, line in enumerate(raw_lines[:-1], start=1):
        if b"\r" in line or b"\n" in line:
            msg = f"plaintext KEX has a bare or mixed line ending at line {line_number}"
            raise ValueError(msg)
        if not line:
            msg = f"plaintext KEX has an empty line at line {line_number}"
            raise ValueError(msg)
        if line.startswith(b":"):
            builder.add_record(line, line_number)
        else:
            builder.add_metadata(line, line_number)

    parsed = Kex(blocks=builder.finish())
    if render(parsed) != data:
        msg = "plaintext KEX is valid but not in canonical rendered form"
        raise ValueError(msg)
    return parsed


def _check_plaintext_envelope(data: bytes) -> None:
    """Reject input that cannot be a plaintext KEX before reading its lines.

    Raises:
        ValueError: if ``data`` is empty, is encrypted updater-resource text,
            or does not end with CRLF, checked in that order.

    """
    if not data:
        msg = "plaintext KEX is empty"
        raise ValueError(msg)
    if _looks_like_encrypted_resource(data):
        msg = (
            "input is encrypted updater-resource text, not an external "
            "plaintext KEX; decrypt and render it before flashing"
        )
        raise ValueError(msg)
    if not data.endswith(b"\r\n"):
        msg = "plaintext KEX must end with canonical CRLF"
        raise ValueError(msg)


@dataclass(slots=True)
class _PlaintextBlockBuilder:
    """Group plaintext KEX lines into validated blocks, in file order.

    A block is a run of metadata lines followed by a run of textual Intel HEX
    records ending in EOF. Each block is validated when the next metadata line
    or the end of the file closes it, so errors surface in line order.
    """

    blocks: list[KexBlock] = field(default_factory=list[KexBlock])
    metadata: list[bytes] = field(default_factory=list[bytes])
    records: bytearray = field(default_factory=bytearray)
    saw_eof: bool = False

    def add_record(self, line: bytes, line_number: int) -> None:
        """Append one ``:`` record line to the open block.

        Raises:
            ValueError: if no metadata line precedes the record, the block
                already holds its EOF record, or the record is malformed.

        """
        if not self.metadata:
            msg = (
                f"plaintext KEX data appears before block metadata at line "
                f"{line_number}"
            )
            raise ValueError(msg)
        if self.saw_eof:
            msg = f"plaintext KEX has a record after EOF at line {line_number}"
            raise ValueError(msg)
        record = _parse_text_record(line, line_number=line_number)
        self.records.extend(record)
        self.saw_eof = record[3] == RecordType.EOF

    def add_metadata(self, line: bytes, line_number: int) -> None:
        """Append one metadata line, first closing the block its records end.

        Raises:
            ValueError: if the open block's records lack an EOF record, the
                closed block fails validation, or the line is encrypted
                updater-resource text.

        """
        if self.records:
            if not self.saw_eof:
                msg = (
                    f"plaintext KEX block {len(self.blocks)} has metadata before EOF "
                    f"at line {line_number}"
                )
                raise ValueError(msg)
            self._close_block()
        if line != b"$ED" and _looks_like_encrypted_resource_line(line):
            msg = (
                "plaintext KEX contains an encrypted-resource line at "
                f"line {line_number}; mixed storage formats are rejected"
            )
            raise ValueError(msg)
        self.metadata.append(line)

    def finish(self) -> tuple[KexBlock, ...]:
        """Close the last block and return every block in file order.

        Raises:
            ValueError: if the last block's records lack an EOF record, the
                file ends with metadata that has no records, or it holds no
                block at all.

        """
        if self.records:
            if not self.saw_eof:
                msg = f"plaintext KEX block {len(self.blocks)} has no EOF record"
                raise ValueError(msg)
            self._close_block()
        elif self.metadata:
            msg = "plaintext KEX ends with metadata that has no data records"
            raise ValueError(msg)
        if not self.blocks:
            msg = "plaintext KEX contains no Intel HEX blocks"
            raise ValueError(msg)
        return tuple(self.blocks)

    def _close_block(self) -> None:
        """Validate the open block, keep it, and start an empty one."""
        self.blocks.append(
            _validated_plaintext_block(
                block_index=len(self.blocks),
                metadata=tuple(self.metadata),
                records=bytes(self.records),
            )
        )
        self.metadata = []
        self.records = bytearray()
        self.saw_eof = False


def _parse_text_record(line: bytes, *, line_number: int) -> bytes:
    """Decode and validate exactly one canonical textual Intel HEX record."""
    encoded = line[1:]
    if not encoded or len(encoded) % 2:
        msg = f"plaintext KEX line {line_number} has an empty or odd-length record"
        raise ValueError(msg)
    if any(byte not in _UPPER_HEX_BYTES for byte in encoded):
        msg = f"plaintext KEX line {line_number} is not uppercase hexadecimal"
        raise ValueError(msg)
    record = bytes.fromhex(encoded.decode("ascii"))
    if len(record) < _RECORD_OVERHEAD:
        msg = f"plaintext KEX line {line_number} is shorter than a record"
        raise ValueError(msg)
    expected_length = 4 + record[0] + 1
    if len(record) != expected_length:
        msg = (
            f"plaintext KEX line {line_number} declares {record[0]} data bytes "
            f"but contains {len(record) - _RECORD_OVERHEAD}"
        )
        raise ValueError(msg)
    if sum(record) & 0xFF and record not in _D75_V103_NONSTANDARD_RECORDS:
        msg = f"plaintext KEX line {line_number} has a bad checksum"
        raise ValueError(msg)
    return record


def _validated_plaintext_block(
    *,
    block_index: int,
    metadata: tuple[bytes, ...],
    records: bytes,
) -> KexBlock:
    """Validate one plaintext block before admitting it to a flash plan."""
    _check_segment_tags(block_index, metadata)
    parsed = parse_intel_hex(records)
    approved_nonstandard_stream = is_d75_v103_nonstandard_overlay_stream(
        block_index=block_index,
        physical_address=_metadata_value(metadata, b"$SA="),
        records=records,
    )
    if parsed.errors and not approved_nonstandard_stream:
        raise ValueError(
            f"plaintext KEX block {block_index} has Intel HEX errors: "
            + "; ".join(parsed.errors)
        )
    _check_record_layout(block_index, records)
    return KexBlock(metadata=metadata, records=records)


def _check_segment_tags(block_index: int, metadata: tuple[bytes, ...]) -> None:
    """Require well-formed, unique ``$`` tags, including ``$ST``, ``$SA`` and ``$ED``.

    Raises:
        ValueError: if a ``$`` line has a malformed tag, a tag repeats, or
            ``$ST``, ``$SA`` or ``$ED`` is missing.

    """
    tag_counts: dict[bytes, int] = {}
    for line in metadata:
        if not line.startswith(b"$"):
            continue
        raw_tag = line[1:].split(b"=", 1)[0]
        if not raw_tag or any(
            byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for byte in raw_tag
        ):
            msg = (
                f"plaintext KEX block {block_index} has malformed segment tag {line!r}"
            )
            raise ValueError(msg)
        tag_counts[raw_tag] = tag_counts.get(raw_tag, 0) + 1

    duplicates = sorted(tag for tag, count in tag_counts.items() if count > 1)
    if duplicates:
        rendered_tags = ", ".join(f"${tag.decode('ascii')}" for tag in duplicates)
        msg = (
            f"plaintext KEX block {block_index} has duplicate segment tag(s): "
            f"{rendered_tags}"
        )
        raise ValueError(msg)
    for required in (b"ST", b"SA", b"ED"):
        if tag_counts.get(required) != 1:
            msg = (
                f"plaintext KEX block {block_index} requires exactly one "
                f"${required.decode('ascii')} tag"
            )
            raise ValueError(msg)


def _check_record_layout(block_index: int, records: bytes) -> None:
    """Require ascending, non-overlapping data records and exactly one EOF.

    Raises:
        ValueError: if a data record overlaps or precedes the previous one,
            the block does not hold exactly one EOF record, or a record is
            truncated.

    """
    previous_end = -1
    eof_count = 0
    for record in iter_records(records):
        if record.record_type == RecordType.DATA:
            start = record.base_address + record.address
            if start < previous_end:
                msg = (
                    f"plaintext KEX block {block_index} has overlapping or "
                    f"out-of-order data at 0x{start:X}"
                )
                raise ValueError(msg)
            previous_end = start + record.byte_count
        elif record.record_type == RecordType.EOF:
            eof_count += 1
    if eof_count != 1:
        msg = f"plaintext KEX block {block_index} requires exactly one EOF record"
        raise ValueError(msg)


def _looks_like_encrypted_resource(data: bytes) -> bool:
    """Recognize the updater's marker-plus-hex encrypted resource grammar."""
    if b":" in data:
        return False
    saw_line = False
    for raw_line in data.splitlines():
        if not raw_line:
            continue
        saw_line = True
        marker, encoded = raw_line[0], raw_line[1:]
        if marker != ord("$") and marker not in _RESOURCE_HEX_BYTES:
            return False
        if len(encoded) % 2 or any(byte not in _RESOURCE_HEX_BYTES for byte in encoded):
            return False
    return saw_line


def _looks_like_encrypted_resource_line(line: bytes) -> bool:
    """Recognize one marker-plus-even-hex line inside an otherwise mixed file."""
    if not line:
        return False
    marker, encoded = line[0], line[1:]
    return bool(
        encoded
        and marker in b"$0123456789abcdefABCDEF"
        and len(encoded) % 2 == 0
        and all(byte in _RESOURCE_HEX_BYTES for byte in encoded)
    )


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
        lines.extend(line.encode("ascii") for line in to_text_lines(block.records))
    return b"\r\n".join(lines) + b"\r\n"


def _resolve_patch(
    patch_or_changes: Patch | Iterable[ByteChange],
) -> tuple[tuple[ByteChange, ...], Patch | None]:
    """Return concrete changes plus optional whole-image integrity policy."""
    if isinstance(patch_or_changes, Patch):
        return patch_or_changes.changes, patch_or_changes
    return tuple(patch_or_changes), None


def _section_start_address(section: str) -> int:
    """Physical ``$SA`` of a section: NOR base plus the section's flash offset."""
    info = lookup_by_name(section)
    if info is None:
        msg = f"unknown section {section!r}"
        raise ValueError(msg)
    return FLASH_BASE + info.flash_address


def _block_index(kex: Kex, section: str) -> int:
    """Return the index of ``section``'s block, located by its ``$SA=`` line.

    Raises:
        ValueError: if ``section`` is not a known section name or no block
            carries its ``$SA=`` address.

    """
    physical = _section_start_address(section)
    for index, block in enumerate(kex.blocks):
        if _metadata_value(block.metadata, b"$SA=") == physical:
            return index
    msg = f"resource has no {section} block ($SA=0x{physical:08X})"
    raise ValueError(msg)


def _parse_block_image(records: bytes, section: str) -> bytes:
    """Parse one block's record stream, rejecting every parser error."""
    parsed = parse_intel_hex(records)
    if parsed.errors:
        msg = f"{section} block has Intel HEX parse errors: " + "; ".join(parsed.errors)
        raise ValueError(msg)
    return parsed.data


def section_image(kex: Kex, section: str) -> bytes:
    """Return the flat image of ``section``'s block (section-relative offsets).

    Raises:
        ValueError: if ``section`` is not a known section name, the resource
            has no block with its ``$SA``, or the block's records do not parse.

    """
    block = kex.blocks[_block_index(kex, section)]
    return _parse_block_image(block.records, section)


def _patch_block(
    block: KexBlock,
    section: str,
    changes: Sequence[ByteChange],
    selected_patch: Patch | None,
) -> KexBlock:
    """Verify, patch and re-checksum one block; unchanged blocks come back as-is.

    A patch may also assign the block a new ``$VA`` version string; the line
    is rewritten at the same byte length so the encrypted splice stays valid.
    """
    source_image = _parse_block_image(block.records, section)
    if selected_patch is not None:
        selected_patch.verify_source(source_image, section)
    version = None if selected_patch is None else selected_patch.version_for(section)
    if not changes:
        if selected_patch is not None:
            selected_patch.verify_result(source_image, section)
        if version is None:
            return block
        return KexBlock(
            metadata=_rewrite_va(block.metadata, version, section),
            records=block.records,
        )
    patched_records = patch_image(block.records, changes)
    region_start = _metadata_value(block.metadata, b"$CS=")
    region_length = _metadata_value(block.metadata, b"$CL=")
    if region_start is None or region_length is None:
        msg = f"{section} block is missing $CS= / $CL= checksum metadata"
        raise ValueError(msg)
    image = _parse_block_image(patched_records, section)
    if selected_patch is not None:
        selected_patch.verify_result(image, section)
    new_ca = _region_checksum(image, region_start, region_length, section)
    metadata = _rewrite_ca(block.metadata, new_ca, section)
    if version is not None:
        metadata = _rewrite_va(metadata, version, section)
    return KexBlock(metadata=metadata, records=patched_records)


def _region_checksum(
    image: bytes, region_start: int, region_length: int, section: str
) -> int:
    """Compute the ``$CA`` of the ``$CS``/``$CL`` region of a patched image.

    Raises:
        ValueError: if the region runs past the end of ``image``.

    """
    if region_start + region_length > len(image):
        # $CS/$CL declare a region larger than the actual image — Python
        # slicing would silently truncate to len(image), producing a $CA
        # computed over fewer bytes than the radio's flash-time verifier
        # will sum. Brick risk; refuse loudly.
        msg = (
            f"$CS=0x{region_start:X}+$CL=0x{region_length:X} exceeds "
            f"{section.lower()} image length 0x{len(image):X}; "
            f"metadata may be corrupt"
        )
        raise ValueError(msg)
    return firmware_checksum(image[region_start : region_start + region_length])


def _changes_by_section(
    changes: Iterable[ByteChange],
) -> dict[str, tuple[ByteChange, ...]]:
    grouped: dict[str, list[ByteChange]] = {}
    for change in changes:
        grouped.setdefault(change.section, []).append(change)
    return {section: tuple(items) for section, items in grouped.items()}


def _apply_stage(
    kex: Kex,
    changes: tuple[ByteChange, ...],
    selected_patch: Patch | None,
) -> Kex:
    """Apply one patch stage to every section it names and return the new model."""
    grouped = _changes_by_section(changes)
    names = set(grouped)
    if selected_patch is not None:
        names.update(selected_patch.touched_sections)
    blocks = list(kex.blocks)
    for section in sorted(names):
        index = _block_index(kex, section)
        blocks[index] = _patch_block(
            blocks[index], section, grouped.get(section, ()), selected_patch
        )
    return Kex(blocks=tuple(blocks))


def patch_kex(
    resource_text: str,
    changes: Patch | Iterable[ByteChange],
) -> bytes:
    """Decrypt an updater resource and emit a patched plaintext .KEX.

    Applies byte changes to every block their section names, fixes the
    Intel HEX record checksums of the records that changed, recomputes
    each patched block's ``$CA`` checksum over its ``$CS``/``$CL`` region,
    and renders the result. Every other byte of every block stays
    identical to the official image.

    Args:
        resource_text: The encrypted updater resource text.
        changes: A ``Patch`` carrying optional whole-image/context/result
            integrity checks, or an iterable of byte changes. The parameter
            retains its original name for keyword-call compatibility.

    Returns:
        The patched ``.KEX`` file as bytes.

    Raises:
        ValueError: if the resource has no block for a named section, that
            block lacks ``$CS=``/``$CL=``/``$CA=`` metadata, or a change's
            offset is invalid (see ``intel_hex.patch_image``).
        PatchVerificationError: if any change's ``expect`` does not
            match the current byte.

    """
    resolved_changes, selected_patch = _resolve_patch(changes)
    kex = parse_resource(resource_text)
    rendered = render(_apply_stage(kex, resolved_changes, selected_patch))
    if selected_patch is not None:
        selected_patch.verify_kex_result(rendered)
    return rendered


def patch_kex_stack(resource_text: str, patches: Sequence[Patch]) -> bytes:
    """Apply ``patches`` in order to one decrypted resource and render the .KEX.

    Every stage's contexts, byte expects and source pins are verified against
    the image as it stands when that stage runs; every stage's result pins are
    verified on its own output. A patch meant to stack must therefore pin only
    what its own stage determines (the theme pins IMAGE_DATA, never FIRMWARE).

    Raises:
        ValueError: if ``patches`` is empty, or on any engine error.
        PatchVerificationError / PatchIntegrityError: on any failed check.

    """
    if not patches:
        msg = "at least one patch is required"
        raise ValueError(msg)
    model = parse_resource(resource_text)
    rendered = b""
    for stage in patches:
        model = _apply_stage(model, stage.changes, stage)
        rendered = render(model)
        stage.verify_kex_result(rendered)
    return rendered


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
                    f"metadata line for {tag_name} has unparseable value {value_str!r}"
                )
                raise ValueError(msg) from exc
    return None


def _rewrite_ca(
    metadata: tuple[bytes, ...], new_ca: int, section: str = "FIRMWARE"
) -> tuple[bytes, ...]:
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
        msg = f"{section} block has no $CA= metadata line"
        raise ValueError(msg)
    return tuple(rewritten)


def _rewrite_va(
    metadata: tuple[bytes, ...], version: str, section: str = "FIRMWARE"
) -> tuple[bytes, ...]:
    """Return ``metadata`` with the ``$VA="..."`` line set to ``version``.

    The new value must have the same byte length as the old one: ``$VL``
    stays valid and the encrypted-resource splice remains same-length.

    Raises:
        ValueError: if there is no ``$VA=`` line, it is not a quoted string,
            or the lengths differ.

    """
    encoded = version.encode("ascii")
    rewritten: list[bytes] = []
    replaced = False
    for line in metadata:
        if not line.startswith(b"$VA="):
            rewritten.append(line)
            continue
        value = line[len(b"$VA=") :]
        if (
            len(value) < _QUOTED_VALUE_MIN_LENGTH
            or value[:1] != b'"'
            or value[-1:] != b'"'
        ):
            msg = f"{section} block has a malformed $VA= line: {line!r}"
            raise ValueError(msg)
        current = value[1:-1]
        if len(current) != len(encoded):
            msg = (
                f"{section} block $VA is {len(current)} bytes ({current!r}); "
                f"version {version!r} must have the same length"
            )
            raise ValueError(msg)
        rewritten.append(b'$VA="' + encoded + b'"')
        replaced = True
    if not replaced:
        msg = f"{section} block has no $VA= metadata line"
        raise ValueError(msg)
    return tuple(rewritten)


def patch_resource(
    resource_text: str,
    changes: Patch | Iterable[ByteChange],
) -> str:
    """Patch the blocks of an *encrypted* updater resource in place.

    Decrypts the resource line by line — preserving every line, its exact
    marker character, blank lines, and CRLF endings — applies the byte
    patches to every block their section names, recomputes the affected
    record checksums and each patched block's ``$CA``, then re-ciphers.
    The result is byte-length-identical to the input and differs only
    where the patch lands, so it can be spliced straight back into the
    updater ``.exe``.

    Args:
        resource_text: The encrypted updater resource text.
        changes: A ``Patch`` carrying optional whole-image/context/result
            integrity checks, or an iterable of byte changes. The parameter
            retains its original name for keyword-call compatibility.

    Returns:
        The re-ciphered resource text.

    Raises:
        ValueError: if the resource has no block for a named section, that
            block lacks ``$CS=``/``$CL=``/``$CA=`` metadata, the patched
            Intel HEX stream has parse errors, the ``$CS``/``$CL``
            region exceeds the block image, or a change's offset is
            invalid (see ``intel_hex.patch_image``).
        PatchVerificationError: if any change's ``expect`` does not
            match the current byte.

    """
    resolved_changes, selected_patch = _resolve_patch(changes)
    decoded = _decode_resource_lines(resource_text)
    grouped = _changes_by_section(resolved_changes)
    names = set(grouped)
    if selected_patch is not None:
        names.update(selected_patch.touched_sections)
    replacements: dict[int, bytes] = {}
    for section in sorted(names):
        replacements.update(
            _resource_block_replacements(
                decoded, section, grouped.get(section, ()), selected_patch
            )
        )
    patched_resource = _encode_resource_lines(decoded, replacements)
    if selected_patch is not None and selected_patch.result_kex_sha256 is not None:
        selected_patch.verify_kex_result(render(parse_resource(patched_resource)))
    return patched_resource


def _decode_resource_lines(resource_text: str) -> list[_DecodedLine]:
    """Decrypt every line of an encrypted resource, keeping the exact layout.

    Blank lines are kept with marker ``None`` and do not advance the cipher;
    every other line keeps its marker character and its trailing-CR flag.

    Raises:
        ValueError: if a line has odd-length or non-hex cipher text.

    """
    state = RollingKeyState()
    decoded: list[_DecodedLine] = []
    for segment in resource_text.split("\n"):
        has_cr = segment.endswith("\r")
        body = segment[:-1] if has_cr else segment
        if not body:
            decoded.append((None, b"", has_cr))
            continue
        _, plaintext = decrypt_line(body, state)
        decoded.append((body[0], plaintext, has_cr))
    return decoded


def _resource_block_replacements(
    decoded: list[_DecodedLine],
    section: str,
    section_changes: tuple[ByteChange, ...],
    selected_patch: Patch | None,
) -> dict[int, bytes]:
    """Return the plaintext line replacements, by index, that patch one block.

    Verifies the block's source and result pins, rewrites its ``$VA`` line when
    the patch assigns a version and, when it has changes, rewrites its data
    lines and its ``$CA`` line at their original lengths.

    Raises:
        ValueError: if the block is missing or lacks required metadata, its
            records do not parse, or its ``$CS``/``$CL`` region exceeds the
            patched image.
        PatchVerificationError: if a change's ``expect`` does not match.
        PatchIntegrityError: if a context window or hash pin does not match.

    """
    location = _locate_block_lines(decoded, section)
    blob = b"".join(decoded[i][1] for i in location.data_indices)
    source_image = _parse_block_image(blob, section)
    if selected_patch is not None:
        selected_patch.verify_source(source_image, section)
    version = None if selected_patch is None else selected_patch.version_for(section)
    replacements: dict[int, bytes] = {}
    if version is not None:
        if location.va_index is None:
            msg = f"{section} block has no $VA= metadata line"
            raise ValueError(msg)
        replacements[location.va_index] = _rewrite_va(
            (decoded[location.va_index][1],), version, section
        )[0]
    if not section_changes:
        if selected_patch is not None:
            selected_patch.verify_result(source_image, section)
        return replacements
    patched_blob = patch_image(blob, section_changes)
    image = _parse_block_image(patched_blob, section)
    if selected_patch is not None:
        selected_patch.verify_result(image, section)
    new_ca = _region_checksum(
        image, location.region_start, location.region_length, section
    )

    # Preserve the original $CA= line's hex-digit width so the
    # re-encrypted line is the same byte length as the line it replaces
    # — the splice-back-into-.exe step is a same-length operation.
    original_ca_line = decoded[location.ca_index][1]
    ca_value = original_ca_line[len(b"$CA=") :].decode("ascii", errors="replace")
    ca_digits = len(ca_value.removeprefix("0x"))
    ca_width = ca_digits if ca_digits > 0 else 4
    replacements[location.ca_index] = b"$CA=0x%0*X" % (ca_width, new_ca)
    cursor = 0
    for i in location.data_indices:
        length = len(decoded[i][1])
        replacements[i] = patched_blob[cursor : cursor + length]
        cursor += length
    return replacements


def _encode_resource_lines(
    decoded: list[_DecodedLine], replacements: dict[int, bytes]
) -> str:
    """Re-cipher decoded lines, substituting ``replacements`` by line index.

    Each line keeps its marker and trailing CR, and one continuous cipher
    stream runs across all non-blank lines, so an unreplaced line re-encrypts
    to its original text.
    """
    out_state = RollingKeyState()
    out: list[str] = []
    for index, (marker, plaintext, has_cr) in enumerate(decoded):
        if marker is None:
            out.append("\r" if has_cr else "")
            continue
        encoded = encrypt_line(replacements.get(index, plaintext), marker, out_state)
        out.append(encoded + "\r" if has_cr else encoded)
    return "\n".join(out)


def patch_resource_stack(resource_text: str, patches: Sequence[Patch]) -> str:
    """Apply ``patches`` in order to an encrypted resource, stage by stage.

    Each stage's ``result_encrypted_resource_sha256`` is checked on that
    stage's own output. See ``patch_kex_stack`` for the stacking contract.

    Raises:
        ValueError: if ``patches`` is empty, or on any engine error.
        PatchVerificationError / PatchIntegrityError: on any failed check.

    """
    if not patches:
        msg = "at least one patch is required"
        raise ValueError(msg)
    text = resource_text
    for stage in patches:
        text = patch_resource(text, stage)
        stage.verify_encrypted_resource_result(text.encode("ascii"))
    return text


@dataclass(frozen=True, slots=True)
class _BlockLocation:
    """Where one section's block sits within a decoded resource line list."""

    section: str
    data_indices: tuple[int, ...]
    ca_index: int
    va_index: int | None
    region_start: int
    region_length: int


def _locate_block_lines(
    decoded: list[_DecodedLine],
    section: str,
) -> _BlockLocation:
    """Segment a decoded resource into blocks and locate ``section``'s block.

    A block is a run of ``$`` metadata lines followed by a run of data
    lines; blank lines are ignored for this segmentation.

    Raises:
        ValueError: if there is no block for ``section``, or it lacks the
            ``$CA=``/``$CS=``/``$CL=`` metadata.

    """
    physical = _section_start_address(section)
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
        if _metadata_value(metadata, b"$SA=") != physical:
            continue
        region_start = _metadata_value(metadata, b"$CS=")
        region_length = _metadata_value(metadata, b"$CL=")
        if region_start is None or region_length is None:
            msg = f"{section} block is missing $CS= / $CL= checksum metadata"
            raise ValueError(msg)
        ca_index = next(
            (i for i in meta_indices if decoded[i][1].startswith(b"$CA=")),
            None,
        )
        if ca_index is None:
            msg = f"{section} block has no $CA= metadata line"
            raise ValueError(msg)
        va_index = next(
            (i for i in meta_indices if decoded[i][1].startswith(b"$VA=")),
            None,
        )
        return _BlockLocation(
            section=section,
            data_indices=tuple(data_indices),
            ca_index=ca_index,
            va_index=va_index,
            region_start=region_start,
            region_length=region_length,
        )
    msg = f"resource has no {section} block ($SA=0x{physical:08X})"
    raise ValueError(msg)
