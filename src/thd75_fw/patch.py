"""Firmware patch abstraction for the TH-D75 updater.

Patches are first-class objects (the ``Patch`` dataclass) carrying a list
of byte changes. Each change declares both the expected current byte and
the new byte; the engine verifies expect bytes against the firmware
before writing, so patches applied to the wrong firmware version,
double-applied, or against corrupted firmware are caught and rejected.

A built-in catalog of vetted patches ships in ``thd75_fw/patches/``;
users can also write their own TOML patches and pass them to the CLI by
path.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypeGuard

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from .sections import lookup_by_name

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__: list[str] = [
    "FIRMWARE_SECTION",
    "ByteChange",
    "ByteContext",
    "Patch",
    "PatchIntegrityError",
    "PatchVerificationError",
    "SectionHashes",
    "expand_run",
    "iter_catalog",
    "load_patch",
    "parse_patch",
]


_SHA256_HEX_LENGTH: int = 64
_BYTE_MAX: Final[int] = 0xFF
"""Largest value one firmware byte holds: ``expect`` and ``value`` lie in 0..255."""

FIRMWARE_SECTION: str = "FIRMWARE"
"""Name of the section that legacy single-section patches address."""


def _validate_section(section: object) -> None:
    if not isinstance(section, str) or lookup_by_name(section) is None:
        msg = f"unknown section {section!r}"
        raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ByteChange:
    """One byte mutation in a firmware patch.

    ``offset`` is into the FIRMWARE block's flat image. The engine reads
    ``expect`` from the firmware before writing ``value``, raising
    ``PatchVerificationError`` on mismatch — no blind writes.
    """

    offset: int
    expect: int
    value: int
    section: str = FIRMWARE_SECTION

    def __post_init__(self) -> None:
        """Reject an unknown section, bool fields and out-of-range or no-op bytes.

        Raises:
            ValueError: if ``section`` is unknown, ``offset`` is negative,
                ``expect`` or ``value`` lies outside 0..255, or ``expect``
                equals ``value``.
            TypeError: if ``offset``, ``expect`` or ``value`` is a ``bool``.

        """
        _validate_section(self.section)
        # bool is a subclass of int in Python, so ``isinstance(True, int)``
        # is True and pyright accepts ``bool`` where ``int`` is annotated.
        # TOML ``true``/``false`` decode as Python bools — without this
        # guard, ``expect = true`` would silently mean ``expect = 1``.
        for field_name, field_value in (
            ("offset", self.offset),
            ("expect", self.expect),
            ("value", self.value),
        ):
            if isinstance(field_value, bool):
                msg = f"{field_name} must be an integer, not a bool"
                raise TypeError(msg)
        if self.offset < 0:
            msg = f"offset must be non-negative, got {self.offset}"
            raise ValueError(msg)
        if not 0 <= self.expect <= _BYTE_MAX:
            msg = f"expect must be 0..255, got {self.expect}"
            raise ValueError(msg)
        if not 0 <= self.value <= _BYTE_MAX:
            msg = f"value must be 0..255, got {self.value}"
            raise ValueError(msg)
        if self.expect == self.value:
            # A no-op change is almost certainly a TOML authoring bug —
            # if the byte already holds the patched value, the change has
            # no effect and would silently mask a more substantive error
            # (e.g. a copy-paste mistake or stale rebase artifact).
            msg = (
                f"expect == value == 0x{self.expect:02X} at offset "
                f"0x{self.offset:X} is a no-op change"
            )
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ByteContext:
    """An unchanged source-byte window that must match before patching.

    Context windows pin the complete instructions surrounding a patch, not
    merely the individual bytes whose values change. ``offset`` is a flat
    FIRMWARE-image offset and ``expect`` is the exact byte sequence there.
    """

    offset: int
    expect: bytes
    section: str = FIRMWARE_SECTION

    def __post_init__(self) -> None:
        """Reject an unknown section, a bool or negative offset and an empty window.

        Raises:
            ValueError: if ``section`` is unknown, ``offset`` is negative, or
                ``expect`` is empty.
            TypeError: if ``offset`` is a ``bool``.

        """
        _validate_section(self.section)
        if isinstance(self.offset, bool):
            msg = "offset must be an integer, not a bool"
            raise TypeError(msg)
        if self.offset < 0:
            msg = f"offset must be non-negative, got {self.offset}"
            raise ValueError(msg)
        if not self.expect:
            msg_0 = "context expect must not be empty"
            raise ValueError(msg_0)


@dataclass(frozen=True, slots=True)
class SectionHashes:
    """Whole-image SHA-256 pins for one non-FIRMWARE section.

    FIRMWARE keeps the top-level ``source_sha256`` / ``result_sha256``
    fields of ``Patch``; this type carries the same two pins for every
    other section a patch touches.
    """

    section: str
    source_sha256: str | None = None
    result_sha256: str | None = None
    version: str | None = None
    """New ``$VA`` version string for the block; the loader's SETUP compares
    it with the bytes at ``$SA + $VS`` and writes the segment on mismatch."""

    def __post_init__(self) -> None:
        """Reject an unknown section, an entry with no pin and malformed pins.

        Raises:
            ValueError: if ``section`` is unknown, no pin is given, ``version``
                is blank, or a digest is not 64 hexadecimal characters.

        """
        _validate_section(self.section)
        if (
            self.source_sha256 is None
            and self.result_sha256 is None
            and self.version is None
        ):
            msg = f"section {self.section} pins neither source, result nor version"
            raise ValueError(msg)
        if self.version is not None and not self.version.strip():
            msg = f"section {self.section}: version must be a non-empty string"
            raise ValueError(msg)
        for field_name, digest in (
            ("source_sha256", self.source_sha256),
            ("result_sha256", self.result_sha256),
        ):
            if digest is not None:
                _validate_sha256(field_name, digest)


@dataclass(frozen=True, slots=True)
class Patch:
    """A firmware patch: a named, described bundle of byte changes.

    Patches are loaded from TOML (the built-in catalog under
    ``thd75_fw/patches/`` or any file the user supplies) and applied by
    the engine via their ``changes`` tuple.
    """

    name: str
    description: str
    target_firmware: str | None
    changes: tuple[ByteChange, ...]
    source_sha256: str | None = None
    result_sha256: str | None = None
    result_kex_sha256: str | None = None
    source_updater_sha256: str | None = None
    result_encrypted_resource_sha256: str | None = None
    result_updater_sha256: str | None = None
    change_count: int | None = None
    contexts: tuple[ByteContext, ...] = ()
    section_hashes: tuple[SectionHashes, ...] = ()

    def __post_init__(self) -> None:
        """Enforce the invariants the patch engine relies on.

        Raises:
            ValueError: if ``name`` or ``description`` is blank,
                ``target_firmware`` is given but blank, there is no change, a
                digest is not 64 hexadecimal characters, ``change_count`` is
                not positive or disagrees with ``changes``, two changes share
                a section and offset, or ``section_hashes`` repeats a section
                or pins FIRMWARE.
            TypeError: if ``change_count`` is a ``bool``.

        """
        self._validate_text()
        if not self.changes:
            msg = "a patch must have at least one change"
            raise ValueError(msg)
        self._validate_digests()
        self._validate_change_count()
        self._validate_unique_changes()
        self._validate_section_pins()

    def _validate_text(self) -> None:
        """Reject a blank name or description and a blank declared target."""
        # ``str.strip()`` rejects whitespace-only names that ``not name``
        # accepts as truthy (e.g. ``"   "`` would otherwise pass the
        # non-empty check and surface as a blank line in
        # ``thd75-list-patches`` output).
        if not self.name or not self.name.strip():
            msg = "name must be non-empty"
            raise ValueError(msg)
        if not self.description or not self.description.strip():
            msg = "description must be non-empty"
            raise ValueError(msg)
        if self.target_firmware is not None and not self.target_firmware.strip():
            # If declared at all, target_firmware must be meaningful;
            # ``target_firmware = ""`` in TOML is almost certainly a typo.
            msg = "target_firmware, if given, must be non-empty"
            raise ValueError(msg)

    def _validate_digests(self) -> None:
        """Require every declared SHA-256 pin to be 64 hexadecimal characters."""
        for field_name, digest in (
            ("source_sha256", self.source_sha256),
            ("result_sha256", self.result_sha256),
            ("result_kex_sha256", self.result_kex_sha256),
            ("source_updater_sha256", self.source_updater_sha256),
            (
                "result_encrypted_resource_sha256",
                self.result_encrypted_resource_sha256,
            ),
            ("result_updater_sha256", self.result_updater_sha256),
        ):
            if digest is not None:
                _validate_sha256(field_name, digest)

    def _validate_change_count(self) -> None:
        """Require a declared ``change_count`` to be a positive, exact count."""
        if isinstance(self.change_count, bool):
            msg = "change_count must be an integer, not a bool"
            raise TypeError(msg)
        if self.change_count is not None:
            if self.change_count <= 0:
                msg = f"change_count must be positive, got {self.change_count}"
                raise ValueError(msg)
            if self.change_count != len(self.changes):
                msg = (
                    f"change_count declares {self.change_count}, but patch defines "
                    f"{len(self.changes)} changes"
                )
                raise ValueError(msg)

    def _validate_unique_changes(self) -> None:
        """Reject two changes at the same offset of the same section."""
        # Duplicate-offset changes silently lose the first one when
        # the engine dedupes by offset (see intel_hex.patch_image);
        # reject at construction so the safety invariant holds. Offsets
        # are only duplicates within one section.
        keys = [(change.section, change.offset) for change in self.changes]
        if len(keys) != len(set(keys)):
            duplicates = sorted({key for key in keys if keys.count(key) > 1})
            msg = "changes have duplicate offset(s): " + ", ".join(
                f"0x{offset:X}"
                if section == FIRMWARE_SECTION
                else f"{section}:0x{offset:X}"
                for section, offset in duplicates
            )
            raise ValueError(msg)

    def _validate_section_pins(self) -> None:
        """Reject a repeated ``section_hashes`` section and FIRMWARE pins there."""
        pinned = [pins.section for pins in self.section_hashes]
        if len(pinned) != len(set(pinned)):
            msg = "section_hashes has duplicate sections"
            raise ValueError(msg)
        if FIRMWARE_SECTION in pinned:
            msg = (
                "FIRMWARE pins belong in source_sha256 / result_sha256, "
                "not section_hashes"
            )
            raise ValueError(msg)

    @property
    def touched_sections(self) -> tuple[str, ...]:
        """Every section named by a change, a context or a hash pin, sorted.

        The top-level ``source_sha256`` and ``result_sha256`` pins belong to
        FIRMWARE, so a patch that changes only another section still has its
        FIRMWARE pins verified.
        """
        names = {change.section for change in self.changes}
        names.update(context.section for context in self.contexts)
        names.update(pins.section for pins in self.section_hashes)
        if self.source_sha256 is not None or self.result_sha256 is not None:
            names.add(FIRMWARE_SECTION)
        return tuple(sorted(names))

    def _section_pins(self, section: str) -> SectionHashes | None:
        for pins in self.section_hashes:
            if pins.section == section:
                return pins
        return None

    def version_for(self, section: str) -> str | None:
        """Return the ``$VA`` version this patch assigns to ``section``, if any."""
        pins = self._section_pins(section)
        return None if pins is None else pins.version

    def verify_source(self, image: bytes, section: str = FIRMWARE_SECTION) -> None:
        """Fail closed unless ``image`` satisfies every source invariant of ``section``."""
        for context in self.contexts:
            if context.section != section:
                continue
            end = context.offset + len(context.expect)
            actual = image[context.offset : end]
            if actual != context.expect:
                msg = (
                    f"source context mismatch at offset 0x{context.offset:X}: "
                    f"expected {context.expect.hex(' ').upper()}, got "
                    f"{actual.hex(' ').upper()}"
                )
                raise PatchIntegrityError(msg)
        if section == FIRMWARE_SECTION:
            expected = self.source_sha256
            label = "source firmware"
        else:
            pins = self._section_pins(section)
            expected = None if pins is None else pins.source_sha256
            label = f"source {section}"
        if expected is not None:
            _verify_sha256(label=label, expected=expected, data=image)

    def verify_result(self, image: bytes, section: str = FIRMWARE_SECTION) -> None:
        """Fail closed unless the patched raw image of ``section`` hashes exactly."""
        if section == FIRMWARE_SECTION:
            expected = self.result_sha256
            label = "patched firmware"
        else:
            pins = self._section_pins(section)
            expected = None if pins is None else pins.result_sha256
            label = f"patched {section}"
        if expected is not None:
            _verify_sha256(label=label, expected=expected, data=image)

    def verify_kex_result(self, rendered_kex: bytes) -> None:
        """Fail closed unless the deterministically rendered KEX is exact."""
        if self.result_kex_sha256 is not None:
            _verify_sha256(
                label="patched KEX",
                expected=self.result_kex_sha256,
                data=rendered_kex,
            )

    def verify_updater_source(self, updater: bytes) -> None:
        """Fail closed unless the input updater executable is exact."""
        if self.source_updater_sha256 is not None:
            _verify_sha256(
                label="source updater",
                expected=self.source_updater_sha256,
                data=updater,
            )

    def verify_encrypted_resource_result(self, resource_data: bytes) -> None:
        """Fail closed unless the patched encrypted resource is exact."""
        if self.result_encrypted_resource_sha256 is not None:
            _verify_sha256(
                label="patched encrypted resource",
                expected=self.result_encrypted_resource_sha256,
                data=resource_data,
            )

    def verify_updater_result(self, updater: bytes) -> None:
        """Fail closed unless the final repacked updater executable is exact."""
        if self.result_updater_sha256 is not None:
            _verify_sha256(
                label="repacked updater",
                expected=self.result_updater_sha256,
                data=updater,
            )


class PatchIntegrityError(ValueError):
    """A whole-image hash, context window, or result hash did not match."""


def _validate_sha256(field_name: str, digest: str) -> None:
    if len(digest) != _SHA256_HEX_LENGTH or any(
        character not in "0123456789abcdefABCDEF" for character in digest
    ):
        msg = f"{field_name} must contain exactly 64 hexadecimal characters"
        raise ValueError(msg)


def _verify_sha256(*, label: str, expected: str, data: bytes) -> None:
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected.lower():
        msg = f"{label} SHA-256 mismatch: expected {expected.lower()}, got {actual}"
        raise PatchIntegrityError(msg)


class PatchVerificationError(ValueError):
    """A patch's expected byte did not match the firmware.

    Raised by the engine before any write — failure is naturally atomic
    (no output is produced if any change's ``expect`` mismatches).
    Carries the offset and the actual vs expected byte so a caller can
    report or handle the mismatch without parsing the message string.

    Attributes:
        offset: The flat-image firmware offset whose ``expect`` failed.
        expected: The byte the patch declared at ``offset``.
        actual: The byte actually present in the firmware.

    """

    def __init__(self, *, offset: int, expected: int, actual: int) -> None:
        """Record the mismatch and build the message from it.

        Args:
            offset: The flat-image firmware offset whose ``expect`` failed.
            expected: The byte the patch declared at ``offset``.
            actual: The byte actually present in the firmware.

        """
        self.offset = offset
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"offset 0x{offset:X}: expected "
            f"0x{expected:02X} but firmware has 0x{actual:02X}"
        )


def expand_run(
    section: str,
    offset: int,
    expect: bytes,
    value: bytes,
) -> tuple[tuple[ByteChange, ...], ByteContext]:
    """Expand a byte run into single-byte changes plus a context window.

    ``expect`` and ``value`` are the current and desired bytes of one
    contiguous window starting at ``offset``. Every byte that differs
    becomes a ``ByteChange``; the whole ``expect`` window becomes a
    ``ByteContext`` so unchanged bytes inside the run are pinned too.

    Raises:
        ValueError: if the run is empty, the two windows differ in length,
            or no byte changes.

    """
    if not expect:
        msg = f"run at offset 0x{offset:X} is empty"
        raise ValueError(msg)
    if len(expect) != len(value):
        msg = (
            f"run at offset 0x{offset:X}: expect ({len(expect)} bytes) and value "
            f"({len(value)} bytes) must have the same length"
        )
        raise ValueError(msg)
    changes = tuple(
        ByteChange(offset=offset + index, expect=old, value=new, section=section)
        for index, (old, new) in enumerate(zip(expect, value, strict=True))
        if old != new
    )
    if not changes:
        msg = f"run at offset 0x{offset:X} changes no byte"
        raise ValueError(msg)
    return changes, ByteContext(offset=offset, expect=expect, section=section)


_VALID_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "description",
        "target_firmware",
        "source_sha256",
        "result_sha256",
        "result_kex_sha256",
        "source_updater_sha256",
        "result_encrypted_resource_sha256",
        "result_updater_sha256",
        "change_count",
        "contexts",
        "changes",
        "sections",
    }
)
_VALID_CHANGE_FIELDS: frozenset[str] = frozenset(
    {"offset", "expect", "value", "section"}
)
_VALID_CONTEXT_FIELDS: frozenset[str] = frozenset({"offset", "expect", "section"})
_VALID_SECTION_FIELDS: frozenset[str] = frozenset(
    {"source_sha256", "result_sha256", "version"}
)


def _is_toml_table(value: object) -> TypeGuard[dict[str, object]]:
    """Report whether a parsed TOML value is a table.

    TOML keys are always strings, so a ``dict`` from ``tomllib`` is a
    ``dict[str, object]``; its values stay ``object`` so each one is
    narrowed again before use.
    """
    return isinstance(value, dict)


def _is_toml_array(value: object) -> TypeGuard[list[object]]:
    """Report whether a parsed TOML value is an array of unchecked items."""
    return isinstance(value, list)


def _toml_table(value: object, message: str) -> dict[str, object]:
    """Return ``value`` as a TOML table, or raise ``ValueError(message)``."""
    if _is_toml_table(value):
        return value
    raise ValueError(message)


def _toml_array(value: object, message: str) -> list[object]:
    """Return ``value`` as a TOML array, or raise ``ValueError(message)``."""
    if _is_toml_array(value):
        return value
    raise ValueError(message)


def _toml_str(value: object, message: str) -> str:
    """Return ``value`` as a TOML string, or raise ``ValueError(message)``."""
    if isinstance(value, str):
        return value
    raise ValueError(message)


def _toml_int(value: object, message: str) -> int:
    """Return ``value`` as a TOML integer, or raise ``ValueError(message)``.

    ``bool`` is a subclass of ``int`` and TOML ``true``/``false`` decode as
    Python bools, so a bool is rejected rather than read as 0 or 1.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ValueError(message)


def _section_of(table: dict[str, object], label: str) -> str:
    if "section" not in table:
        return FIRMWARE_SECTION
    return _toml_str(table["section"], f"{label}: section must be a string")


def parse_patch(toml_text: str) -> Patch:
    """Parse a patch TOML document into a ``Patch``.

    Raises:
        ValueError: on invalid TOML, missing required fields, bad types,
            unknown fields, or any ``ByteChange``/``Patch`` validation
            failure.
        TypeError: if a change field decodes to a Python ``bool`` (TOML
            ``true``/``false`` where an integer was expected).

    """
    try:
        # Typed with the top value type so every field access must narrow
        # via isinstance — untrusted TOML must not bypass static checks.
        document: dict[str, object] = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as exc:
        msg = f"invalid TOML: {exc}"
        raise ValueError(msg) from exc

    # Reject unknown top-level fields: a typo like ``targets_firmware``
    # would otherwise be silently dropped and produce a patch with
    # target_firmware=None despite the author's intent.
    unknown = set(document) - _VALID_TOP_LEVEL_FIELDS
    if unknown:
        msg = f"unknown top-level field(s): {sorted(unknown)}"
        raise ValueError(msg)

    name = _required_str(document, "name")
    description = _required_str(document, "description")
    target_firmware = _optional_str(document, "target_firmware")
    source_sha256 = _optional_str(document, "source_sha256")
    result_sha256 = _optional_str(document, "result_sha256")
    result_kex_sha256 = _optional_str(document, "result_kex_sha256")
    source_updater_sha256 = _optional_str(document, "source_updater_sha256")
    result_encrypted_resource_sha256 = _optional_str(
        document,
        "result_encrypted_resource_sha256",
    )
    result_updater_sha256 = _optional_str(document, "result_updater_sha256")
    change_count = _optional_int(document, "change_count")
    contexts = _parse_contexts(document)

    if "changes" not in document:
        msg = "a patch must have at least one change"
        raise ValueError(msg)
    raw_changes = document["changes"]
    # Entries stay ``object``: ``_parse_change`` narrows each one.
    entries = _toml_array(
        raw_changes,
        "field 'changes' must be a TOML array of tables, "
        f"got {type(raw_changes).__name__}",
    )
    if not entries:
        msg = "a patch must have at least one change"
        raise ValueError(msg)
    changes: list[ByteChange] = []
    run_contexts: list[ByteContext] = []
    for index, entry in enumerate(entries):
        expanded, run_context = _parse_change(entry, index)
        changes.extend(expanded)
        if run_context is not None:
            run_contexts.append(run_context)
    all_contexts = tuple(contexts) + tuple(run_contexts)
    context_keys = [(context.section, context.offset) for context in all_contexts]
    if len(context_keys) != len(set(context_keys)):
        msg_0 = "contexts have duplicate starting offsets"
        raise ValueError(msg_0)
    section_hashes = _parse_sections(document)
    return Patch(
        name=name,
        description=description,
        target_firmware=target_firmware,
        changes=tuple(changes),
        source_sha256=source_sha256,
        result_sha256=result_sha256,
        result_kex_sha256=result_kex_sha256,
        source_updater_sha256=source_updater_sha256,
        result_encrypted_resource_sha256=result_encrypted_resource_sha256,
        result_updater_sha256=result_updater_sha256,
        change_count=change_count,
        contexts=all_contexts,
        section_hashes=section_hashes,
    )


def _required_str(document: dict[str, object], field: str) -> str:
    if field not in document:
        msg = f"missing required field {field!r}"
        raise ValueError(msg)
    return _toml_str(document[field], f"field {field!r} must be a string")


def _optional_str(document: dict[str, object], field: str) -> str | None:
    if field not in document:
        return None
    return _toml_str(document[field], f"field {field!r} must be a string")


def _optional_int(document: dict[str, object], field: str) -> int | None:
    if field not in document:
        return None
    return _toml_int(
        document[field],
        f"field {field!r} must be an integer, not a bool or other type",
    )


def _parse_contexts(document: dict[str, object]) -> tuple[ByteContext, ...]:
    if "contexts" not in document:
        return ()
    entries = _toml_array(
        document["contexts"], "field 'contexts' must be a TOML array of tables"
    )
    contexts = tuple(
        _parse_context(entry, index) for index, entry in enumerate(entries)
    )
    keys = [(context.section, context.offset) for context in contexts]
    if len(keys) != len(set(keys)):
        msg = "contexts have duplicate starting offsets"
        raise ValueError(msg)
    return contexts


def _parse_sections(document: dict[str, object]) -> tuple[SectionHashes, ...]:
    if "sections" not in document:
        return ()
    tables = _toml_table(
        document["sections"], "field 'sections' must be a table of section tables"
    )
    return tuple(
        _parse_section(section, raw_table) for section, raw_table in tables.items()
    )


def _parse_section(section: str, raw_table: object) -> SectionHashes:
    """Parse one ``[sections.<NAME>]`` table into its pins."""
    table = _toml_table(raw_table, f"sections.{section} must be a table")
    unknown = set(table) - _VALID_SECTION_FIELDS
    if unknown:
        msg = f"sections.{section}: unknown field(s): {sorted(unknown)}"
        raise ValueError(msg)
    if section == FIRMWARE_SECTION:
        msg = (
            "FIRMWARE pins belong in source_sha256 / result_sha256, "
            "not [sections.FIRMWARE]"
        )
        raise ValueError(msg)
    source_sha256 = _optional_section_str(table, "source_sha256", section)
    result_sha256 = _optional_section_str(table, "result_sha256", section)
    version = _optional_section_str(table, "version", section)
    try:
        return SectionHashes(
            section=section,
            source_sha256=source_sha256,
            result_sha256=result_sha256,
            version=version,
        )
    except ValueError as exc:
        msg = f"sections.{section}: {exc}"
        raise ValueError(msg) from exc


def _optional_section_str(
    table: dict[str, object], field: str, section: str
) -> str | None:
    """Return the optional string ``field`` of ``[sections.<section>]``."""
    value = table.get(field)
    if value is None:
        return None
    return _toml_str(value, f"sections.{section}: {field} must be a string")


def _parse_context(entry: object, index: int) -> ByteContext:
    label = f"contexts[{index}]"
    table = _toml_table(entry, f"{label} must be a table")
    unknown = set(table) - _VALID_CONTEXT_FIELDS
    if unknown:
        msg = f"{label}: unknown field(s): {sorted(unknown)}"
        raise ValueError(msg)
    if "offset" not in table or "expect" not in table:
        msg = f"{label} requires 'offset' and 'expect'"
        raise ValueError(msg)
    section = _section_of(table, label)
    offset = _toml_int(table["offset"], f"{label}: offset must be an integer")
    not_hex = f"{label}: expect must be a hexadecimal string"
    expect = _toml_str(table["expect"], not_hex)
    try:
        expected_bytes = bytes.fromhex(expect)
    except ValueError as exc:
        raise ValueError(not_hex) from exc
    try:
        return ByteContext(offset=offset, expect=expected_bytes, section=section)
    except (ValueError, TypeError) as exc:
        msg = f"{label}: {exc}"
        raise ValueError(msg) from exc


def _parse_change(
    entry: object, index: int
) -> tuple[tuple[ByteChange, ...], ByteContext | None]:
    """Parse one ``[[changes]]`` table.

    An integer ``expect``/``value`` pair yields one change and no context; a
    hex-string pair is a run and yields one change per differing byte plus a
    context pinning the whole window (see ``expand_run``).
    """
    label = f"changes[{index}]"
    table = _toml_table(entry, f"{label} must be a table")

    # Reject unknown change fields: a typo like ``expects = 0x1B``
    # would otherwise silently mean ``expect`` is missing, producing a
    # confusing "missing required field" error that hides the real bug.
    unknown = set(table) - _VALID_CHANGE_FIELDS
    if unknown:
        msg = f"{label}: unknown field(s): {sorted(unknown)}"
        raise ValueError(msg)
    for field in ("offset", "expect", "value"):
        if field not in table:
            msg = f"{label}: missing required field {field!r}"
            raise ValueError(msg)
    section = _section_of(table, label)
    raw_offset = table["offset"]
    offset = _toml_int(
        raw_offset,
        f"{label}: field 'offset' must be an integer, got {type(raw_offset).__name__}",
    )
    expect = table["expect"]
    value = table["value"]
    if isinstance(expect, str) or isinstance(value, str):
        return _parse_run_change(label, section, offset, expect, value)

    expect_byte = _change_byte(expect, label, "expect")
    value_byte = _change_byte(value, label, "value")
    try:
        change = ByteChange(
            offset=offset,
            expect=expect_byte,
            value=value_byte,
            section=section,
        )
    except (ValueError, TypeError) as exc:
        # Re-raise with the change-index context so the user knows
        # which entry in their TOML is malformed.
        msg = f"{label}: {exc}"
        raise ValueError(msg) from exc
    return (change,), None


def _parse_run_change(
    label: str, section: str, offset: int, expect: object, value: object
) -> tuple[tuple[ByteChange, ...], ByteContext]:
    """Expand a ``[[changes]]`` table whose ``expect`` or ``value`` is a string.

    Both must be hex strings; ``expand_run`` then yields one change per
    differing byte and the context pinning the whole window.
    """
    mixed = f"{label}: expect and value must be both hex strings or both integers"
    expect_text = _toml_str(expect, mixed)
    value_text = _toml_str(value, mixed)
    try:
        expect_bytes = bytes.fromhex(expect_text)
        value_bytes = bytes.fromhex(value_text)
    except ValueError as exc:
        msg = f"{label}: expect and value must be hexadecimal strings"
        raise ValueError(msg) from exc
    try:
        return expand_run(section, offset, expect_bytes, value_bytes)
    except (ValueError, TypeError) as exc:
        msg = f"{label}: {exc}"
        raise ValueError(msg) from exc


def _change_byte(value: object, label: str, field: str) -> int:
    """Return the integer ``field`` (``expect`` or ``value``) of a change table.

    bool is a subclass of int — TOML ``true``/``false`` decode as Python
    bools. Reject explicitly so ``expect = true`` does not silently mean
    ``expect = 1``.

    Raises:
        ValueError: if ``value`` is a bool or not an integer.

    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    reason = "not a bool" if isinstance(value, bool) else f"got {type(value).__name__}"
    msg = f"{label}: field {field!r} must be an integer, {reason}"
    raise ValueError(msg)


def iter_catalog() -> Iterator[Patch]:
    """Yield every built-in catalog patch, sorted by patch ``name``.

    The catalog directory is scanned for ``*.toml`` files; each is
    parsed and the resulting ``Patch`` instances are yielded in
    ``name``-sorted order so the iteration order is stable regardless
    of filesystem listing order.
    """
    catalog_dir = importlib.resources.files("thd75_fw") / "patches"
    toml_files = [
        entry for entry in catalog_dir.iterdir() if entry.name.endswith(".toml")
    ]
    parsed = [parse_patch(entry.read_text(encoding="utf-8")) for entry in toml_files]
    yield from sorted(parsed, key=lambda patch: patch.name)


def load_patch(name_or_path: str | Path) -> Patch:
    r"""Resolve ``name_or_path`` to a Patch.

    Resolution order: a filesystem path that exists, then a catalog
    name. If the argument looks like a path (contains ``/`` or ``\\``
    or ends in ``.toml``) but does not point at a file, a path-specific
    error is raised so the user is not misled into thinking they need
    a catalog name. Otherwise, an unknown catalog name raises
    ``ValueError`` with the list of available catalog names.

    Raises:
        ValueError: if the argument resolves to neither a file nor a
            catalog name, or if two catalog files declare the same
            ``name``.

    """
    path = Path(name_or_path)
    if path.is_file():
        return parse_patch(path.read_text(encoding="utf-8"))

    key = str(name_or_path)
    looks_like_path = "/" in key or "\\" in key or key.endswith(".toml")
    if looks_like_path:
        msg = f"patch file not found: {key}"
        raise ValueError(msg)

    catalog: dict[str, Patch] = {}
    for patch in iter_catalog():
        if patch.name in catalog:
            msg = f"duplicate patch name in catalog: {patch.name!r}"
            raise ValueError(msg)
        catalog[patch.name] = patch
    if key in catalog:
        return catalog[key]

    available = ", ".join(sorted(catalog))
    msg = f"patch {key!r} not found; available: {available}"
    raise ValueError(msg)
