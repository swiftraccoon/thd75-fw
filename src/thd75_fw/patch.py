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

import importlib.resources
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__: list[str] = [
    "ByteChange",
    "Patch",
    "PatchVerificationError",
    "iter_catalog",
    "load_patch",
    "parse_patch",
]


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

    def __post_init__(self) -> None:
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
        if not 0 <= self.expect <= 0xFF:
            msg = f"expect must be 0..255, got {self.expect}"
            raise ValueError(msg)
        if not 0 <= self.value <= 0xFF:
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

    def __post_init__(self) -> None:
        # ``str.strip()`` rejects whitespace-only names that ``not name``
        # accepts as truthy (e.g. ``"   "`` would otherwise pass the
        # non-empty check and surface as a blank line in
        # ``thd75-list-patches`` output).
        if not self.name or not self.name.strip():
            raise ValueError("name must be non-empty")
        if not self.description or not self.description.strip():
            raise ValueError("description must be non-empty")
        if self.target_firmware is not None and not self.target_firmware.strip():
            # If declared at all, target_firmware must be meaningful;
            # ``target_firmware = ""`` in TOML is almost certainly a typo.
            raise ValueError("target_firmware, if given, must be non-empty")
        if not self.changes:
            raise ValueError("a patch must have at least one change")
        offsets = [change.offset for change in self.changes]
        if len(offsets) != len(set(offsets)):
            # Duplicate-offset changes silently lose the first one when
            # the engine dedupes by offset (see intel_hex.patch_image);
            # reject at construction so the safety invariant holds.
            duplicates = sorted({o for o in offsets if offsets.count(o) > 1})
            msg = (
                "changes have duplicate offset(s): "
                + ", ".join(f"0x{o:X}" for o in duplicates)
            )
            raise ValueError(msg)


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
        self.offset = offset
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"offset 0x{offset:X}: expected "
            f"0x{expected:02X} but firmware has 0x{actual:02X}"
        )


_VALID_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {"name", "description", "target_firmware", "changes"}
)
_VALID_CHANGE_FIELDS: frozenset[str] = frozenset({"offset", "expect", "value"})


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
        raw_document: Any = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as exc:
        msg = f"invalid TOML: {exc}"
        raise ValueError(msg) from exc
    # Re-type with the top type so every field access must narrow via
    # isinstance — untrusted TOML must not bypass static checks.
    document: dict[str, object] = raw_document

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

    if "changes" not in document:
        raise ValueError("a patch must have at least one change")
    raw_changes = document["changes"]
    if not isinstance(raw_changes, list):
        msg = (
            f"field 'changes' must be a TOML array of tables, "
            f"got {type(raw_changes).__name__}"
        )
        raise ValueError(msg)
    if not raw_changes:
        raise ValueError("a patch must have at least one change")

    # isinstance narrows to `list` but loses element type; treat as
    # `list[object]` so `_parse_change` does the per-entry narrowing.
    entries: list[object] = cast("list[object]", raw_changes)
    changes = tuple(
        _parse_change(entry, index) for index, entry in enumerate(entries)
    )
    return Patch(
        name=name,
        description=description,
        target_firmware=target_firmware,
        changes=changes,
    )


def _required_str(document: dict[str, object], field: str) -> str:
    if field not in document:
        msg = f"missing required field {field!r}"
        raise ValueError(msg)
    value = document[field]
    if not isinstance(value, str):
        msg = f"field {field!r} must be a string"
        raise ValueError(msg)
    return value


def _optional_str(document: dict[str, object], field: str) -> str | None:
    if field not in document:
        return None
    value = document[field]
    if not isinstance(value, str):
        msg = f"field {field!r} must be a string"
        raise ValueError(msg)
    return value


def _parse_change(entry: object, index: int) -> ByteChange:
    if not isinstance(entry, dict):
        msg = f"changes[{index}] must be a table"
        raise ValueError(msg)
    # Cast to a typed dict view; isinstance narrows to `dict` but loses
    # key/value types. Each value is still checked at runtime below.
    table: dict[str, object] = cast("dict[str, object]", entry)

    # Reject unknown change fields: a typo like ``expects = 0x1B``
    # would otherwise silently mean ``expect`` is missing, producing a
    # confusing "missing required field" error that hides the real bug.
    unknown = set(table) - _VALID_CHANGE_FIELDS
    if unknown:
        msg = f"changes[{index}]: unknown field(s): {sorted(unknown)}"
        raise ValueError(msg)

    parsed: dict[str, int] = {}
    for field in ("offset", "expect", "value"):
        if field not in table:
            msg = f"changes[{index}]: missing required field {field!r}"
            raise ValueError(msg)
        field_value = table[field]
        # bool is a subclass of int — TOML ``true``/``false`` decode
        # as Python bools. Reject explicitly so ``expect = true`` does
        # not silently mean ``expect = 1``.
        if isinstance(field_value, bool):
            msg = (
                f"changes[{index}]: field {field!r} must be an integer, "
                f"not a bool"
            )
            raise ValueError(msg)
        if not isinstance(field_value, int):
            msg = (
                f"changes[{index}]: field {field!r} must be an integer, "
                f"got {type(field_value).__name__}"
            )
            raise ValueError(msg)
        parsed[field] = field_value
    try:
        return ByteChange(
            offset=parsed["offset"],
            expect=parsed["expect"],
            value=parsed["value"],
        )
    except (ValueError, TypeError) as exc:
        # Re-raise with the change-index context so the user knows
        # which entry in their TOML is malformed.
        msg = f"changes[{index}]: {exc}"
        raise ValueError(msg) from exc


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
    """Resolve ``name_or_path`` to a Patch.

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
