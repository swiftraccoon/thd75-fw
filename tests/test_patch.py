"""Tests for the patch abstraction."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from thd75_fw.patch import (
    ByteChange,
    Patch,
    PatchVerificationError,
    iter_catalog,
    load_patch,
    parse_patch,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestByteChange:
    """A ByteChange = offset + expected-old + new-value; values are 0..255."""

    def test_construction_holds_fields(self) -> None:
        change = ByteChange(offset=0x10444, expect=0x1B, value=0x33)
        assert change.offset == 0x10444
        assert change.expect == 0x1B
        assert change.value == 0x33

    def test_frozen(self) -> None:
        # Use distinct expect/value (a meaningful change) — the dataclass
        # rejects no-op changes (expect == value) at construction now.
        change = ByteChange(offset=0, expect=0, value=1)
        with pytest.raises(AttributeError):
            change.offset = 1  # type: ignore[misc]

    def test_negative_offset_rejected(self) -> None:
        with pytest.raises(ValueError, match="offset must be non-negative"):
            ByteChange(offset=-1, expect=0, value=0)

    def test_negative_expect_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"expect must be 0\.\.255"):
            ByteChange(offset=0, expect=-1, value=0)

    def test_out_of_range_expect_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"expect must be 0\.\.255"):
            ByteChange(offset=0, expect=256, value=0)

    def test_negative_value_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"value must be 0\.\.255"):
            ByteChange(offset=0, expect=0, value=-1)

    def test_out_of_range_value_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"value must be 0\.\.255"):
            ByteChange(offset=0, expect=0, value=256)

    def test_no_op_change_rejected(self) -> None:
        # ``expect == value`` is almost certainly a TOML authoring bug
        # (copy-paste, stale rebase) — would silently do nothing if
        # accepted. Reject at construction so the catalog can't ship one.
        with pytest.raises(ValueError, match="no-op change"):
            ByteChange(offset=0x10444, expect=0x33, value=0x33)

    def test_bool_field_rejected(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python; TOML decodes
        # ``true``/``false`` as Python bools. Reject explicitly so a
        # ``value = true`` in a TOML patch doesn't silently mean
        # ``value = 1``.
        with pytest.raises(
            TypeError, match="value must be an integer, not a bool",
        ):
            ByteChange(offset=0, expect=0, value=True)


class TestPatch:
    """A Patch bundles ByteChanges with name/description/target metadata.
    Validates non-empty changes and non-blank name/description."""

    def test_construction(self) -> None:
        patch = Patch(
            name="example",
            description="A test patch.",
            target_firmware="TH-D75 V1.03",
            changes=(ByteChange(0, 0, 1),),
        )
        assert patch.name == "example"
        assert patch.description == "A test patch."
        assert patch.target_firmware == "TH-D75 V1.03"
        assert len(patch.changes) == 1

    def test_target_firmware_optional(self) -> None:
        patch = Patch(
            name="x",
            description="d",
            target_firmware=None,
            changes=(ByteChange(0, 0, 1),),
        )
        assert patch.target_firmware is None

    def test_frozen(self) -> None:
        patch = Patch(
            name="x", description="d",
            target_firmware=None, changes=(ByteChange(0, 0, 1),),
        )
        with pytest.raises(AttributeError):
            patch.name = "y"  # type: ignore[misc]

    def test_empty_changes_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one change"):
            Patch(
                name="x", description="d",
                target_firmware=None, changes=(),
            )

    def test_blank_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="name must be non-empty"):
            Patch(
                name="", description="d",
                target_firmware=None, changes=(ByteChange(0, 0, 1),),
            )

    def test_blank_description_rejected(self) -> None:
        with pytest.raises(ValueError, match="description must be non-empty"):
            Patch(
                name="x", description="",
                target_firmware=None, changes=(ByteChange(0, 0, 1),),
            )


class TestPatchVerificationError:
    """Raised when a patch's `expect` byte does not match the firmware."""

    def test_is_value_error_subclass(self) -> None:
        # Catchable as ValueError too — useful for callers that want a
        # broad "the patch couldn't be applied" net.
        assert issubclass(PatchVerificationError, ValueError)

    def test_carries_message(self) -> None:
        # PatchVerificationError now takes structured kwargs (offset,
        # expected, actual) and builds the message itself, so callers
        # can react to the mismatch without parsing the string.
        exc = PatchVerificationError(offset=0x10, expected=0x1B, actual=0x33)
        assert "0x10" in str(exc)

    def test_carries_structured_fields(self) -> None:
        # Callers (CLI, library consumers) can pull the failure context
        # out programmatically without parsing the message string.
        exc = PatchVerificationError(offset=0x10444, expected=0x1B, actual=0x33)
        assert exc.offset == 0x10444
        assert exc.expected == 0x1B
        assert exc.actual == 0x33


_SAMPLE_TOML = """
name        = "pf-screen-capture"
description = "Front-panel PF screen-capture patch (test sample)."
target_firmware = "TH-D75 V1.03"

[[changes]]
offset = 0x10444
expect = 0x1B
value  = 0x33

[[changes]]
offset = 0x104B8
expect = 0x1B
value  = 0x33
"""


class TestParsePatch:
    """`parse_patch` round-trips the documented TOML schema and raises a
    clear ValueError on bad input."""

    def test_round_trip(self) -> None:
        patch = parse_patch(_SAMPLE_TOML)
        assert patch.name == "pf-screen-capture"
        assert patch.description.startswith("Front-panel")
        assert patch.target_firmware == "TH-D75 V1.03"
        assert len(patch.changes) == 2
        assert patch.changes[0] == ByteChange(offset=0x10444, expect=0x1B, value=0x33)
        assert patch.changes[1] == ByteChange(offset=0x104B8, expect=0x1B, value=0x33)

    def test_target_firmware_optional(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0
expect = 0
value  = 1
"""
        patch = parse_patch(toml)
        assert patch.target_firmware is None

    def test_missing_name_rejected(self) -> None:
        toml = """
description = "d"

[[changes]]
offset = 0
expect = 0
value  = 1
"""
        with pytest.raises(ValueError, match="missing required field 'name'"):
            parse_patch(toml)

    def test_missing_description_rejected(self) -> None:
        toml = """
name = "x"

[[changes]]
offset = 0
expect = 0
value  = 1
"""
        with pytest.raises(ValueError, match="missing required field 'description'"):
            parse_patch(toml)

    def test_missing_changes_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"
"""
        with pytest.raises(ValueError, match="at least one change"):
            parse_patch(toml)

    def test_change_missing_field_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0
expect = 0
"""
        with pytest.raises(ValueError, match="missing required field 'value'"):
            parse_patch(toml)

    def test_bad_toml_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid TOML"):
            parse_patch("name = ")


class TestIterCatalog:
    """`iter_catalog` yields every TOML file shipped under
    ``thd75_fw/patches/``, sorted by name."""

    def test_yields_screen_capture(self) -> None:
        names = [p.name for p in iter_catalog()]
        assert "pf-screen-capture" in names

    def test_sorted_by_name(self) -> None:
        names = [p.name for p in iter_catalog()]
        assert names == sorted(names)

    def test_screen_capture_payload(self) -> None:
        patch = next(p for p in iter_catalog() if p.name == "pf-screen-capture")
        assert patch.target_firmware == "TH-D75 V1.03"
        offsets = sorted(c.offset for c in patch.changes)
        assert offsets == [0x10444, 0x104B8]
        assert all(c.expect == 0x1B and c.value == 0x33 for c in patch.changes)


class TestLoadPatch:
    """`load_patch` resolves a string to a Patch — path first, then catalog."""

    def test_loads_by_catalog_name(self) -> None:
        patch = load_patch("pf-screen-capture")
        assert patch.name == "pf-screen-capture"

    def test_loads_by_path(self, tmp_path: Path) -> None:
        toml = """
name        = "custom"
description = "user-supplied patch"

[[changes]]
offset = 0
expect = 0
value  = 1
"""
        file = tmp_path / "custom.toml"
        file.write_text(toml.lstrip(), encoding="utf-8")
        patch = load_patch(file)
        assert patch.name == "custom"

    def test_unknown_name_lists_available(self) -> None:
        with pytest.raises(ValueError, match=r"not found.*pf-screen-capture"):
            load_patch("nonexistent-patch")

    def test_path_looking_name_gets_path_specific_error(
        self, tmp_path: Path,
    ) -> None:
        # A user passing ``--patch ./typo.toml`` should see a path-not-found
        # error, not a catalog-not-found error that misleads them about
        # the problem.
        bad_path = tmp_path / "nonexistent.toml"
        with pytest.raises(ValueError, match="patch file not found"):
            load_patch(bad_path)

    def test_path_with_separator_nonexistent_gets_path_specific_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="patch file not found"):
            load_patch("./not/a/real/file")

    def test_directory_not_treated_as_path(self, tmp_path: Path) -> None:
        # A directory at the named path is not a file → resolution falls
        # through to catalog lookup. Since the catalog has no entry
        # named ``str(tmp_path)`` (and tmp_path contains a separator),
        # the path-looking branch fires first.
        with pytest.raises(ValueError, match="patch file not found"):
            load_patch(tmp_path)


class TestPatchDuplicateOffsets:
    """Two ``ByteChange`` entries with the same offset would silently
    bypass the first ``expect`` check at the engine level (dict-by-offset
    dedup); reject at construction so the catalog can't ship one."""

    def test_two_changes_same_offset_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate offset"):
            Patch(
                name="x", description="d", target_firmware=None,
                changes=(
                    ByteChange(0x10444, 0x1B, 0x33),
                    ByteChange(0x10444, 0x33, 0x77),  # same offset
                ),
            )

    def test_three_changes_two_distinct_offsets_rejected(self) -> None:
        # The error message names every duplicated offset.
        with pytest.raises(ValueError, match=r"0x10444"):
            Patch(
                name="x", description="d", target_firmware=None,
                changes=(
                    ByteChange(0x10444, 0x1B, 0x33),
                    ByteChange(0x10500, 0x00, 0x01),
                    ByteChange(0x10444, 0x99, 0xAA),
                ),
            )


class TestPatchWhitespaceFields:
    """``Patch`` rejects whitespace-only ``name``/``description``: the
    naked truthy check accepts e.g. ``"   "``, which would surface as
    a blank line in ``thd75-list-patches`` output."""

    def test_whitespace_only_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="name must be non-empty"):
            Patch(
                name="   ", description="d", target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
            )

    def test_whitespace_only_description_rejected(self) -> None:
        with pytest.raises(ValueError, match="description must be non-empty"):
            Patch(
                name="x", description="\n\t", target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
            )

    def test_empty_target_firmware_rejected(self) -> None:
        # ``target_firmware = ""`` in TOML is almost certainly a typo;
        # ``target_firmware = None`` (i.e. omitting the field) is the
        # explicit way to declare "unspecified".
        with pytest.raises(ValueError, match=r"target_firmware.*non-empty"):
            Patch(
                name="x", description="d", target_firmware="",
                changes=(ByteChange(0, 0, 1),),
            )


class TestParsePatchTomlLevelValidation:
    """TOML-level rejection paths — the user-visible failure surface
    for hand-written patch files. Tests pin the error messages so a
    refactor cannot quietly soften them."""

    def test_empty_toml_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing required field 'name'"):
            parse_patch("")

    def test_changes_not_a_list_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"
changes     = 42
"""
        with pytest.raises(ValueError, match="must be a TOML array"):
            parse_patch(toml)

    def test_empty_changes_list_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"
changes     = []
"""
        with pytest.raises(ValueError, match="at least one change"):
            parse_patch(toml)

    def test_negative_offset_in_toml_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = -1
expect = 0
value  = 1
"""
        with pytest.raises(ValueError, match="offset must be non-negative"):
            parse_patch(toml)

    def test_expect_out_of_range_in_toml_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0
expect = 256
value  = 0
"""
        with pytest.raises(ValueError, match=r"expect must be 0\.\.255"):
            parse_patch(toml)

    def test_value_out_of_range_in_toml_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0
expect = 0
value  = 999
"""
        with pytest.raises(ValueError, match=r"value must be 0\.\.255"):
            parse_patch(toml)

    def test_string_where_integer_expected_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = "0x10444"
expect = 0x1B
value  = 0x33
"""
        with pytest.raises(ValueError, match="must be an integer"):
            parse_patch(toml)

    def test_bool_where_integer_expected_rejected(self) -> None:
        # TOML ``true``/``false`` decode as Python bools and would
        # silently mean 1/0 if not rejected explicitly.
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0
expect = 0
value  = true
"""
        with pytest.raises(ValueError, match="must be an integer, not a bool"):
            parse_patch(toml)

    def test_unknown_top_level_field_rejected(self) -> None:
        # Catches typos like ``targets_firmware = "..."`` that would
        # silently leave the actual field at its default.
        toml = """
name             = "x"
description      = "d"
targets_firmware = "TH-D75 V1.03"

[[changes]]
offset = 0
expect = 0
value  = 1
"""
        with pytest.raises(ValueError, match="unknown top-level field"):
            parse_patch(toml)

    def test_unknown_change_field_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset  = 0
expect  = 0
value   = 1
expects = 0x1B
"""
        with pytest.raises(ValueError, match=r"changes\[0\]: unknown field"):
            parse_patch(toml)

    def test_duplicate_offset_in_toml_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0x10444
expect = 0x1B
value  = 0x33

[[changes]]
offset = 0x10444
expect = 0x33
value  = 0x77
"""
        with pytest.raises(ValueError, match="duplicate offset"):
            parse_patch(toml)

    def test_no_op_change_in_toml_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0x10444
expect = 0x33
value  = 0x33
"""
        with pytest.raises(ValueError, match="no-op change"):
            parse_patch(toml)


class TestCatalogContents:
    """Every catalog patch must parse without error and carry the
    minimum metadata a user needs (name, description, at least one
    change). Defends against shipping a broken .toml file in the
    catalog directory."""

    def test_every_catalog_patch_parses_with_required_fields(self) -> None:
        patches = list(iter_catalog())
        assert patches, "catalog should not be empty"
        for entry in patches:
            assert entry.name, f"catalog patch missing name: {entry}"
            assert entry.description, (
                f"catalog patch missing description: {entry.name}"
            )
            assert entry.changes, (
                f"catalog patch has no changes: {entry.name}"
            )
