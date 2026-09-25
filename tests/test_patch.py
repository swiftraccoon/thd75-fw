"""Tests for the patch abstraction."""

from __future__ import annotations

import functools
import hashlib
from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from thd75_fw.patch import (
    FIRMWARE_SECTION,
    ByteChange,
    ByteContext,
    Patch,
    PatchIntegrityError,
    PatchVerificationError,
    SectionHashes,
    expand_run,
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
        # Frozen dataclasses reject attribute assignment at runtime; the field
        # name is a variable so ruff's B010 does not rewrite it to setattr, and
        # pyright accepts setattr where ``change.offset = 1`` would be a typed
        # frozen-instance error.
        field_name = "offset"
        with pytest.raises(AttributeError):
            setattr(change, field_name, 1)

    def test_negative_offset_rejected(self) -> None:
        with pytest.raises(ValueError, match="offset must be non-negative"):
            _ = ByteChange(offset=-1, expect=0, value=0)

    def test_negative_expect_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"expect must be 0\.\.255"):
            _ = ByteChange(offset=0, expect=-1, value=0)

    def test_out_of_range_expect_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"expect must be 0\.\.255"):
            _ = ByteChange(offset=0, expect=256, value=0)

    def test_negative_value_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"value must be 0\.\.255"):
            _ = ByteChange(offset=0, expect=0, value=-1)

    def test_out_of_range_value_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"value must be 0\.\.255"):
            _ = ByteChange(offset=0, expect=0, value=256)

    def test_no_op_change_rejected(self) -> None:
        # ``expect == value`` is almost certainly a TOML authoring bug
        # (copy-paste, stale rebase) — would silently do nothing if
        # accepted. Reject at construction so the catalog can't ship one.
        with pytest.raises(ValueError, match="no-op change"):
            _ = ByteChange(offset=0x10444, expect=0x33, value=0x33)

    def test_bool_field_rejected(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python; TOML decodes
        # ``true``/``false`` as Python bools. Reject explicitly so a
        # ``value = true`` in a TOML patch doesn't silently mean
        # ``value = 1``.
        with pytest.raises(
            TypeError,
            match="value must be an integer, not a bool",
        ):
            _ = ByteChange(offset=0, expect=0, value=True)


class TestByteContext:
    """Context windows pin complete original instruction byte strings."""

    def test_construction(self) -> None:
        context = ByteContext(offset=0x6F85C, expect=bytes.fromhex("A0 26 F6 02"))
        assert context.offset == 0x6F85C
        assert context.expect == b"\xa0\x26\xf6\x02"

    def test_empty_context_rejected(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            _ = ByteContext(offset=0, expect=b"")

    def test_negative_offset_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            _ = ByteContext(offset=-1, expect=b"\x00")


class TestPatch:
    """A Patch bundles ByteChanges with name/description/target metadata.

    Validates non-empty changes and non-blank name/description.
    """

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
            name="x",
            description="d",
            target_firmware=None,
            changes=(ByteChange(0, 0, 1),),
        )
        # See TestByteChange.test_frozen for why this uses setattr with the
        # field name in a variable.
        field_name = "name"
        with pytest.raises(AttributeError):
            setattr(patch, field_name, "y")

    def test_empty_changes_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one change"):
            _ = Patch(
                name="x",
                description="d",
                target_firmware=None,
                changes=(),
            )

    def test_blank_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="name must be non-empty"):
            _ = Patch(
                name="",
                description="d",
                target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
            )

    def test_blank_description_rejected(self) -> None:
        with pytest.raises(ValueError, match="description must be non-empty"):
            _ = Patch(
                name="x",
                description="",
                target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
            )

    def test_declared_change_count_must_match(self) -> None:
        with pytest.raises(ValueError, match=r"declares 2.*defines 1"):
            _ = Patch(
                name="x",
                description="d",
                target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
                change_count=2,
            )

    def test_sha256_fields_are_validated(self) -> None:
        with pytest.raises(ValueError, match="64 hexadecimal"):
            _ = Patch(
                name="x",
                description="d",
                target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
                source_sha256="not-a-digest",
            )


class TestPatchIntegrity:
    """Whole-image, context, and result checks fail closed."""

    # A Patch with the fixed identity fields filled in; each test supplies
    # only the pin or contexts it exercises, as keyword arguments the
    # checkers still validate against Patch.
    _patch = staticmethod(
        functools.partial(
            Patch,
            name="strict",
            description="strict test patch",
            target_firmware=None,
            changes=(ByteChange(1, 0x11, 0x22),),
        )
    )

    def test_source_hash_and_context_accept_exact_image(self) -> None:
        image = b"\x00\x11\x22\x33"
        patch = self._patch(
            source_sha256=hashlib.sha256(image).hexdigest(),
            contexts=(ByteContext(1, b"\x11\x22\x33"),),
        )
        patch.verify_source(image)

    def test_wrong_source_hash_rejected(self) -> None:
        patch = self._patch(source_sha256="00" * 32)
        with pytest.raises(PatchIntegrityError, match="source firmware SHA-256"):
            patch.verify_source(b"\x00\x11")

    def test_wrong_full_context_rejected(self) -> None:
        patch = self._patch(contexts=(ByteContext(0, b"\x00\x11\x22\x33"),))
        with pytest.raises(PatchIntegrityError, match=r"context.*0x0"):
            patch.verify_source(b"\x00\x11\x99\x33")

    def test_wrong_result_hash_rejected(self) -> None:
        patch = self._patch(result_sha256="00" * 32)
        with pytest.raises(PatchIntegrityError, match="patched firmware SHA-256"):
            patch.verify_result(b"\x00\x22")

    def test_wrong_kex_hash_rejected(self) -> None:
        patch = self._patch(result_kex_sha256="00" * 32)
        with pytest.raises(PatchIntegrityError, match="patched KEX SHA-256"):
            patch.verify_kex_result(b"candidate KEX")

    def test_wrong_source_updater_hash_rejected(self) -> None:
        patch = self._patch(source_updater_sha256="00" * 32)
        with pytest.raises(PatchIntegrityError, match="source updater SHA-256"):
            patch.verify_updater_source(b"official updater")

    def test_wrong_encrypted_resource_hash_rejected(self) -> None:
        patch = self._patch(result_encrypted_resource_sha256="00" * 32)
        with pytest.raises(
            PatchIntegrityError,
            match="patched encrypted resource SHA-256",
        ):
            patch.verify_encrypted_resource_result(b"patched resource")

    def test_wrong_repacked_updater_hash_rejected(self) -> None:
        patch = self._patch(result_updater_sha256="00" * 32)
        with pytest.raises(PatchIntegrityError, match="repacked updater SHA-256"):
            patch.verify_updater_result(b"patched updater")


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
    """`parse_patch` round-trips the documented TOML schema.

    It raises a clear ValueError on bad input.
    """

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
            _ = parse_patch(toml)

    def test_missing_description_rejected(self) -> None:
        toml = """
name = "x"

[[changes]]
offset = 0
expect = 0
value  = 1
"""
        with pytest.raises(ValueError, match="missing required field 'description'"):
            _ = parse_patch(toml)

    def test_missing_changes_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"
"""
        with pytest.raises(ValueError, match="at least one change"):
            _ = parse_patch(toml)

    def test_change_missing_field_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"

[[changes]]
offset = 0
expect = 0
"""
        with pytest.raises(ValueError, match="missing required field 'value'"):
            _ = parse_patch(toml)

    def test_bad_toml_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid TOML"):
            _ = parse_patch("name = ")

    def test_integrity_metadata_and_contexts_parse(self) -> None:
        toml = """
name = "strict"
description = "strict patch"
source_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
result_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
result_kex_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
source_updater_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
result_encrypted_resource_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
result_updater_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
change_count = 1

[[contexts]]
offset = 0x6F85C
expect = "A0 26 F6 02"

[[changes]]
offset = 0x6F85C
expect = 0xA0
value = 0x80
"""
        patch = parse_patch(toml)
        assert patch.source_sha256 == "aa" * 32
        assert patch.result_sha256 == "bb" * 32
        assert patch.result_kex_sha256 == "cc" * 32
        assert patch.source_updater_sha256 == "dd" * 32
        assert patch.result_encrypted_resource_sha256 == "ee" * 32
        assert patch.result_updater_sha256 == "ff" * 32
        assert patch.change_count == 1
        assert patch.contexts == (ByteContext(0x6F85C, b"\xa0\x26\xf6\x02"),)

    def test_bad_context_hex_rejected(self) -> None:
        toml = """
name = "strict"
description = "strict patch"

[[contexts]]
offset = 0
expect = "not hex"

[[changes]]
offset = 0
expect = 0
value = 1
"""
        with pytest.raises(ValueError, match=r"contexts\[0\].*hexadecimal"):
            _ = parse_patch(toml)


class TestIterCatalog:
    """`iter_catalog` yields every TOML file shipped under ``thd75_fw/patches/``.

    Files come out sorted by name.
    """

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

    def test_service_9r_nor_read_payload_and_integrity_policy(self) -> None:
        patch = load_patch("service-9r-nor-read")
        assert patch.target_firmware == "TH-D75 V1.03 official FIRMWARE"
        assert patch.source_sha256 == (
            "193963ca4b7a38392815686893858eec20292b629fe999f10b93a22a3a8e4001"
        )
        assert patch.result_sha256 == (
            "c7cd9d300a73c984408df39c50d2fb7802f826b7300cb8ffb7122c366c010e91"
        )
        assert patch.result_kex_sha256 == (
            "fa95a673156c2d47b06a85fd6038682bbe1adfcbd1b7bdfdb7529ecfc1ca9541"
        )
        assert patch.source_updater_sha256 == (
            "a76f0c80525c942c983bd62494109e15270380a6b5964d6c2a6b4726331f60ad"
        )
        assert patch.result_encrypted_resource_sha256 == (
            "4fe12582ea43a1d7debaf97ea6135df7a2d13aa5d68168507f8947a22ac2f0de"
        )
        assert patch.result_updater_sha256 == (
            "5c4a5661dbabab24db32d542ffb3c5273103c6b4e6eff3f3c42f1da4791b029f"
        )
        assert patch.change_count == len(patch.changes) == 19
        assert patch.contexts == (
            ByteContext(0x6F85C, bytes.fromhex("A0 26 F6 02")),
            ByteContext(
                0x6F8A0,
                bytes.fromhex(
                    "02 AA 09 04 09 0C 01 98 A1 F7 B2 FE 01 28 05 D1 "
                    "00 9A 02 A9 28 00 FF F7 D6 FA 04 E0"
                ),
            ),
        )
        assert [(c.offset, c.expect, c.value) for c in patch.changes] == [
            (0x6F85C, 0xA0, 0x80),
            (0x6F85E, 0xF6, 0xB6),
            (0x6F85F, 0x02, 0x03),
            (0x6F8A0, 0x02, 0x60),
            (0x6F8A1, 0xAA, 0x26),
            (0x6F8A2, 0x09, 0x36),
            (0x6F8A3, 0x04, 0x06),
            (0x6F8A4, 0x09, 0x01),
            (0x6F8A5, 0x0C, 0x99),
            (0x6F8A6, 0x01, 0x89),
            (0x6F8A7, 0x98, 0x19),
            (0x6F8A8, 0xA1, 0x02),
            (0x6F8A9, 0xF7, 0xA8),
            (0x6F8AA, 0xB2, 0x00),
            (0x6F8AB, 0xFE, 0x9A),
            (0x6F8AC, 0x01, 0xA1),
            (0x6F8AD, 0x28, 0xF7),
            (0x6F8AE, 0x05, 0x8D),
            (0x6F8AF, 0xD1, 0xFD),
        ]


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
        _ = file.write_text(toml.lstrip(), encoding="utf-8")
        patch = load_patch(file)
        assert patch.name == "custom"

    def test_unknown_name_lists_available(self) -> None:
        with pytest.raises(ValueError, match=r"not found.*pf-screen-capture"):
            _ = load_patch("nonexistent-patch")

    def test_path_looking_name_gets_path_specific_error(
        self,
        tmp_path: Path,
    ) -> None:
        # A user passing ``--patch ./typo.toml`` should see a path-not-found
        # error, not a catalog-not-found error that misleads them about
        # the problem.
        bad_path = tmp_path / "nonexistent.toml"
        with pytest.raises(ValueError, match="patch file not found"):
            _ = load_patch(bad_path)

    def test_path_with_separator_nonexistent_gets_path_specific_error(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="patch file not found"):
            _ = load_patch("./not/a/real/file")

    def test_directory_not_treated_as_path(self, tmp_path: Path) -> None:
        # A directory at the named path is not a file → resolution falls
        # through to catalog lookup. Since the catalog has no entry
        # named ``str(tmp_path)`` (and tmp_path contains a separator),
        # the path-looking branch fires first.
        with pytest.raises(ValueError, match="patch file not found"):
            _ = load_patch(tmp_path)


class TestPatchDuplicateOffsets:
    """Two ``ByteChange`` entries with the same offset are rejected.

    They would otherwise silently bypass the first ``expect`` check at the
    engine level (dict-by-offset dedup), so construction rejects them and the
    catalog can't ship one.
    """

    def test_two_changes_same_offset_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate offset"):
            _ = Patch(
                name="x",
                description="d",
                target_firmware=None,
                changes=(
                    ByteChange(0x10444, 0x1B, 0x33),
                    ByteChange(0x10444, 0x33, 0x77),  # same offset
                ),
            )

    def test_three_changes_two_distinct_offsets_rejected(self) -> None:
        # The error message names every duplicated offset.
        with pytest.raises(ValueError, match=r"0x10444"):
            _ = Patch(
                name="x",
                description="d",
                target_firmware=None,
                changes=(
                    ByteChange(0x10444, 0x1B, 0x33),
                    ByteChange(0x10500, 0x00, 0x01),
                    ByteChange(0x10444, 0x99, 0xAA),
                ),
            )


class TestPatchWhitespaceFields:
    """``Patch`` rejects whitespace-only ``name``/``description``.

    A naked truthy check accepts e.g. ``"   "``, which would surface as a
    blank line in ``thd75-list-patches`` output.
    """

    def test_whitespace_only_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="name must be non-empty"):
            _ = Patch(
                name="   ",
                description="d",
                target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
            )

    def test_whitespace_only_description_rejected(self) -> None:
        with pytest.raises(ValueError, match="description must be non-empty"):
            _ = Patch(
                name="x",
                description="\n\t",
                target_firmware=None,
                changes=(ByteChange(0, 0, 1),),
            )

    def test_empty_target_firmware_rejected(self) -> None:
        # ``target_firmware = ""`` in TOML is almost certainly a typo;
        # ``target_firmware = None`` (i.e. omitting the field) is the
        # explicit way to declare "unspecified".
        with pytest.raises(ValueError, match=r"target_firmware.*non-empty"):
            _ = Patch(
                name="x",
                description="d",
                target_firmware="",
                changes=(ByteChange(0, 0, 1),),
            )


class TestParsePatchTomlLevelValidation:
    """TOML-level rejection paths — the user-visible failure surface.

    These cover hand-written patch files. Tests pin the error messages so a
    refactor cannot quietly soften them.
    """

    def test_empty_toml_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing required field 'name'"):
            _ = parse_patch("")

    def test_changes_not_a_list_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"
changes     = 42
"""
        with pytest.raises(ValueError, match="must be a TOML array"):
            _ = parse_patch(toml)

    def test_empty_changes_list_rejected(self) -> None:
        toml = """
name        = "x"
description = "d"
changes     = []
"""
        with pytest.raises(ValueError, match="at least one change"):
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)

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
            _ = parse_patch(toml)


class TestCatalogContents:
    """Every catalog patch must parse and carry the minimum metadata.

    A user needs name, description and at least one change. Defends against
    shipping a broken .toml file in the catalog directory.
    """

    def test_every_catalog_patch_parses_with_required_fields(self) -> None:
        patches = list(iter_catalog())
        assert patches, "catalog should not be empty"
        for entry in patches:
            assert entry.name, f"catalog patch missing name: {entry}"
            assert entry.description, f"catalog patch missing description: {entry.name}"
            assert entry.changes, f"catalog patch has no changes: {entry.name}"


class TestNormalGmDdrReadPins:
    """The `normal-gm-ddr-read` patch turns the normal-mode `GM` into a reader.

    It makes the command a live memory reader. It is a modified-main patch, so
    its manifest carries hashes for every emitted artifact. These tests are the
    drift detector: they fail if the change list, the catalog, or the emitting
    pipeline moves without the pins being re-derived from a re-verified image.
    """

    PATCH_NAME = "normal-gm-ddr-read"

    def _patch(self) -> Patch:
        return load_patch(self.PATCH_NAME)

    def test_declares_every_artifact_hash(self) -> None:
        entry = self._patch()
        assert entry.source_sha256, "source image must be pinned"
        assert entry.result_sha256, "patched image must be pinned"
        assert entry.result_kex_sha256, "rendered KEX must be pinned"
        assert entry.source_updater_sha256, "source updater must be pinned"
        assert entry.result_encrypted_resource_sha256, "resource must be pinned"
        assert entry.result_updater_sha256, "repacked updater must be pinned"

    def test_change_count_matches_declared(self) -> None:
        entry = self._patch()
        assert entry.change_count == 31
        assert len(entry.changes) == 31

    def test_targets_the_three_expected_regions(self) -> None:
        """Check the three edit regions: bound, read block and GM handler adapter.

        Any offset outside the accepted-window bound, the read block, or the
        existing GM handler adapter means the patch has grown scope and must be
        re-reviewed rather than re-pinned.
        """
        entry = self._patch()
        bound = {0x6F85C, 0x6F85E, 0x6F85F}
        read_block = set(range(0x6F8A0, 0x6F8B0))
        gm_adapter = {
            0x2EC00,
            0x2EC02,
            *range(0x2EC04, 0x2EC0E),
        }
        allowed = bound | read_block | gm_adapter
        offsets = {change.offset for change in entry.changes}
        assert offsets == allowed

    def test_leaves_the_dispatch_entry_alone(self) -> None:
        """Leave the stock handler word, mnemonic and padding untouched.

        The adapter lives at the handler address the table already names.
        """
        entry = self._patch()
        table_entry = set(range(0x2E2C8, 0x2E2D0))
        offsets = {change.offset for change in entry.changes}
        assert not (offsets & table_entry)

    def test_leaves_checkbytes_and_final_zzz_alone(self) -> None:
        """Leave FINAL_ZZZ and CHECKBYTES at flash 0x00200040-0x0020007F alone.

        The updater stamps them after the main write; touching them is a
        brick risk.
        """
        entry = self._patch()
        reserved = set(range(0x40, 0x80))
        offsets = {change.offset for change in entry.changes}
        assert not (offsets & reserved)

    def test_retargets_the_read_base_to_ddr(self) -> None:
        """Retarget the read base to DDR (0xC0000000), not NOR.

        The first two changes of the read block build the base address as
        `movs r6,#0xC0 ; lsls r6,r6,#24`, which is 0xC0000000. A value of 0x60
        there would read NOR instead, which is a different patch.
        """
        entry = self._patch()
        by_offset = {change.offset: change.value for change in entry.changes}
        assert by_offset[0x6F8A0] == 0xC0, "base must be DDR, not NOR"
        assert by_offset[0x6F8A1] == 0x26
        assert by_offset[0x6F8A2] == 0x36
        assert by_offset[0x6F8A3] == 0x06

    def test_installs_status_two_adapter(self) -> None:
        """Install the exact ARMv5 Thumb adapter that stores status two.

        The adapter retains R2, calls 9R, stores status two, and returns.
        Reconstruct the complete window from stock plus the byte-oriented
        manifest so omitted same-value bytes are checked too.
        """
        entry = self._patch()
        by_offset = {change.offset: change.value for change in entry.changes}
        stock = bytearray.fromhex("70 B5 06 00 0D 00 14 00 FB F7 52 FF 01 00")
        for offset, value in by_offset.items():
            if 0x2EC00 <= offset < 0x2EC0E:
                stock[offset - 0x2EC00] = value
        assert bytes(stock) == bytes.fromhex(
            "10 B5 14 00 40 F0 0F FE 02 20 20 70 10 BD"
        )

    def test_pins_both_gm_dispatch_entries_and_9r_return(self) -> None:
        entry = self._patch()
        contexts = {context.offset: context.expect for context in entry.contexts}
        assert contexts[0x2E2C8] == bytes.fromhex("01 EC 02 C0 47 4D 00 00")
        assert contexts[0x6F370][4:12] == bytes.fromhex("01 EC 02 C0 47 4D 00 00")
        assert contexts[0x6F826].startswith(bytes.fromhex("70 B5 C2 B0"))
        assert contexts[0x6F8BC].endswith(bytes.fromhex("42 B0 70 BD"))


class TestNormalGmNorReadPins:
    """The NOR reader is exactly the reviewed DDR patch with one base byte."""

    def test_pins_every_artifact_and_exact_change_count(self) -> None:
        entry = load_patch("normal-gm-nor-read")

        assert entry.source_sha256 == (
            "193963ca4b7a38392815686893858eec20292b629fe999f10b93a22a3a8e4001"
        )
        assert entry.result_sha256 == (
            "2eddf487e985861c95fb4212d0f7eabfb57c648eee06f3141819582226fd6ea0"
        )
        assert entry.result_kex_sha256 == (
            "f619fbb6b6fd91ad5bcdaf85bcc3bcd31483564fc5a5643aad73ce5915f5f30e"
        )
        assert entry.source_updater_sha256 == (
            "a76f0c80525c942c983bd62494109e15270380a6b5964d6c2a6b4726331f60ad"
        )
        assert entry.result_encrypted_resource_sha256 == (
            "ff65c725b7f669ec829d85c2800c3e4317aac2dd4e7e71066a130991e919fdcd"
        )
        assert entry.result_updater_sha256 == (
            "c14e68f6e70c31cc29761cbb70983becddb792899dfc17679c2778cf2a255544"
        )
        assert entry.change_count == len(entry.changes) == 31

    def test_exactly_matches_ddr_manifest_except_base_immediate(self) -> None:
        ddr = load_patch("normal-gm-ddr-read")
        nor = load_patch("normal-gm-nor-read")

        assert nor.target_firmware == ddr.target_firmware
        assert nor.source_sha256 == ddr.source_sha256
        assert nor.source_updater_sha256 == ddr.source_updater_sha256
        assert nor.contexts == ddr.contexts
        assert len(nor.changes) == len(ddr.changes) == 31

        ddr_changes = {
            change.offset: (change.expect, change.value) for change in ddr.changes
        }
        nor_changes = {
            change.offset: (change.expect, change.value) for change in nor.changes
        }
        assert set(nor_changes) == set(ddr_changes)
        differing_changes = {
            offset: (ddr_changes[offset], nor_changes[offset])
            for offset in ddr_changes
            if ddr_changes[offset] != nor_changes[offset]
        }
        assert differing_changes == {
            0x6F8A0: ((0x02, 0xC0), (0x02, 0x60)),
        }


class TestNormalGmNorReadUsbRecoverPins:
    """The production USB handoff is one exact fail-closed GM-NOR variant."""

    @staticmethod
    def _patched_window(
        entry: Patch,
        *,
        start: int,
        end: int,
    ) -> bytes:
        context = next(
            context
            for context in entry.contexts
            if context.offset <= start and end <= context.offset + len(context.expect)
        )
        source = bytearray(context.expect)
        context_end = context.offset + len(source)
        assert context.offset <= start <= end <= context_end
        for change in entry.changes:
            if context.offset <= change.offset < context_end:
                index = change.offset - context.offset
                assert source[index] == change.expect
                source[index] = change.value
        return bytes(source[start - context.offset : end - context.offset])

    def test_pins_direct_source_and_every_result(self) -> None:
        entry = load_patch("normal-gm-nor-read-usb-recover")

        assert entry.target_firmware == ("TH-D75 V1.03 normal-gm-nor-read FIRMWARE")
        assert entry.source_sha256 == (
            "2eddf487e985861c95fb4212d0f7eabfb57c648eee06f3141819582226fd6ea0"
        )
        assert entry.result_sha256 == (
            "239128bca8f608398dc23865c336bd48a00484ea598202a000fd9f5647aa92a6"
        )
        assert entry.result_kex_sha256 == (
            "257a93cbefb843c61676e5ca61e03ce4bc72b071658c936757f89477f1fa792a"
        )
        assert entry.source_updater_sha256 == (
            "c14e68f6e70c31cc29761cbb70983becddb792899dfc17679c2778cf2a255544"
        )
        assert entry.result_encrypted_resource_sha256 == (
            "07731912d6cd20d75b3b92b89df1ff281a76a71735c5d1d93057ad9b7580c0de"
        )
        assert entry.result_updater_sha256 == (
            "28e9ae17ab85e7831d04bb7a520e9e735081ea78c22e64e57daafa50f7bce23d"
        )
        assert entry.change_count == len(entry.changes) == 3027

    def test_changes_are_confined_to_the_32_audited_linker_sections(self) -> None:
        entry = load_patch("normal-gm-nor-read-usb-recover")
        offsets = {change.offset for change in entry.changes}
        section_bounds = (
            (0x2EC0E, 0x2EC4E),
            (0x2F368, 0x2F36A),
            (0x2F36A, 0x2F3A4),
            (0x2F6E8, 0x2F6EC),
            (0x6F8A0, 0x6F8A2),
            (0x8D830, 0x8D858),
            (0x8D9F8, 0x8D9FE),
            (0xD95CE, 0xD95D6),
            (0xFE5AA, 0xFE5AE),
            (0xFE5CA, 0xFE5CE),
            (0xFE60E, 0xFE612),
            (0xFE62E, 0xFE632),
            (0x101178, 0x10117A),
            (0x1011E8, 0x1011EC),
            (0x101D5A, 0x101D5E),
            (0x101ECC, 0x101ED0),
            (0x171B56, 0x171B5A),
            (0x171B5C, 0x171B5E),
            (0x171DFA, 0x171DFE),
            (0x17205A, 0x17205E),
            (0x1720A4, 0x1720A8),
            (0x17D910, 0x17D918),
            (0x17D956, 0x17D95A),
            (0x17D992, 0x17D996),
            (0x17D99E, 0x17D9A6),
            (0x19C360, 0x19C390),
            (0x19C390, 0x19C67C),
            (0x19C67C, 0x19C700),
            (0x19C700, 0x19C860),
            (0x19C860, 0x19CA00),
            (0x19CA00, 0x19CB00),
            (0x19CB00, 0x19D000),
        )

        assert all(
            any(start <= offset < end for start, end in section_bounds)
            for offset in offsets
        )
        assert {
            0x2F368,
            0x2F369,
            0x6F8A0,
            0xFE5AA,
            0xFE5CA,
            0x101178,
            0x101D5A,
            0x101ECC,
            0x17205A,
            0x19C360,
            0x19CF9F,
        } <= offsets
        assert not (offsets & set(range(0x40, 0x80)))
        assert not (offsets & set(range(0x19D000, 0x19D280)))
        assert not (offsets & set(range(0x2F3A4, 0x2F3A8)))
        cave_changes = [
            change for change in entry.changes if 0x19C360 <= change.offset < 0x19D000
        ]
        assert cave_changes
        assert all(change.expect == 0xFF for change in cave_changes)

    def test_exact_trigger_helper_and_usb_state_literal(self) -> None:
        entry = load_patch("normal-gm-nor-read-usb-recover")

        assert self._patched_window(
            entry,
            start=0x2EC0E,
            end=0x2EC4E,
        ) == bytes.fromhex(
            "38 B5 15 00 02 24 05 29 0B D1 83 78 20 2B 08 D1 "
            "C3 78 32 2B 05 D1 03 79 0D 2B 02 D1 02 20 20 F0 "
            "14 FD 2C 70 31 BD 00 2A 04 D1 02 21 08 B5 74 F0 "
            "34 F9 08 BD 70 47 5F 20 5E F0 07 FE 32 BD C0 46"
        )
        assert self._patched_window(
            entry,
            start=0x2F368,
            end=0x2F3A4,
        ) == bytes.fromhex(
            "51 E4 38 B5 DE 4C 20 78 FF 3C 35 3C 61 79 02 39 "
            "06 D0 02 29 0F D0 02 D8 01 38 0C D0 03 D3 5D E4 "
            "00 28 08 D1 20 71 5F 20 6D F1 74 FA 02 E0 C0 46 "
            "C0 46 C0 46 32 BD 01 20 FC E7 C0 46"
        )
        assert self._patched_window(
            entry,
            start=0x2F6E8,
            end=0x2F6EC,
        ) == bytes.fromhex("68 5C 3E C2")
        assert self._patched_window(
            entry,
            start=0x6F8A0,
            end=0x6F8A2,
        ) == bytes.fromhex("C0 26")

    def test_exact_handoff_and_cmd17_call_sites(self) -> None:
        entry = load_patch("normal-gm-nor-read-usb-recover")

        assert self._patched_window(
            entry,
            start=0x8D830,
            end=0x8D858,
        ) == bytes.fromhex(
            "38 B5 25 4C 01 F0 D0 FB 05 00 43 F0 BE FF 05 43 "
            "02 D0 04 20 01 25 01 E0 03 20 00 25 60 71 0F F1 "
            "2F F8 28 00 32 BD C0 46"
        )
        assert self._patched_window(
            entry,
            start=0x8D9F8,
            end=0x8D9FE,
        ) == bytes.fromhex("28 88 A1 F7 B6 FC")
        assert self._patched_window(
            entry,
            start=0x101178,
            end=0x10117A,
        ) == bytes.fromhex("C0 46")
        assert self._patched_window(
            entry,
            start=0x17D910,
            end=0x17D918,
        ) == bytes.fromhex("02 7B 09 20 B1 F6 8E F9")
        exact_sites = {
            (0xFE5AA, 0xFE5AE): "9D F0 C2 FF",
            (0xFE5CA, 0xFE5CE): "9D F0 E6 FF",
            (0x101D5A, 0x101D5E): "9A F0 1F FD",
            (0x101ECC, 0x101ED0): "9A F0 70 FC",
            (0x171DFA, 0x171DFE): "2A F0 81 FC",
            (0x17205A, 0x17205E): "2A F0 0D FD",
            (0x1720A4, 0x1720A8): "2A F0 90 FA",
        }
        for (start, end), expected in exact_sites.items():
            assert self._patched_window(entry, start=start, end=end) == bytes.fromhex(
                expected
            )


class TestAzimuthPins:
    """Azimuth pins ABI-3 automation to one exact V1.03 source hash."""

    PATCH_NAME = "normal-gm-nor-read-usb-recover-azimuth"
    RUNTIME_START = 0x19D280
    RUNTIME_END = RUNTIME_START + 1300

    @staticmethod
    def _patched_window(
        entry: Patch,
        *,
        start: int,
        end: int,
    ) -> bytes:
        context = next(
            context
            for context in entry.contexts
            if context.offset <= start and end <= context.offset + len(context.expect)
        )
        result = bytearray(context.expect)
        for change in entry.changes:
            if context.offset <= change.offset < context.offset + len(result):
                result[change.offset - context.offset] = change.value
        return bytes(result[start - context.offset : end - context.offset])

    def test_pins_exact_source_and_every_result(self) -> None:
        entry = load_patch(self.PATCH_NAME)

        assert entry.source_sha256 == (
            "239128bca8f608398dc23865c336bd48a00484ea598202a000fd9f5647aa92a6"
        )
        assert entry.result_sha256 == (
            "e4ee2338b0483acfc4fea2d7cb7805aacf1fdfe2102b2f2252d19e750dfc1c29"
        )
        assert entry.result_kex_sha256 == (
            "6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d"
        )
        assert entry.source_updater_sha256 == (
            "28e9ae17ab85e7831d04bb7a520e9e735081ea78c22e64e57daafa50f7bce23d"
        )
        assert entry.result_encrypted_resource_sha256 == (
            "3f867a3e00b5f4b24bc6e2ffef117f7a6845e0e1c73aabf2a1b2fe7b1738cb36"
        )
        assert entry.result_updater_sha256 == (
            "14353287f3d56b1829b00f6d0877e5f0915440ba2657f9fa886ed64d05d7a2e4"
        )
        assert entry.change_count == len(entry.changes) == 1267

    def test_changes_remain_confined_to_two_hooks_and_ff_runtime_cave(self) -> None:
        entry = load_patch(self.PATCH_NAME)
        offsets = {change.offset for change in entry.changes}
        hooks = set(range(0x2EC04, 0x2EC08)) | set(range(0x6F8AC, 0x6F8B0))
        firmware_identity = set(range(0xA6, 0xA9))

        assert hooks | firmware_identity <= offsets
        assert all(
            offset in hooks
            or offset in firmware_identity
            or self.RUNTIME_START <= offset < self.RUNTIME_END
            for offset in offsets
        )
        runtime = [
            change
            for change in entry.changes
            if self.RUNTIME_START <= change.offset < self.RUNTIME_END
        ]
        assert runtime
        assert all(change.expect == 0xFF for change in runtime)

    def test_exact_hooks_abi_and_runtime_digest(self) -> None:
        entry = load_patch(self.PATCH_NAME)

        assert self._patched_window(entry, start=0xA0, end=0xB0) == (
            b"V1.03.AZM      \0"
        )
        assert self._patched_window(entry, start=0x2EC00, end=0x2EC0E) == bytes.fromhex(
            "10 B5 14 00 6E F1 3C FB 02 20 20 70 10 BD"
        )
        assert self._patched_window(entry, start=0x6F8A0, end=0x6F8B0) == bytes.fromhex(
            "C0 26 36 06 01 99 89 19 02 A8 00 9A 2D F1 1F FF"
        )
        runtime = self._patched_window(
            entry,
            start=self.RUNTIME_START,
            end=self.RUNTIME_END,
        )
        assert runtime[0x150:0x158] == bytes.fromhex("44 37 35 41 03 7F 18 02")
        assert hashlib.sha256(runtime).hexdigest() == (
            "3be7e8a35e43e6eb773f9f11a709063a353783688bbc4bf0962f872d72523f71"
        )


_IMAGE_DATA_DIGEST = hashlib.sha256(b"image-data").hexdigest()


class TestSectionField:
    """Changes and contexts name the section they patch; FIRMWARE is the default."""

    def test_default_section_is_firmware(self) -> None:
        assert ByteChange(offset=1, expect=0, value=1).section == FIRMWARE_SECTION
        assert ByteContext(offset=1, expect=b"\x00").section == FIRMWARE_SECTION

    def test_image_data_section_accepted(self) -> None:
        change = ByteChange(
            offset=0x56F10, expect=0x00, value=0x60, section="IMAGE_DATA"
        )
        assert change.section == "IMAGE_DATA"

    def test_unknown_section_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown section 'BOGUS'"):
            _ = ByteChange(offset=1, expect=0, value=1, section="BOGUS")
        with pytest.raises(ValueError, match="unknown section 'BOGUS'"):
            _ = ByteContext(offset=1, expect=b"\x00", section="BOGUS")

    def test_same_offset_in_two_sections_is_not_a_duplicate(self) -> None:
        patch_obj = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(
                ByteChange(offset=4, expect=0, value=1),
                ByteChange(offset=4, expect=0, value=1, section="IMAGE_DATA"),
            ),
        )
        assert patch_obj.touched_sections == ("FIRMWARE", "IMAGE_DATA")

    def test_duplicate_offset_within_image_data_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate offset"):
            _ = Patch(
                name="p",
                description="d",
                target_firmware=None,
                changes=(
                    ByteChange(offset=4, expect=0, value=1, section="IMAGE_DATA"),
                    ByteChange(offset=4, expect=0, value=2, section="IMAGE_DATA"),
                ),
            )


class TestSectionHashes:
    """Per-section whole-image pins live beside the FIRMWARE pins."""

    def test_requires_at_least_one_digest(self) -> None:
        with pytest.raises(ValueError, match="pins neither source"):
            _ = SectionHashes(section="IMAGE_DATA")

    def test_rejects_firmware_section(self) -> None:
        with pytest.raises(ValueError, match="belong in source_sha256"):
            _ = Patch(
                name="p",
                description="d",
                target_firmware=None,
                changes=(ByteChange(offset=0, expect=0, value=1),),
                section_hashes=(
                    SectionHashes(section="FIRMWARE", source_sha256=_IMAGE_DATA_DIGEST),
                ),
            )

    def test_verify_source_checks_the_named_section(self) -> None:
        patch_obj = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(ByteChange(offset=0, expect=0, value=1, section="IMAGE_DATA"),),
            contexts=(ByteContext(offset=0, expect=b"im", section="IMAGE_DATA"),),
            section_hashes=(
                SectionHashes(section="IMAGE_DATA", source_sha256=_IMAGE_DATA_DIGEST),
            ),
        )
        patch_obj.verify_source(b"image-data", "IMAGE_DATA")
        with pytest.raises(PatchIntegrityError, match="source IMAGE_DATA SHA-256"):
            patch_obj.verify_source(b"im-other", "IMAGE_DATA")
        # FIRMWARE has no pins and no FIRMWARE contexts: anything passes.
        patch_obj.verify_source(b"whatever")

    def test_firmware_contexts_ignored_for_other_sections(self) -> None:
        patch_obj = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(ByteChange(offset=0, expect=0, value=1),),
            contexts=(ByteContext(offset=0, expect=b"fw"),),
        )
        patch_obj.verify_source(b"anything", "IMAGE_DATA")
        with pytest.raises(PatchIntegrityError, match="source context mismatch"):
            patch_obj.verify_source(b"xx")

    def test_verify_result_uses_section_result_pin(self) -> None:
        patch_obj = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(ByteChange(offset=0, expect=0, value=1, section="IMAGE_DATA"),),
            section_hashes=(
                SectionHashes(section="IMAGE_DATA", result_sha256=_IMAGE_DATA_DIGEST),
            ),
        )
        patch_obj.verify_result(b"image-data", "IMAGE_DATA")
        with pytest.raises(PatchIntegrityError, match="patched IMAGE_DATA SHA-256"):
            patch_obj.verify_result(b"nope", "IMAGE_DATA")


_RUN_TOML = """
name = "runs"
description = "run form"
change_count = 2

[sections.IMAGE_DATA]
source_sha256 = "{digest}"

[[contexts]]
section = "IMAGE_DATA"
offset = 0x10
expect = "AA BB"

[[changes]]
section = "IMAGE_DATA"
offset = 0x20
expect = "00 11 22 33"
value  = "00 99 22 77"

[[changes]]
offset = 0x5
expect = 0x1B
value = 0x33
"""


class TestExpandRun:
    def test_only_differing_bytes_become_changes(self) -> None:
        changes, context = expand_run(
            "IMAGE_DATA", 0x20, b"\x00\x11\x22\x33", b"\x00\x99\x22\x77"
        )
        assert changes == (
            ByteChange(offset=0x21, expect=0x11, value=0x99, section="IMAGE_DATA"),
            ByteChange(offset=0x23, expect=0x33, value=0x77, section="IMAGE_DATA"),
        )
        assert context == ByteContext(
            offset=0x20, expect=b"\x00\x11\x22\x33", section="IMAGE_DATA"
        )

    def test_length_mismatch_rejected(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            _ = expand_run("FIRMWARE", 0, b"\x00\x01", b"\x00")

    def test_run_without_a_change_rejected(self) -> None:
        with pytest.raises(ValueError, match="changes no byte"):
            _ = expand_run("FIRMWARE", 0, b"\x00\x01", b"\x00\x01")

    def test_empty_run_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            _ = expand_run("FIRMWARE", 0, b"", b"")


class TestParseSectionsAndRuns:
    def test_run_form_expands_and_pins(self) -> None:
        digest = hashlib.sha256(b"image").hexdigest()
        toml_text = _RUN_TOML.replace("{digest}", digest).replace(
            "change_count = 2", "change_count = 3"
        )
        parsed = parse_patch(toml_text)
        assert parsed.changes == (
            ByteChange(offset=0x21, expect=0x11, value=0x99, section="IMAGE_DATA"),
            ByteChange(offset=0x23, expect=0x33, value=0x77, section="IMAGE_DATA"),
            ByteChange(offset=0x5, expect=0x1B, value=0x33),
        )
        assert parsed.contexts == (
            ByteContext(offset=0x10, expect=b"\xaa\xbb", section="IMAGE_DATA"),
            ByteContext(offset=0x20, expect=b"\x00\x11\x22\x33", section="IMAGE_DATA"),
        )
        assert parsed.section_hashes == (
            SectionHashes(section="IMAGE_DATA", source_sha256=digest),
        )
        assert parsed.touched_sections == ("FIRMWARE", "IMAGE_DATA")

    def test_top_level_firmware_pins_name_firmware(self) -> None:
        change = ByteChange(0, 0xFF, 0x00, section="IMAGE_DATA")
        unpinned = Patch(
            name="image-only",
            description="d",
            target_firmware=None,
            changes=(change,),
        )
        pinned = Patch(
            name="image-only",
            description="d",
            target_firmware=None,
            changes=(change,),
            result_sha256="0" * 64,
        )
        assert unpinned.touched_sections == ("IMAGE_DATA",)
        assert pinned.touched_sections == ("FIRMWARE", "IMAGE_DATA")

    def test_change_count_counts_expanded_bytes(self) -> None:
        digest = hashlib.sha256(b"image").hexdigest()
        with pytest.raises(ValueError, match="change_count declares 2"):
            _ = parse_patch(_RUN_TOML.replace("{digest}", digest))

    def test_mixed_int_and_string_rejected(self) -> None:
        toml_text = (
            'name = "x"\ndescription = "y"\n'
            '[[changes]]\noffset = 0\nexpect = "00"\nvalue = 1\n'
        )
        with pytest.raises(ValueError, match="both hex strings or both integers"):
            _ = parse_patch(toml_text)

    def test_bad_hex_rejected(self) -> None:
        toml_text = (
            'name = "x"\ndescription = "y"\n'
            '[[changes]]\noffset = 0\nexpect = "zz"\nvalue = "00"\n'
        )
        with pytest.raises(ValueError, match="hexadecimal"):
            _ = parse_patch(toml_text)

    def test_sections_table_rejects_firmware_and_unknown_keys(self) -> None:
        digest = hashlib.sha256(b"image").hexdigest()
        base = 'name = "x"\ndescription = "y"\n[[changes]]\noffset = 0\nexpect = 0\nvalue = 1\n'
        with pytest.raises(ValueError, match="belong in source_sha256"):
            _ = parse_patch(base + f'[sections.FIRMWARE]\nsource_sha256 = "{digest}"\n')
        with pytest.raises(ValueError, match="unknown field"):
            _ = parse_patch(base + f'[sections.IMAGE_DATA]\nsource = "{digest}"\n')
        with pytest.raises(ValueError, match="unknown section"):
            _ = parse_patch(base + f'[sections.BOGUS]\nsource_sha256 = "{digest}"\n')

    def test_context_section_field(self) -> None:
        toml_text = (
            'name = "x"\ndescription = "y"\n'
            '[[contexts]]\nsection = "IMAGE_DATA"\noffset = 4\nexpect = "01"\n'
            "[[changes]]\noffset = 0\nexpect = 0\nvalue = 1\n"
        )
        parsed = parse_patch(toml_text)
        assert parsed.contexts[0].section == "IMAGE_DATA"

    def test_every_catalog_patch_names_its_sections(self) -> None:
        for entry in iter_catalog():
            if entry.name == "orange-on-black":
                assert entry.touched_sections == ("FIRMWARE", "IMAGE_DATA")
            else:
                assert entry.touched_sections == ("FIRMWARE",), entry.name

    @given(
        expect=st.binary(min_size=1, max_size=24),
        flips=st.lists(st.integers(min_value=0, max_value=23), min_size=1, max_size=6),
    )
    def test_expanded_changes_rebuild_the_value_window(
        self, expect: bytes, flips: list[int]
    ) -> None:
        value = bytearray(expect)
        for position in flips:
            index = position % len(expect)
            value[index] ^= 0x5A
        if bytes(value) == expect:
            return
        changes, context = expand_run("IMAGE_DATA", 0x100, expect, bytes(value))
        rebuilt = bytearray(expect)
        for change in changes:
            assert rebuilt[change.offset - 0x100] == change.expect
            rebuilt[change.offset - 0x100] = change.value
        assert bytes(rebuilt) == bytes(value)
        assert context.expect == expect


class TestSectionVersion:
    """``[sections.<NAME>] version`` assigns the block a new ``$VA`` string."""

    def test_version_alone_is_a_valid_section_entry(self) -> None:
        pins = SectionHashes(section="IMAGE_DATA", version="1.00.02.01")
        assert pins.version == "1.00.02.01"
        patch_obj = Patch(
            name="p",
            description="d",
            target_firmware=None,
            changes=(ByteChange(offset=0, expect=0, value=1, section="IMAGE_DATA"),),
            section_hashes=(pins,),
        )
        assert patch_obj.version_for("IMAGE_DATA") == "1.00.02.01"
        assert patch_obj.version_for("FIRMWARE") is None

    def test_blank_version_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            _ = SectionHashes(section="IMAGE_DATA", version="  ")

    def test_version_parsed_from_toml(self) -> None:
        toml_text = (
            'name = "x"\ndescription = "y"\n'
            '[sections.IMAGE_DATA]\nversion = "1.00.02.01"\n'
            '[[changes]]\nsection = "IMAGE_DATA"\noffset = 0\nexpect = 0\nvalue = 1\n'
        )
        parsed = parse_patch(toml_text)
        assert parsed.section_hashes == (
            SectionHashes(section="IMAGE_DATA", version="1.00.02.01"),
        )

    def test_non_string_version_rejected(self) -> None:
        toml_text = (
            'name = "x"\ndescription = "y"\n'
            "[sections.IMAGE_DATA]\nversion = 1\n"
            '[[changes]]\nsection = "IMAGE_DATA"\noffset = 0\nexpect = 0\nvalue = 1\n'
        )
        with pytest.raises(ValueError, match="version must be a string"):
            _ = parse_patch(toml_text)
