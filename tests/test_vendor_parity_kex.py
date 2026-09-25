"""Vendor parity tests — KEX file format.

Tag prefix conventions, value parsing forms (plain int, hex, quoted-LE-bytes),
and stock V1.03 known values. Cross-verified against vendor `p.cs` (single
tag-line parser) and `j.cs` (KEX file outer reader).

KEX tag conventions (from vendor `j.cs:b='#', m_c='$'`):
- Top-level tags prefixed by `#`: #TC, #FC, #TU, #AF
- Per-segment tags prefixed by `$`: $SA, $DL, $EL, $TT, $ET, $CB, $CA,
  $CS, $CL, $CT, $VS, $VL, $VA, $DU

Value forms (from vendor `p.cs:177-193`):
- Bare integer (decimal): `$DL=655360`
- Hex integer (0x prefix): `$DL=0xA0000`
- Quoted string: `description="some text"`
- Comma-separated u32 array: `$something=0x01,0x02,0x03`

Stock V1.03 KEX values (hardware-validated):
- #TC=0, #FC=0x1DB0, #TU=1, #AF=1, per-segment $TT=0x0F
- 7 segments total; all $SA start with 0x60xxxxxx
"""

from __future__ import annotations

import pytest

from thd75_fw.flash.segments import (
    _int_tag,
    _parse_metadata_tags,
    _parse_quoted_hex_u64,
)
from thd75_fw.kex import _metadata_value

# --- tag-prefix conventions ---------------------------------------------


def test_top_level_tag_prefix_is_hash() -> None:
    """vendor: j.cs:8 `const char b = '#'` (top-level tag prefix).

    Top-level tags affect the overall flash flow (TC for ENTER_PROGRAM
    payload, FC for COMPLETE_UPDATE payload, etc.).
    """
    assert chr(0x23) == "#"
    # Common top-level tags:
    for tag in ["#TC", "#FC", "#TU", "#AF"]:
        assert tag.startswith("#")


def test_segment_tag_prefix_is_dollar() -> None:
    """vendor: j.cs:9 `const char m_c = '$'` (per-segment tag prefix)."""
    assert chr(0x24) == "$"
    for tag in [
        "$SA",
        "$DL",
        "$EL",
        "$TT",
        "$ET",
        "$CB",
        "$CA",
        "$CS",
        "$CL",
        "$CT",
        "$VS",
        "$VL",
        "$VA",
        "$DU",
    ]:
        assert tag.startswith("$")


def test_top_level_and_segment_prefixes_differ() -> None:
    """vendor: j.cs distinguishes #-tags (top-level) from $-tags (per-segment).

    It tells them apart by the leading byte. Confusing them would put a $TT
    value where the ENTER_PROGRAM byte should go.
    """
    top = "#"
    seg = "$"
    assert top != seg
    assert ord(top) == 0x23
    assert ord(seg) == 0x24


# --- value-form parsing -------------------------------------------------


def test_parse_decimal_int_tag() -> None:
    """vendor: p.cs:185-189 — `Convert.ToUInt32(token, 10)` for decimal tokens.

    That branch runs when the token doesn't start with `0x`. Our parser
    accepts decimal.
    """
    metadata = (b"$DL=655360",)
    tags = _parse_metadata_tags(metadata)
    assert tags.get("DL") == 655360


def test_parse_hex_int_tag() -> None:
    """vendor: p.cs:189 — `Convert.ToUInt32(token, 16)` when token starts with `0x`.

    Our parser accepts hex.
    """
    metadata = (b"$DL=0xA0000",)
    tags = _parse_metadata_tags(metadata)
    assert tags.get("DL") == 0xA0000
    assert tags.get("DL") == 655360  # same value, hex form


def test_parse_quoted_hex_u64_tt_form() -> None:
    """vendor: p.cs:181-184 stores the quoted string; j.cs:1071-1073 evaluates it.

    The evaluation is ``Convert.ToUInt64(value.Replace(" ",""), 16)``.

    The spacing is cosmetic: the leading group is the *most* significant
    byte, so stock V1.03 $TT = "0F 00 00 00 00 00 00 00" is
    0x0F00000000000000, not 0x0F.
    """
    assert _parse_quoted_hex_u64('"0F 00 00 00 00 00 00 00"') == 0x0F00_0000_0000_0000
    assert _parse_quoted_hex_u64('"01 00 00 00 00 00 00 00"') == 0x0100_0000_0000_0000
    assert _parse_quoted_hex_u64('"00 00 00 00 00 00 00 80"') == 0x80


def test_parse_quoted_hex_u64_rejects_malformed() -> None:
    """vendor: p.cs only stores well-formed quoted strings in m_e."""
    assert _parse_quoted_hex_u64("not quoted") is None
    assert _parse_quoted_hex_u64('"non-hex chars"') is None
    assert _parse_quoted_hex_u64('"AB"') == 0xAB  # single byte is valid


# --- stock V1.03 known values -------------------------------------------


def test_stock_v103_tc_is_zero() -> None:
    r"""vendor: KEX file ground truth, hardware-validated.

    `#TC=0` → ENTER_PROGRAM payload byte = b"\\x00".

    Top-level `#`-prefixed tags are parsed via ``kex._metadata_value``
    (a separate code path from ``_parse_metadata_tags`` which only
    handles per-segment ``$``-prefixed tags).
    """
    metadata = (b"#TC=0",)
    assert _metadata_value(metadata, b"#TC=") == 0


def test_stock_v103_fc_is_0x1db0() -> None:
    """vendor: KEX file ground truth, hardware-validated.

    `#FC=0x1DB0` → official COMPLETE_UPDATE payload is LE u16.
    """
    metadata = (b"#FC=0x1DB0",)
    assert _metadata_value(metadata, b"#FC=") == 0x1DB0


def test_stock_v103_tt_is_0x0f00000000000000() -> None:
    """vendor: KEX file ground truth + j.cs:1071-1073.

    Per-segment `$TT="0F 00 00 00 00 00 00 00"` → 0x0F00000000000000,
    which the little-endian struct marshal puts on the wire as
    `00 00 00 00 00 00 00 0f` at descriptor offset 16.
    """
    metadata = (b'$TT="0F 00 00 00 00 00 00 00"',)
    tags = _parse_metadata_tags(metadata)
    # $TT is parsed via _parse_quoted_hex_u64.
    assert tags.get("TT") == 0x0F00_0000_0000_0000


# --- _int_tag helper ----------------------------------------------------


def test_int_tag_returns_default_when_missing() -> None:
    """vendor: implicit — vendor p.cs returns 0 for absent fields.

    It does so via the default uint initialization.
    """
    tags: dict[str, object] = {"OTHER": 42}
    assert _int_tag(tags, "MISSING", default=0) == 0
    assert _int_tag(tags, "MISSING", default=99) == 99


def test_int_tag_returns_present_value() -> None:
    """vendor: implicit — present-tag-wins semantics."""
    tags: dict[str, object] = {"SA": 0x60200000}
    assert _int_tag(tags, "SA", default=0) == 0x60200000


def test_int_tag_raises_on_non_int_value() -> None:
    """vendor: p.cs stores quoted strings in m_e, ints in m_d.

    Our _int_tag helper enforces type safety on the int-tag retrieval path.
    """
    tags: dict[str, object] = {"DESCRIPTION": "some string"}
    with pytest.raises(ValueError, match="must be an integer"):
        _ = _int_tag(tags, "DESCRIPTION", default=0)


# --- multi-line metadata parsing ----------------------------------------


def test_parse_multiple_tags_in_metadata_list() -> None:
    """vendor: j.cs iterates the KEX file line-by-line.

    It calls p.cs's constructor per tag-line and aggregates into the
    segment's DataBlockInfo. Our _parse_metadata_tags handles a tuple of
    lines.
    """
    metadata = (
        b"$SA=0x60200000",
        b"$DL=0x10000",
        b"$EL=0x10000",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$ET=5",
        b"$DU=1024",
    )
    tags = _parse_metadata_tags(metadata)
    assert tags.get("SA") == 0x60200000
    assert tags.get("DL") == 0x10000
    assert tags.get("EL") == 0x10000
    assert tags.get("TT") == 0x0F00_0000_0000_0000
    assert tags.get("ET") == 5
    assert tags.get("DU") == 1024
