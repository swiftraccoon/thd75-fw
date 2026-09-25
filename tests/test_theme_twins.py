"""Tests for twin detection and scheme-role assignment."""

from __future__ import annotations

import struct

import pytest

from tests.fixtures.png_helpers import PngHeader, build_png
from thd75_fw.theme.twins import (
    UI_TABLE_WINDOW,
    V103_ROLE_OVERRIDES,
    Evidence,
    Role,
    ThemeError,
    TwinGroup,
    assign_roles,
    closest_black_twin,
    collect_evidence,
    find_twin_groups,
)

_PIXELS = bytes([0, 1, 2, 3, 3, 2, 1, 0, 1, 1, 2, 2])
_OTHER = bytes([3, 3, 3, 3, 0, 0, 0, 0, 1, 2, 1, 2])
_INDEXED_4X3 = PngHeader(width=4, height=3, colour_type=3)
_GRAY_4X3 = PngHeader(width=4, height=3, colour_type=0)
_INDEXED_2X2 = PngHeader(width=2, height=2, colour_type=3)
_BLACK_PLTE = [(0, 0, 0), (255, 255, 255), (255, 0, 255), (56, 160, 216)]
_WHITE_PLTE = [(255, 255, 255), (0, 0, 0), (255, 0, 255), (24, 117, 197)]
_SELECTED_PLTE = [(0, 0, 0), (255, 255, 255), (255, 0, 255), (248, 216, 8)]


def _pngs() -> dict[int, bytes]:
    return {
        10: build_png(_INDEXED_4X3, _PIXELS, _BLACK_PLTE),
        20: build_png(_INDEXED_4X3, _PIXELS, _WHITE_PLTE),
        30: build_png(_INDEXED_4X3, _OTHER, _BLACK_PLTE),
        40: build_png(_GRAY_4X3, _PIXELS),  # grayscale: never a twin
        50: build_png(_INDEXED_4X3, _OTHER, _BLACK_PLTE),  # same as 30: not a twin
    }


def _firmware(*words: int, at: int = 0x10) -> bytes:
    data = bytearray(0x40)
    struct.pack_into(f"<{len(words)}H", data, at, *words)
    return bytes(data)


class TestFindTwinGroups:
    def test_groups_pixel_identical_indexed_pngs_with_different_palettes(self) -> None:
        groups = find_twin_groups(_pngs())
        assert groups == (TwinGroup(members=(10, 20), width=4, height=3),)


class TestCollectEvidence:
    def test_pair_table_evidence(self) -> None:
        groups = find_twin_groups(_pngs())
        evidence = collect_evidence(_firmware(10, 20), groups, window=(0, 0x40))
        assert evidence == (Evidence(black=10, white=20, kind="pair", offset=0x10),)

    def test_outside_window_is_ignored(self) -> None:
        groups = find_twin_groups(_pngs())
        assert (
            collect_evidence(_firmware(10, 20, at=0x30), groups, window=(0, 0x20)) == ()
        )
        assert UI_TABLE_WINDOW == (0x15F000, 0x180000)

    def test_descriptor_evidence_needs_every_pair_to_be_twins(self) -> None:
        pngs = {
            10: build_png(_INDEXED_2X2, b"\x00\x01\x02\x03", _BLACK_PLTE),
            20: build_png(_INDEXED_2X2, b"\x00\x01\x02\x03", _WHITE_PLTE),
            11: build_png(_INDEXED_2X2, b"\x03\x02\x01\x00", _BLACK_PLTE),
            21: build_png(_INDEXED_2X2, b"\x03\x02\x01\x00", _WHITE_PLTE),
            12: build_png(_INDEXED_2X2, b"\x01\x01\x02\x02", _BLACK_PLTE),
            22: build_png(_INDEXED_2X2, b"\x01\x01\x02\x02", _WHITE_PLTE),
        }
        groups = find_twin_groups(pngs)
        evidence = collect_evidence(
            _firmware(10, 11, 12, 20, 21, 22), groups, window=(0, 0x40)
        )
        kinds = {(e.black, e.white, e.kind) for e in evidence}
        assert {
            (10, 20, "descriptor3"),
            (11, 21, "descriptor3"),
            (12, 22, "descriptor3"),
        } <= kinds
        # A sequential run of unrelated indices produces no descriptor evidence.
        assert (
            collect_evidence(
                _firmware(10, 11, 12, 13, 14, 15), groups, window=(0, 0x40)
            )
            == ()
        )


class TestAssignRoles:
    def test_pair_evidence_assigns_roles(self) -> None:
        groups = find_twin_groups(_pngs())
        evidence = collect_evidence(_firmware(10, 20), groups, window=(0, 0x40))
        assert assign_roles(groups, evidence, {}) == {10: Role.BLACK, 20: Role.WHITE}

    def test_straddled_reads_lose_the_vote(self) -> None:
        group = TwinGroup(members=(10, 11, 20, 21), width=2, height=2)
        evidence = (
            Evidence(10, 20, "pair", 0x100),
            Evidence(11, 21, "pair", 0x104),
            Evidence(20, 11, "pair", 0x102),  # straddles two 4-byte records
        )
        roles = assign_roles([group], evidence, {})
        assert roles == {10: Role.BLACK, 11: Role.BLACK, 20: Role.WHITE, 21: Role.WHITE}

    def test_no_evidence_and_no_override_is_ambiguous(self) -> None:
        groups = find_twin_groups(_pngs())
        with pytest.raises(ThemeError, match="ambiguous"):
            _ = assign_roles(groups, (), {})

    def test_override_resolves_a_pair(self) -> None:
        groups = find_twin_groups(_pngs())
        assert assign_roles(groups, (), {20: Role.WHITE}) == {
            10: Role.BLACK,
            20: Role.WHITE,
        }

    def test_override_contradicting_evidence_fails_closed(self) -> None:
        groups = find_twin_groups(_pngs())
        evidence = collect_evidence(_firmware(10, 20), groups, window=(0, 0x40))
        with pytest.raises(ThemeError, match="contradicts"):
            _ = assign_roles(groups, evidence, {10: Role.WHITE})

    def test_all_members_one_role_rejected(self) -> None:
        groups = find_twin_groups(_pngs())
        with pytest.raises(ThemeError, match="no valid role assignment"):
            _ = assign_roles(groups, (), {10: Role.BLACK, 20: Role.BLACK})


class TestClosestBlackTwin:
    def test_prefers_the_black_member_sharing_most_palette_entries(self) -> None:
        pngs = {
            10: build_png(_INDEXED_4X3, _PIXELS, _BLACK_PLTE),
            11: build_png(_INDEXED_4X3, _PIXELS, _SELECTED_PLTE),
            20: build_png(_INDEXED_4X3, _PIXELS, _WHITE_PLTE),
            21: build_png(
                _INDEXED_4X3,
                _PIXELS,
                [(255, 255, 255), (0, 0, 0), (255, 0, 255), (248, 216, 8)],
            ),
        }
        group = TwinGroup(members=(10, 11, 20, 21), width=4, height=3)
        roles = {10: Role.BLACK, 11: Role.BLACK, 20: Role.WHITE, 21: Role.WHITE}
        assert closest_black_twin(20, group, roles, pngs) == 10
        assert closest_black_twin(21, group, roles, pngs) == 11


class TestV103Overrides:
    def test_overrides_cover_the_nine_evidence_free_groups(self) -> None:
        blacks = {i for i, role in V103_ROLE_OVERRIDES.items() if role is Role.BLACK}
        whites = {i for i, role in V103_ROLE_OVERRIDES.items() if role is Role.WHITE}
        assert blacks == {
            588,
            589,
            594,
            595,
            656,
            657,
            658,
            659,
            683,
            684,
            685,
            686,
            836,
            837,
            842,
            843,
            844,
        }
        assert whites == {
            590,
            591,
            596,
            597,
            747,
            748,
            749,
            750,
            774,
            775,
            776,
            777,
            840,
            841,
            845,
            846,
            847,
        }
