"""Scheme twins: pixel-identical indexed PNGs whose palettes differ per scheme.

The firmware ships most indexed icons twice, one PLTE per scheme, and
selects the twin by scheme through pair tables (two adjacent u16 image
indices, Black first) or N-image widget descriptors (N Black indices then
N White indices). This module finds the twin groups in an image
database, gathers that evidence from the FIRMWARE image, and assigns a
role to every member by majority vote. Groups that the firmware selects
with inline constants are resolved by an explicit override table.
"""

from __future__ import annotations

import hashlib
import itertools
import struct
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Final

from .png import decode_8bit, is_indexed_8bit, palette

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from .colour import RGB

__all__: list[str] = [
    "DESCRIPTOR_SIZES",
    "UI_TABLE_WINDOW",
    "V103_ROLE_OVERRIDES",
    "Evidence",
    "Role",
    "ThemeError",
    "TwinGroup",
    "assign_roles",
    "closest_black_twin",
    "collect_evidence",
    "find_twin_groups",
]


class ThemeError(ValueError):
    """The theme cannot be derived from these sections."""


class Role(Enum):
    """Which scheme an image is drawn for."""

    BLACK = "black"
    WHITE = "white"


@dataclass(frozen=True, slots=True)
class TwinGroup:
    """Images with identical dimensions and pixels but at least two distinct PLTEs."""

    members: tuple[int, ...]
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class Evidence:
    """One firmware table entry naming ``black`` as the Black-scheme twin of ``white``."""

    black: int
    white: int
    kind: str
    offset: int


UI_TABLE_WINDOW: tuple[int, int] = (0x15F000, 0x180000)
"""FIRMWARE flat-offset range holding the V1.03 display tables."""

DESCRIPTOR_SIZES: tuple[int, ...] = (3, 6)
"""Image counts per scheme block in the widget descriptors seen in V1.03."""

_MIN_GROUP_MEMBERS: Final[int] = 2
"""Fewest pixel-identical images that can form a twin group."""

_MIN_DISTINCT_PALETTES: Final[int] = 2
"""Fewest distinct PLTEs among a twin group's members."""


def find_twin_groups(pngs: Mapping[int, bytes]) -> tuple[TwinGroup, ...]:
    """Group indexed 8-bit PNGs by (width, height, pixels); keep groups with differing PLTEs."""
    by_key: dict[tuple[int, int, bytes], list[int]] = {}
    palettes: dict[int, tuple[RGB, ...]] = {}
    for index in sorted(pngs):
        png = pngs[index]
        if not is_indexed_8bit(png):
            continue
        decoded = decode_8bit(png)
        key = (decoded.width, decoded.height, hashlib.sha256(decoded.pixels).digest())
        by_key.setdefault(key, []).append(index)
        palettes[index] = palette(png)
    groups = [
        TwinGroup(members=tuple(members), width=width, height=height)
        for (width, height, _), members in by_key.items()
        if len(members) >= _MIN_GROUP_MEMBERS
        and len({palettes[m] for m in members}) >= _MIN_DISTINCT_PALETTES
    ]
    return tuple(sorted(groups, key=lambda group: group.members))


def collect_evidence(
    firmware: bytes,
    groups: Sequence[TwinGroup],
    window: tuple[int, int] = UI_TABLE_WINDOW,
) -> tuple[Evidence, ...]:
    """Scan ``window`` of ``firmware`` for pair tables and widget descriptors."""
    group_of: dict[int, TwinGroup] = {m: g for g in groups for m in g.members}
    low = max(0, window[0])
    high = min(len(firmware), window[1])

    def word(at: int) -> int:
        value: int = struct.unpack_from("<H", firmware, at)[0]
        return value

    def twins(a: int, b: int) -> bool:
        return a != b and a in group_of and b in group_of and group_of[a] is group_of[b]

    found: list[Evidence] = []
    for offset in range(low, high - 3, 2):
        a, b = word(offset), word(offset + 2)
        if twins(a, b):
            found.append(Evidence(black=a, white=b, kind="pair", offset=offset))
    for size in DESCRIPTOR_SIZES:
        for offset in range(low, high - 4 * size + 1, 2):
            pairs = [
                (word(offset + 2 * k), word(offset + 2 * size + 2 * k))
                for k in range(size)
            ]
            if all(twins(a, b) for a, b in pairs):
                found.extend(
                    Evidence(black=a, white=b, kind=f"descriptor{size}", offset=offset)
                    for a, b in pairs
                )
    return tuple(found)


def assign_roles(
    groups: Sequence[TwinGroup],
    evidence: Sequence[Evidence],
    overrides: Mapping[int, Role],
) -> dict[int, Role]:
    """Give every group member a role by majority vote over its evidence.

    Overrides fix members in advance. The winning assignment must be unique,
    must contain both roles, and must score as well as the best assignment
    without overrides; otherwise ``ThemeError`` is raised.
    """
    group_of: dict[int, TwinGroup] = {m: g for g in groups for m in g.members}
    per_group: dict[tuple[int, ...], list[Evidence]] = {g.members: [] for g in groups}
    for item in evidence:
        group = group_of.get(item.black)
        if group is not None and group_of.get(item.white) is group:
            per_group[group.members].append(item)

    roles: dict[int, Role] = {}
    for group in groups:
        members = group.members
        fixed = {m: overrides[m] for m in members if m in overrides}
        scored: list[tuple[int, dict[int, Role]]] = []
        unconstrained_best = 0
        for assignment in itertools.product(
            (Role.BLACK, Role.WHITE), repeat=len(members)
        ):
            if Role.BLACK not in assignment or Role.WHITE not in assignment:
                continue
            mapping: dict[int, Role] = dict(zip(members, assignment, strict=True))
            score = sum(
                1
                for item in per_group[members]
                if mapping[item.black] is Role.BLACK
                and mapping[item.white] is Role.WHITE
            )
            unconstrained_best = max(unconstrained_best, score)
            if all(mapping[m] is role for m, role in fixed.items()):
                scored.append((score, mapping))
        if not scored:
            msg = f"twin group {members}: overrides leave no valid role assignment"
            raise ThemeError(msg)
        best = max(score for score, _ in scored)
        winners = [mapping for score, mapping in scored if score == best]
        if best < unconstrained_best:
            msg = f"twin group {members}: an override contradicts the firmware evidence"
            raise ThemeError(msg)
        if len(winners) != 1:
            msg = (
                f"twin group {members}: ambiguous roles ({len(winners)} assignments "
                f"score {best}); add an override"
            )
            raise ThemeError(msg)
        roles.update(winners[0])
    return roles


def closest_black_twin(
    white: int,
    group: TwinGroup,
    roles: Mapping[int, Role],
    pngs: Mapping[int, bytes],
) -> int:
    """Return the Black member sharing the most PLTE entries with ``white``.

    Ties go to the lowest index.
    """
    white_palette = palette(pngs[white])
    blacks = [m for m in group.members if roles[m] is Role.BLACK]
    if not blacks:
        msg = f"twin group {group.members} has no Black member"
        raise ThemeError(msg)

    def shared(black: int) -> int:
        return sum(
            1
            for a, b in zip(palette(pngs[black]), white_palette, strict=False)
            if a == b
        )

    return max(blacks, key=lambda black: (shared(black), -black))


V103_ROLE_OVERRIDES: dict[int, Role] = {
    # sub_C007C4AC draws 0x24C/0x24E (588/590) and 0x24D/0x24F (589/591) by scheme.
    588: Role.BLACK,
    590: Role.WHITE,
    589: Role.BLACK,
    591: Role.WHITE,
    # sub_C007F228 draws 0x252/0x254 (594/596) and 0x253/0x255 (595/597) by scheme.
    594: Role.BLACK,
    596: Role.WHITE,
    595: Role.BLACK,
    597: Role.WHITE,
    # Icon bank 640..796: every evidenced pair sits at +91 (660/751, 667/758, 705/796).
    656: Role.BLACK,
    657: Role.BLACK,
    658: Role.BLACK,
    659: Role.BLACK,
    683: Role.BLACK,
    684: Role.BLACK,
    685: Role.BLACK,
    686: Role.BLACK,
    747: Role.WHITE,
    748: Role.WHITE,
    749: Role.WHITE,
    750: Role.WHITE,
    774: Role.WHITE,
    775: Role.WHITE,
    776: Role.WHITE,
    777: Role.WHITE,
    # Bar elements 834/838 and 835/839 pair at +4 in the table at flat offset 0x16194C.
    836: Role.BLACK,
    837: Role.BLACK,
    840: Role.WHITE,
    841: Role.WHITE,
    # 9x5 signal pips pair at +3; the Black index is the lower one in all 111 clean evidences.
    842: Role.BLACK,
    843: Role.BLACK,
    844: Role.BLACK,
    845: Role.WHITE,
    846: Role.WHITE,
    847: Role.WHITE,
}
"""Roles for the V1.03 twin groups the firmware selects without a table."""
