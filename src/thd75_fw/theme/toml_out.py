"""Render a theme build as a catalog patch TOML using the hex run form."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from thd75_fw.patch import SectionHashes

__all__: list[str] = ["ByteRun", "PatchTomlContent", "render_patch_toml"]


@dataclass(frozen=True, slots=True)
class ByteRun:
    """One contiguous window of a section: current bytes and desired bytes.

    Defined beside the renderer that writes it, so ``build`` can import both
    without an import cycle; ``build`` re-exports it.
    """

    section: str
    offset: int
    expect: bytes
    value: bytes

    def changed(self) -> int:
        """Count the bytes that differ between ``expect`` and ``value``."""
        return sum(
            1 for old, new in zip(self.expect, self.value, strict=True) if old != new
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PatchTomlContent:
    """Everything :func:`render_patch_toml` writes into one patch document.

    Attributes:
        name: The patch's ``name`` field.
        description: Multi-line description; it must not contain three
            consecutive double quotes, the TOML string delimiter it is
            written inside.
        target_firmware: Human-readable firmware the patch applies to.
        change_count: Declared number of single-byte changes.
        section_hashes: One ``[sections.<NAME>]`` pin table per entry, in
            order.
        runs: Byte runs to emit as ``[[changes]]`` entries.

    """

    name: str
    description: str
    target_firmware: str
    change_count: int
    section_hashes: Sequence[SectionHashes]
    runs: Sequence[ByteRun]


def _basic_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_patch_toml(content: PatchTomlContent) -> str:
    """Emit a patch document ``thd75_fw.patch.parse_patch`` accepts.

    Runs are written as equal-length hex strings so unchanged bytes inside a
    run are pinned as context; FIRMWARE runs come first, then the others,
    each group sorted by offset.

    Args:
        content: The patch's metadata, section pins and byte runs.

    Returns:
        The TOML text, ending in exactly one newline.

    Raises:
        ValueError: If the description contains three consecutive double
            quotes.

    """
    description = content.description
    if '"""' in description:
        msg = 'description must not contain """'
        raise ValueError(msg)
    lines: list[str] = [
        f"name = {_basic_string(content.name)}",
        'description = """',
        *description.strip("\n").splitlines(),
        '"""',
        f"target_firmware = {_basic_string(content.target_firmware)}",
        f"change_count = {content.change_count}",
        "",
    ]
    for pins in content.section_hashes:
        lines.append(f"[sections.{pins.section}]")
        if pins.source_sha256 is not None:
            lines.append(f'source_sha256 = "{pins.source_sha256}"')
        if pins.result_sha256 is not None:
            lines.append(f'result_sha256 = "{pins.result_sha256}"')
        if pins.version is not None:
            lines.append(f'version = "{pins.version}"')
        lines.append("")
    ordered = sorted(
        content.runs,
        key=lambda run: (run.section != "FIRMWARE", run.section, run.offset),
    )
    for run in ordered:
        lines.extend(
            [
                "[[changes]]",
                f'section = "{run.section}"',
                f"offset = 0x{run.offset:X}",
                f'expect = "{run.expect.hex(" ").upper()}"',
                f'value  = "{run.value.hex(" ").upper()}"',
                "",
            ]
        )
    return "\n".join(lines).rstrip("\n") + "\n"
