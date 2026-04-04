"""Firmware resource extraction from the .NET updater PE.

The TH-D75 firmware updater embeds all firmware data as a managed
string resource. This module locates and extracts that resource,
either from a pre-extracted file (ILSpy output) or by scanning the
PE binary directly.
"""

from __future__ import annotations

from pathlib import Path

__all__: list[str] = ["load"]

_HEX_CHARS: frozenset[int] = frozenset(b"0123456789abcdefABCDEF")

_ILSPY_RESOURCE_NAME: str = "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"

_MIN_RESOURCE_SIZE: int = 1_000_000  # Must be > 1 MB to be valid


def load(exe_path: Path) -> str:
    """Load the firmware resource text from an updater executable.

    Checks for a sibling ILSpy-extracted file first, then falls back
    to scanning the PE binary.

    Args:
        exe_path: Path to ``TH-D75_V103_e.exe`` (or equivalent).

    Returns:
        The full text content of the firmware resource.

    Raises:
        FileNotFoundError: If ``exe_path`` does not exist.
        ValueError: If the resource cannot be found in the PE.
    """
    exe_path = Path(exe_path)
    if not exe_path.exists():
        raise FileNotFoundError(exe_path)

    # Prefer pre-extracted resource (much faster, no scanning)
    ilspy_path: Path = exe_path.parent / _ILSPY_RESOURCE_NAME
    if ilspy_path.exists():
        return ilspy_path.read_text(encoding="utf-8")

    return _scan_pe(exe_path)


def _scan_pe(exe_path: Path) -> str:
    """Scan a PE binary for the embedded firmware resource.

    The resource is a contiguous ASCII text region consisting of
    ``$``-prefixed metadata lines interleaved with hex data lines.
    It occupies ~42 MB of the 43 MB executable.
    """
    data: bytes = exe_path.read_bytes()

    for i in range(len(data) - 100):
        if data[i] != ord("$"):
            continue

        # Check for a valid ``$`` + hex metadata line
        line_end: int = data.find(b"\r\n", i)
        if line_end < 0:
            line_end = data.find(b"\n", i)
        if line_end < 0 or line_end - i < 4:
            continue

        line: bytes = data[i:line_end]
        if not all(c in _HEX_CHARS or c == ord("$") for c in line):
            continue

        # Found a candidate — scan forward for the end
        end: int = _find_end(data, line_end)
        text: str = data[i:end].decode("ascii", errors="replace")

        if len(text) >= _MIN_RESOURCE_SIZE:
            return text

    msg = (
        "Firmware resource not found in PE. "
        "Extract manually with: ilspycmd <exe> -p -o <dir>"
    )
    raise ValueError(msg)


def _find_end(data: bytes, start: int) -> int:
    """Find the end of the firmware resource region starting at ``start``."""
    pos: int = start

    while pos < len(data) - 10:
        next_nl: int = data.find(b"\n", pos + 1)
        if next_nl < 0:
            break

        line: bytes = data[pos + 1 : next_nl].strip(b"\r").strip()

        # Empty lines are OK
        if not line:
            pos = next_nl
            continue

        # Hex data lines and ``$`` metadata lines are part of the resource
        if all(c in _HEX_CHARS for c in line):
            pos = next_nl
            continue
        if line[0:1] == b"$" and all(
            c in _HEX_CHARS or c == ord("$") for c in line
        ):
            pos = next_nl
            continue

        # Binary content → end of resource
        if b"\x00\x00" in line[:10]:
            break

        pos = next_nl

    return pos
