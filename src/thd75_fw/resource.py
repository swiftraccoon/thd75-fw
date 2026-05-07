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
_DOLLAR_BYTE: int = ord("$")

_ILSPY_RESOURCE_NAME: str = "THD75_Updater_E.Resources.TH-D75_Firm_E.txt"

_MIN_RESOURCE_SIZE: int = 1_000_000  # Must be > 1 MB to be valid


def _is_resource_line(line: bytes) -> bool:
    """Return True if ``line`` looks like a resource line: hex chars only,
    optionally with a leading ``$`` for metadata lines.

    The resource is pure ASCII hex pairs interleaved with ``$``-prefixed
    metadata lines, so any byte outside ``[0-9a-fA-F$]`` disqualifies a
    candidate region.
    """
    return all(c in _HEX_CHARS or c == _DOLLAR_BYTE for c in line)


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

    # Prefer pre-extracted resource (much faster, no scanning).
    # If the .exe doesn't exist, _scan_pe's read_bytes() raises
    # FileNotFoundError with .filename properly populated for callers.
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

    for candidate_start in range(len(data) - 100):
        if data[candidate_start] != _DOLLAR_BYTE:
            continue

        # Check for a valid ``$`` + hex metadata line at this candidate.
        line_end: int = data.find(b"\r\n", candidate_start)
        if line_end < 0:
            line_end = data.find(b"\n", candidate_start)
        if line_end < 0 or line_end - candidate_start < 4:
            continue

        if not _is_resource_line(data[candidate_start:line_end]):
            continue

        # Found a candidate — scan forward for the end of the resource region
        end: int = _find_end(data, line_end)
        # Strict ASCII: the resource is supposed to be pure ASCII hex/$ markers.
        # A UnicodeDecodeError here means we found a false-positive region;
        # let the caller see the failure rather than silently substituting.
        try:
            text: str = data[candidate_start:end].decode(
                "ascii", errors="strict",
            )
        except UnicodeDecodeError:
            continue

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

        # Hex data lines and ``$`` metadata lines are part of the resource.
        if _is_resource_line(line):
            pos = next_nl
            continue

        # Binary content reached → end of resource.
        if b"\x00\x00" in line[:10]:
            break

        pos = next_nl

    return pos
