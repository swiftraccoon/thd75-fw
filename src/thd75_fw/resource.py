"""Firmware resource extraction from the .NET updater PE.

The TH-D75 firmware updater embeds all firmware data as a managed
string resource. This module locates and extracts that resource by
scanning the PE binary directly. Callers that have a pre-extracted
resource (e.g. ILSpy output) should pass it explicitly through the
CLI ``--resource`` flag rather than relying on path-based discovery.
"""

from __future__ import annotations

from pathlib import Path

__all__: list[str] = ["extract", "load", "replace"]

_HEX_CHARS: frozenset[int] = frozenset(b"0123456789abcdefABCDEF")
_DOLLAR_BYTE: int = ord("$")

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

    The resource is scanned out of ``exe_path`` itself. A previous
    version of this loader silently preferred a sibling ILSpy-extracted
    text file when one existed next to the requested ``.exe`` — that
    auto-discovery would silently bypass the requested updater and is
    a firmware-version footgun (e.g. ``thd75-extract V1.05.exe`` could
    return V1.03 content if a sibling text file from a prior session
    sat in the same directory). Pre-extracted resources are now
    explicit-only via the CLI ``--resource`` flag.

    Args:
        exe_path: Path to ``TH-D75_V103_e.exe`` (or equivalent).

    Returns:
        The full text content of the firmware resource.

    Raises:
        FileNotFoundError: If ``exe_path`` does not exist.
        ValueError: If the resource cannot be found in the PE.
    """
    return _scan_pe(Path(exe_path))


def extract(exe_data: bytes) -> str:
    """Extract the firmware resource text from updater ``.exe`` bytes.

    Args:
        exe_data: Raw bytes of the updater executable.

    Returns:
        The full text of the embedded firmware resource.

    Raises:
        ValueError: if the resource cannot be located.
    """
    start, end = _find_resource_span(exe_data)
    return exe_data[start:end].decode("ascii", errors="strict")


def replace(exe_data: bytes, new_resource: str) -> bytes:
    """Return ``exe_data`` with its embedded firmware resource replaced.

    The resource is overwritten in place, so ``new_resource`` must encode
    to exactly the same number of ASCII bytes as the resource it replaces
    — keeping every other PE offset (and the managed resource's own
    length prefix) untouched.

    Args:
        exe_data: Raw bytes of the updater executable.
        new_resource: Replacement resource text.

    Returns:
        The updater bytes with the resource region overwritten.

    Raises:
        ValueError: if the resource cannot be located, or
            ``new_resource`` is not the same length as the original.
    """
    start, end = _find_resource_span(exe_data)
    replacement: bytes = new_resource.encode("ascii")
    if len(replacement) != end - start:
        msg = (
            f"replacement resource is {len(replacement):,} bytes but the "
            f"original is {end - start:,} — an in-place splice needs an "
            f"exact length match"
        )
        raise ValueError(msg)
    return exe_data[:start] + replacement + exe_data[end:]


def _scan_pe(exe_path: Path) -> str:
    """Scan a PE binary *file* for the embedded firmware resource."""
    return extract(exe_path.read_bytes())


def _find_resource_span(data: bytes) -> tuple[int, int]:
    """Locate the embedded firmware resource within PE bytes.

    The resource is a contiguous ASCII text region of ``$``-prefixed
    metadata lines interleaved with hex data lines — ~42 MB of the 43 MB
    executable.

    Returns:
        The ``(start, end)`` byte offsets of the resource region.

    Raises:
        ValueError: if no resource region is found.
    """
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

        # Found a candidate — scan forward for the end of the region.
        end: int = _find_end(data, line_end)
        # Strict ASCII: the resource is pure ASCII hex/$ markers. A
        # UnicodeDecodeError means a false-positive region — keep looking.
        try:
            text: str = data[candidate_start:end].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            continue

        if len(text) >= _MIN_RESOURCE_SIZE:
            return (candidate_start, end)

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
