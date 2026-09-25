"""Rich-based ProgressListener — renders FlashSession events to a live UI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self


from .flash.diagnostics import format_busy_telemetry, format_throughput
from .flash.progress import (
    FlashCompleted,
    HandshakeBaudTried,
    HandshakeStarted,
    HandshakeSucceeded,
    ProgressEvent,
    SegmentChunkSent,
    SegmentErased,
    SegmentProgress,
    SegmentStarted,
    SegmentVerified,
    TargetIdentified,
    TransportBaudChanged,
)


class RichProgressListener:
    """ProgressListener that renders to a rich.Console.

    Minimal implementation: one line per significant event with status
    markers. Per-chunk events are intentionally suppressed (they would
    dominate the output for a multi-MB segment). The full Live-driven
    progress-bar UI is a future enhancement; this keeps the protocol-
    correctness story testable without binding to rich.Live internals.
    """

    def __init__(self, console: Console | None = None) -> None:
        """Render to ``console``, or to a new default console when none is given."""
        super().__init__()
        self._console = console or Console()

    def emit(self, event: ProgressEvent) -> None:
        """Print one line for a significant event; per-chunk events print nothing."""
        match event:
            # First arm on purpose. Every other event fires a handful of
            # times per flash; this one fires once per data unit, tens of
            # thousands of times, and a match arm costs a type test whether
            # or not it matches. No arm below overlaps it, so the order can
            # be chosen by frequency.
            case SegmentChunkSent():
                # Don't print every chunk — too noisy for multi-MB segments.
                pass
            case (
                HandshakeStarted()
                | HandshakeBaudTried()
                | HandshakeSucceeded()
                | TargetIdentified()
            ):
                self._emit_link_event(event)
            case _:
                self._emit_transfer_event(event)

    def _emit_link_event(
        self,
        event: HandshakeStarted
        | HandshakeBaudTried
        | HandshakeSucceeded
        | TargetIdentified,
    ) -> None:
        """Print an unlock or target-identification event."""
        match event:
            case HandshakeStarted(port=port, baud_ladder=ladder):
                self._console.print(
                    f"[bold]Handshake[/bold] on {port} (bauds: {ladder})",
                )
            case HandshakeBaudTried(baud=baud, succeeded=True):
                self._console.print(f"  [green]✓[/green] baud {baud}")
            case HandshakeBaudTried(baud=baud, succeeded=False):
                self._console.print(f"  [yellow]✗[/yellow] baud {baud}")
            case HandshakeSucceeded(baud=baud, xor_key=key):
                self._console.print(
                    f"[green]✓ Handshake[/green] baud {baud}, XOR key 0x{key:02X}",
                )
            case TargetIdentified(
                target_mask_bytes=target_mask,
                opaque_bytes_8_15=opaque,
                trailing_status=status,
            ):
                self._console.print(
                    "[green]✓ Target[/green] mask bytes "
                    f"{target_mask.hex(' ')}, opaque[8:16] {opaque.hex(' ')}, "
                    f"trailing status 0x{status:02X}",
                )
            case _:
                # Exhaustiveness: every variant above has an explicit case;
                # this catch-all silences pyright's warning about
                # HandshakeBaudTried having both succeeded values (the static
                # checker can't see the `succeeded=True` + `succeeded=False`
                # pair as exhaustive on its own).
                pass

    def _emit_transfer_event(
        self,
        event: TransportBaudChanged
        | SegmentStarted
        | SegmentErased
        | SegmentProgress
        | SegmentVerified
        | FlashCompleted,
    ) -> None:
        """Print a line-rate, per-segment, or completion event."""
        match event:
            case SegmentProgress(
                chunks_sent=chunks,
                bytes_sent=sent,
                elapsed_seconds=elapsed,
            ):
                self._console.print(
                    "  [cyan]·[/cyan] "
                    + format_throughput(
                        chunks=chunks,
                        bytes_sent=sent,
                        elapsed_seconds=elapsed,
                    ),
                )
            case TransportBaudChanged(baud=baud, reason=reason):
                self._console.print(f"  [cyan]·[/cyan] baud {baud} ({reason})")
            case SegmentStarted(
                name=name,
                index=idx,
                total_segments=total,
                byte_count=n,
                erase_length=erase_length,
            ):
                erase_note = "" if erase_length else ", no erase ($EL=0)"
                self._console.print(
                    f"[bold]Segment {idx + 1}/{total} {name}[/bold] "
                    f"({n:,} bytes{erase_note})",
                )
            case SegmentErased(
                elapsed_seconds=t,
                busy_count=busy_count,
                first_busy_seconds=first_busy,
                busy_intervals=intervals,
            ):
                telemetry = format_busy_telemetry(
                    busy_count=busy_count,
                    first_busy_seconds=first_busy,
                    busy_intervals=intervals,
                )
                self._console.print(
                    f"  [green]✓[/green] BEGIN complete ({t:.1f}s; {telemetry})",
                )
            case SegmentVerified(expected_checksum=e, status_code=status):
                marker = "[green]✓[/green]" if status == 0 else "[red]✗[/red]"
                self._console.print(
                    f"  {marker} verified (loader status 0x{status:02X}; "
                    f"descriptor CA 0x{e:04X})",
                )
            case FlashCompleted(bytes_written=n, elapsed_seconds=t):
                self._console.print(
                    f"\n[green]✓ Flash complete[/green] in {t:.0f}s — "
                    f"{n:,} bytes written",
                )

    def __enter__(self) -> Self:
        """Return the listener for use in a ``with`` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Release nothing: the listener holds no resources of its own."""
