"""Evidence capture for a real flash: config banner, wire trace, build identity.

Every past hardware attempt recorded only the image, the port and the
outcome. Chunk size, transfer mode, ACK policy and the negotiated baud had
to be reconstructed afterwards by correlating run timestamps against source
edits, and for some runs that was impossible. This module exists so a run
log states its own configuration.

Two rules shape the design:

* **The banner is derived, never restated.** The transfer-mode figures come
  from :func:`thd75_fw.flash.session.negotiated_transfer_mode`, the same
  call that builds the BAUD_AND_ACK payload actually sent, so the banner
  cannot describe one protocol while the session runs another.
* **The default path stays free.** :class:`WireTrace` is constructed only
  when the operator passes ``--wire-trace``; with it off the session holds
  ``None`` and each frame costs one ``is not None`` test. With it on,
  records are appended as tuples and formatted in batches, so no frame pays
  for string formatting or a write syscall.

Nothing here imports the protocol types — the session passes plain ints and
bytes — so this module is pure stdlib and directly testable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from types import TracebackType

    from typing_extensions import Self

#: Payload bytes retained per wire-trace record.
#:
#: A SEND_CHUNK payload is ``offset:u32 + length:u32 + data``, so 16 bytes
#: shows both header fields plus the first eight data bytes — enough to
#: confirm sequencing and alignment. The cap is what keeps a 15 MB flash
#: from writing a 15 MB trace, and it is why the trace holds no meaningful
#: quantity of firmware content.
TRACE_HEX_PREFIX_BYTES: Final[int] = 16

#: Records buffered before one batched write. At 256-byte chunks a full
#: stock flash produces about 60,000 records, so this is roughly 120 writes
#: for the whole run instead of one per frame.
TRACE_FLUSH_RECORDS: Final[int] = 512

#: First line of every trace file. Bump when the column layout changes.
TRACE_FORMAT_VERSION: Final[str] = "thd75-fw wire-trace v1"

#: Column header written under the format version.
TRACE_COLUMNS: Final[str] = "t_seconds,dir,verb,verb_name,payload_len,hex_prefix"

BANNER_START: Final[str] = "=== FLASH CONFIGURATION ==="
BANNER_END: Final[str] = "=== END FLASH CONFIGURATION ==="

#: Source files whose bytes decide how a flash behaves. The digest over
#: these answers "which code ran" even when the working tree is dirty,
#: which a git revision alone does not.
_FINGERPRINTED_SOURCES: Final[tuple[str, ...]] = (
    "cli.py",
    "intel_hex.py",
    "kex.py",
    "flash/commands.py",
    "flash/diagnostics.py",
    "flash/handshake.py",
    "flash/progress.py",
    "flash/protocol.py",
    "flash/segments.py",
    "flash/serial_io.py",
    "flash/session.py",
)

#: Characters of each hex digest kept for display.
_SHORT_DIGEST_CHARS: Final[int] = 12

#: Directory levels searched upward for a repository checkout.
_GIT_SEARCH_LEVELS: Final[int] = 6


def git_revision(start: Path | None = None) -> str | None:
    """Return the short commit id of the checkout containing this package.

    Reads ``.git`` directly rather than shelling out: no subprocess, no
    ``git`` on PATH required, and nothing to hang a flash run. Returns
    ``None`` for an installed wheel, a shallow copy, or an unborn branch —
    the caller renders that as "unavailable" rather than guessing.
    """
    base = Path(__file__).resolve().parent if start is None else Path(start).resolve()
    candidates = (base, *base.parents)
    for candidate in list(candidates)[:_GIT_SEARCH_LEVELS]:
        git_path = candidate / ".git"
        try:
            git_dir = _resolve_git_dir(git_path)
        except OSError:
            return None
        if git_dir is None:
            continue
        try:
            return _head_commit(git_dir)
        except OSError:
            return None
    return None


def _resolve_git_dir(git_path: Path) -> Path | None:
    """Return the real git directory for ``.git``, dir or worktree file."""
    if git_path.is_dir():
        return git_path
    if git_path.is_file():
        # Worktrees and submodules store "gitdir: <path>" in a plain file.
        content = git_path.read_text(encoding="utf-8", errors="replace").strip()
        if content.startswith("gitdir:"):
            target = Path(content.split(":", 1)[1].strip())
            if not target.is_absolute():
                target = (git_path.parent / target).resolve()
            return target if target.is_dir() else None
    return None


def _head_commit(git_dir: Path) -> str | None:
    """Resolve HEAD to a short commit id without invoking git."""
    head_file = git_dir / "HEAD"
    if not head_file.is_file():
        return None
    head = head_file.read_text(encoding="utf-8", errors="replace").strip()
    if not head.startswith("ref:"):
        return head[:_SHORT_DIGEST_CHARS] if _is_hex(head) else None
    ref = head.split(":", 1)[1].strip()
    ref_file = git_dir / ref
    if ref_file.is_file():
        value = ref_file.read_text(encoding="utf-8", errors="replace").strip()
        return value[:_SHORT_DIGEST_CHARS] if _is_hex(value) else None
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.endswith(f" {ref}"):
                value = line.split(" ", 1)[0]
                return value[:_SHORT_DIGEST_CHARS] if _is_hex(value) else None
    return None


def _is_hex(value: str) -> bool:
    return bool(value) and all(c in "0123456789abcdefABCDEF" for c in value)


def flasher_source_digest(package_root: Path | None = None) -> str:
    """Digest the flasher sources so a dirty tree still identifies itself.

    The problem this addresses is specific: a run log that names a commit
    is useless when the commit was not what executed. Hashing the files
    that decide flash behaviour pins the exact code, and it costs a few
    milliseconds once per session.

    Returns ``"unavailable"`` if the sources cannot be read (an installed
    zipimport, for example) rather than raising into a flash preflight.
    """
    root = (
        Path(__file__).resolve().parent.parent if package_root is None else package_root
    )
    digest = hashlib.sha256()
    try:
        for relative in _FINGERPRINTED_SOURCES:
            digest.update(relative.encode("ascii"))
            digest.update((root / relative).read_bytes())
    except OSError:
        return "unavailable"
    return digest.hexdigest()[:_SHORT_DIGEST_CHARS]


@dataclass(frozen=True, slots=True)
class FlashConfig:
    """Everything a later reader needs to know what a flash run did.

    Held as data rather than printed inline so the same values can go to
    the operator's terminal and into the wire-trace header, and so the
    banner is assertable in tests without parsing console output.
    """

    #: Image path as the operator gave it.
    image: str
    #: SHA-256 of the rendered plaintext image, or ``None`` for raw plans.
    image_sha256: str | None
    #: Audited-artifact label, or ``None`` when the image is not pinned.
    image_label: str | None
    port: str
    #: Baud the serial device is opened at, before any session change.
    open_baud: int
    #: ``"cleartext"`` (FPROMOD) or ``"keyed"`` (Thd75tw + XOR).
    unlock_path: str
    #: Baud the unlock itself runs at. For the keyed path this is the first
    #: rung of the ladder that answers, so it is a plan, not an observation.
    unlock_baud: int
    #: Baud restored after unlock, or ``None`` when the path does not move.
    post_unlock_baud: int | None
    #: Ladder the keyed path probes; ``None`` on the cleartext path.
    baud_ladder: tuple[int, ...] | None
    #: Exact BAUD_AND_ACK payload bytes that will be sent.
    baud_and_ack_payload: bytes
    #: Baud code the payload declares.
    transfer_mode_code: int
    #: Baud that code stands for in the loader's own table.
    transfer_declared_baud: int
    #: Whether the loader ACKs every SEND_CHUNK in that mode.
    ack_each_data_packet: bool
    #: Base command-reply margin. SETUP/VERIFY add their descriptor ``$CT``;
    #: BEGIN adds ``$ET`` independently for every BUSY/ACK response.
    base_reply_timeout_seconds: float
    chunk_size: int
    #: ``True`` writes every segment (KEX ``#AF=1``); ``False`` lets the
    #: loader's SETUP equality answer skip current ones.
    force_all_segments: bool
    #: Exact zero-based segment indices deliberately rewritten even when SETUP
    #: reports them current. Non-empty only for a separately gated hardware
    #: qualification run; ordinary recovery uses the skip-current policy.
    forced_segment_indices: tuple[int, ...]
    #: Stable qualification profile identifier recorded for offline validation.
    qualification: str | None
    #: Derived description of the exact selectively rewritten payload, including
    #: its index, label, byte/packet counts, and SHA-256. ``None`` outside a
    #: qualification run.
    qualification_target: str | None
    complete_update_value: int
    complete_update_width: int
    segment_count: int
    planned_bytes: int
    wire_trace_path: str | None
    progress_every_chunks: int
    tool_version: str
    git_revision: str | None
    source_digest: str
    #: Host-side omission applied before any loader command, or ``None``.
    host_omission: str | None = None

    def rows(self) -> tuple[tuple[str, str], ...]:
        """Return the banner as ``(key, value)`` pairs, in print order."""
        completion_bytes = self.complete_update_value.to_bytes(
            self.complete_update_width,
            "little",
        )
        ack_flag = int(self.ack_each_data_packet)
        ack_policy = (
            "per-packet ACK: every SEND_CHUNK waits for a loader reply"
            if self.ack_each_data_packet
            else (
                "streaming: the loader answers no SEND_CHUNK; END_TRANSFER "
                "and VERIFY_SEGMENT are the synchronisation points"
            )
        )
        segment_policy = (
            "force-all: write every segment, honouring KEX #AF=1"
            if self.force_all_segments
            else "skip-current: the loader's SETUP equality answer decides"
        )
        forced_segments = (
            ",".join(str(index) for index in self.forced_segment_indices)
            if self.forced_segment_indices
            else "none"
        )
        host_omission_row = (
            (("host_omission", self.host_omission),)
            if self.host_omission is not None
            else ()
        )
        return (
            ("tool_version", self.tool_version),
            ("git_revision", self.git_revision or "unavailable"),
            ("source_digest", self.source_digest),
            ("image", self.image),
            ("image_sha256", self.image_sha256 or "n/a"),
            ("image_audit", self.image_label or "unpinned"),
            ("port", self.port),
            ("port_open_baud", str(self.open_baud)),
            ("unlock_path", self._unlock_description()),
            ("baud_plan", self._baud_plan()),
            ("baud_and_ack", self._baud_and_ack_description(ack_flag)),
            ("ack_policy", ack_policy),
            (
                "reply_timeouts",
                f"base {self.base_reply_timeout_seconds:g}s; "
                "SETUP/VERIFY add $CT; BEGIN adds $ET per response",
            ),
            ("chunk_size", f"{self.chunk_size} bytes per SEND_CHUNK"),
            ("segment_policy", segment_policy),
            ("qualification", self.qualification or "off"),
            ("forced_segments", forced_segments),
            *host_omission_row,
            ("qualification_target", self.qualification_target or "off"),
            (
                "completion",
                f"0x{self.complete_update_value:X} as LE u"
                f"{self.complete_update_width * 8} ({completion_bytes.hex(' ')})",
            ),
            (
                "plan",
                f"{self.segment_count} segments, {self.planned_bytes:,} bytes",
            ),
            ("wire_trace", self.wire_trace_path or "off"),
            (
                "progress_interval",
                f"every {self.progress_every_chunks} chunks"
                if self.progress_every_chunks
                else "off",
            ),
        )

    def _unlock_description(self) -> str:
        if self.unlock_path == "cleartext":
            return "cleartext FPROMOD; framed traffic in plaintext (xor_key=0)"
        return "keyed Thd75tw; framed traffic under the 4-step cipher"

    def _baud_and_ack_description(self, ack_flag: int) -> str:
        return (
            f"payload {self.baud_and_ack_payload.hex(' ')} = code "
            f"0x{self.transfer_mode_code:02X} (declares "
            f"{self.transfer_declared_baud} baud), "
            f"ack_each_data_packet={ack_flag}"
        )

    def _baud_plan(self) -> str:
        steps = [f"{self.open_baud} (port open)"]
        if self.unlock_path == "cleartext":
            if self.unlock_baud == self.open_baud:
                steps[0] = f"{self.open_baud} (port open; FPROMOD at same rate)"
            else:
                steps.append(f"{self.unlock_baud} (set before FPROMOD)")
        elif self.baud_ladder:
            ladder = "/".join(str(b) for b in self.baud_ladder)
            steps.append(f"{ladder} (keyed unlock ladder)")
        if self.post_unlock_baud is not None:
            steps.append(f"{self.post_unlock_baud} (restored after unlock)")
        tail = (
            ""
            if self.post_unlock_baud is not None
            else "; no further change during the data phase"
        )
        return " -> ".join(steps) + tail

    def render(self) -> str:
        """Return the banner as one block of text, ready to log."""
        width = max(len(key) for key, _ in self.rows())
        lines = [BANNER_START]
        lines.extend(f"  {key:<{width}} : {value}" for key, value in self.rows())
        lines.append(BANNER_END)
        return "\n".join(lines)

    def comment_lines(self) -> tuple[str, ...]:
        """Return the banner as ``#``-prefixed lines for a trace header."""
        return tuple(f"# {line}" for line in self.render().splitlines())


class WireTrace:
    """Append-only record of every frame sent and received.

    Records are kept as tuples and rendered in batches of
    ``flush_records``. That ordering is deliberate: formatting a line and
    calling ``write`` per frame would put a syscall inside the data phase
    and distort exactly the timing this trace is meant to measure. Payload
    bytes are truncated at capture time, not at flush time, so a multi-MB
    segment never sits in the buffer.

    Not thread-safe. The flash session is synchronous by design (see the
    unused async-reader note in ``session.py``); if that ever changes, this
    needs a lock.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        header_lines: Sequence[str] = (),
        flush_records: int = TRACE_FLUSH_RECORDS,
        hex_prefix_bytes: int = TRACE_HEX_PREFIX_BYTES,
        exclusive: bool = False,
    ) -> None:
        """Open the trace file and write its header.

        Args:
            path: Where to write the trace.
            header_lines: Lines written verbatim after the format version,
                normally :meth:`FlashConfig.comment_lines`.
            flush_records: Records buffered before one batched write.
            hex_prefix_bytes: Payload bytes retained per record.
            exclusive: Create the file exclusively, refusing to replace an
                existing one, instead of truncating it.

        Raises:
            ValueError: If ``flush_records`` is below 1 or
                ``hex_prefix_bytes`` is negative.
            OSError: If the file cannot be opened, including
                ``FileExistsError`` when ``exclusive`` finds one already there.

        """
        super().__init__()
        if flush_records < 1:
            msg = f"flush_records must be >= 1, got {flush_records}"
            raise ValueError(msg)
        if hex_prefix_bytes < 0:
            msg = f"hex_prefix_bytes must be >= 0, got {hex_prefix_bytes}"
            raise ValueError(msg)
        self._path = Path(path)
        self._flush_records = flush_records
        self._hex_prefix_bytes = hex_prefix_bytes
        self._records: list[tuple[float, str, int, int, str]] = []
        self._record_count = 0
        # UTF-8 rather than ASCII: the records themselves are hex and verb
        # names, but the header carries the banner, and an image path with a
        # non-ASCII character would otherwise raise UnicodeEncodeError while
        # opening the trace. That is a ValueError, so the CLI's OSError
        # handler would not catch it and the operator would get a traceback
        # instead of a flash.
        # Qualification evidence must never overwrite an earlier run. Ordinary
        # diagnostic traces retain the historical replace behavior; the tightly
        # gated qualification path opts into race-safe exclusive creation.
        mode = "x" if exclusive else "w"
        self._file = self._path.open(mode, encoding="utf-8", newline="\n")
        _ = self._file.write(f"# {TRACE_FORMAT_VERSION}\n")
        for line in header_lines:
            _ = self._file.write(f"{line}\n")
        _ = self._file.write(f"# columns: {TRACE_COLUMNS}\n")
        _ = self._file.write(
            f"# payload bytes are truncated to {hex_prefix_bytes} for size\n"
        )
        self._file.flush()
        # perf_counter, not monotonic: the trace measures intervals inside
        # one run, and this is the highest-resolution monotonic clock
        # Python offers.
        self._start = time.perf_counter()

    @property
    def path(self) -> Path:
        """Location of the trace file."""
        return self._path

    @property
    def record_count(self) -> int:
        """Frames recorded so far, including any still buffered."""
        return self._record_count

    def record(self, direction: str, verb: int, payload: bytes) -> None:
        """Buffer one frame. Called on the hot path; keep it allocation-light."""
        self._records.append(
            (
                time.perf_counter() - self._start,
                direction,
                verb,
                len(payload),
                payload[: self._hex_prefix_bytes].hex(),
            ),
        )
        self._record_count += 1
        if len(self._records) >= self._flush_records:
            self.flush()

    def record_tx(self, verb: int, payload: bytes) -> None:
        """Buffer one frame sent to the loader."""
        self.record("TX", verb, payload)

    def record_rx(self, verb: int, payload: bytes) -> None:
        """Buffer one response decoded from the loader."""
        self.record("RX", verb, payload)

    def note(self, text: str) -> None:
        """Write a comment line, ordered after everything buffered so far."""
        self.flush()
        _ = self._file.write(f"# {text}\n")
        self._file.flush()

    def flush(self) -> None:
        """Render and write buffered records, then clear the buffer."""
        if not self._records:
            return
        _ = self._file.write(
            "".join(
                f"{elapsed:.6f},{direction},0x{verb:02X},"
                f"{verb_label(direction, verb)},{length},{prefix}\n"
                for elapsed, direction, verb, length, prefix in self._records
            ),
        )
        self._records.clear()
        # A flash that hangs is the case this trace exists for, and a hung
        # process is killed rather than closed cleanly. Flushing per batch
        # bounds what a kill can lose to one batch.
        self._file.flush()

    def close(self) -> None:
        """Flush buffered records, append the frame-count footer, and close."""
        self.flush()
        if not self._file.closed:
            _ = self._file.write(f"# {self._record_count} frames recorded\n")
            self._file.close()

    def __enter__(self) -> Self:
        """Return the open trace for use in a ``with`` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the trace, whether or not the block raised."""
        del exc_type, exc_val, exc_tb
        self.close()


#: Request verbs, by value. Kept as a plain dict so the trace module does
#: not import the protocol enums (it stays pure stdlib and independently
#: testable); ``test_flash_diagnostics`` asserts the two stay in step.
_REQUEST_VERB_NAMES: Final[dict[int, str]] = {
    0x30: "ENTER_PROGRAM",
    0x31: "QUERY_TARGET",
    0x33: "BAUD_AND_ACK",
    0x40: "SETUP_SEGMENT",
    0x42: "BEGIN_TRANSFER",
    0x43: "SEND_CHUNK",
    0x44: "END_TRANSFER",
    0x45: "VERIFY_SEGMENT",
    0x50: "COMPLETE_UPDATE",
    0xA0: "TIMED_SESSION",
    0xA3: "SELECT_TARGET",
}

#: One- and two-byte loader responses, by value.
_RESPONSE_CODE_NAMES: Final[dict[int, str]] = {
    0x06: "ACK",
    0x11: "BUSY",
    0x15: "NAK",
}


def verb_label(direction: str, verb: int) -> str:
    """Return a human name for a traced verb byte.

    Resolved at flush time rather than at capture time so the hot path
    never pays for a dict lookup or a string.
    """
    if direction == "RX":
        code_name = _RESPONSE_CODE_NAMES.get(verb)
        if code_name is not None:
            return code_name
        # Framed replies carry request_verb + 1 (see response_verb_for).
        request_name = _REQUEST_VERB_NAMES.get(verb - 1)
        if request_name is not None:
            return f"{request_name}_REPLY"
        return "UNKNOWN"
    return _REQUEST_VERB_NAMES.get(verb, "UNKNOWN")


def format_throughput(
    *,
    chunks: int,
    bytes_sent: int,
    elapsed_seconds: float,
) -> str:
    """Render one data-phase progress line.

    Shared by the console listener and the trace so a slow run reads the
    same way in both places.
    """
    rate = bytes_sent / elapsed_seconds if elapsed_seconds > 0 else 0.0
    return (
        f"{chunks:,} chunks, {bytes_sent:,} bytes in {elapsed_seconds:.1f}s "
        f"({rate:,.0f} B/s)"
    )


def format_busy_telemetry(
    *,
    busy_count: int,
    first_busy_seconds: float | None,
    busy_intervals: Iterable[float],
) -> str:
    """Render BEGIN_TRANSFER BUSY evidence, including its absence.

    Whether the D75 loader emits BUSY at all during erase is an open
    question, so "no BUSY frames" is a result worth stating explicitly
    rather than an empty field a reader has to interpret.
    """
    if busy_count == 0:
        return "no BUSY frames (loader ACKed the erase directly)"
    gaps = ", ".join(f"{gap:.2f}s" for gap in busy_intervals)
    first = "unknown" if first_busy_seconds is None else f"{first_busy_seconds:.2f}s"
    plural = "" if busy_count == 1 else "s"
    detail = f"{busy_count} BUSY frame{plural}, first at {first}"
    return f"{detail}, gaps {gaps}" if gaps else detail
