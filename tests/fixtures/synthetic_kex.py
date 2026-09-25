"""Scaled-down stock-shaped plaintext ``.KEX`` artifacts for offline tests.

The stock V1.03 package is seven segments and about 15.3 MB of ``$DL``.
Driving that whole artifact through the flasher is worth doing (see the
``slow``-marked full-image test) but too heavy for every suite run, so this
module builds a byte-for-byte structurally identical artifact at a
thousandth of the size: the same seven segments in the same order, the same
``$DU``/``$DC`` data unit, the same two sub-sector overlays with ``$EL`` and
``$CL`` zero, and the same two segments whose Intel HEX coverage runs past
``$DL`` to the erase boundary.

The output is a canonical plaintext KEX file, so tests consume it through
:func:`thd75_fw.kex.parse_kex_bytes` and :func:`thd75_fw.intel_hex.parse`
exactly as the CLI consumes a real one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from thd75_fw import intel_hex, kex
from thd75_fw.flash.segments import (
    CHECKBYTES_D75_V103,
    CHECKBYTES_OFFSET,
    CHECKBYTES_SETUP_CHECKSUM_D75_V103,
    FINAL_ZZZ_D75_V103,
    FINAL_ZZZ_SETUP_CHECKSUM_D75_V103,
    ZZZ_MARKER_OFFSET,
    SegmentDescriptor,
)

#: Data unit ``$DU`` (and cluster ``$DC``) every non-overlay stock segment
#: declares.
STOCK_DATA_UNIT = 0x400

#: Vendor ``$TT`` mask, little-endian quoted-hex form.
_STOCK_TARGET_TYPE = '"0F 00 00 00 00 00 00 00"'

#: Bytes per Intel HEX data record, matching the stock artifact.
_RECORD_WIDTH = 16

#: Address span one extended-linear-address record covers.
_ELA_SPAN = 0x1_0000


class SeededByteStream:
    """Reproducible pseudorandom test data drawn from SHAKE-256 of a seed.

    Fixtures need bytes that look arbitrary, so that a dropped, reordered or
    duplicated chunk changes them, and that are identical on every run and
    every Python version. ``random.Random`` guarantees only its ``random()``
    sequence across versions, and as a non-cryptographic generator it is
    flagged by the project's security lint (S311) wherever it is constructed.
    Hashing the seed with a draw counter through an extendable-output function
    gives a stream fixed by the SHA-3 standard instead. It is meant for test
    data only.
    """

    def __init__(self, seed: int) -> None:
        super().__init__()
        self._seed = seed
        self._draws = 0

    def take(self, length: int) -> bytes:
        """Return the next ``length`` bytes of the stream."""
        block = hashlib.shake_256(f"{self._seed}:{self._draws}".encode("ascii"))
        self._draws += 1
        return block.digest(length)

    def below(self, bound: int) -> int:
        """Return an integer in ``range(bound)`` (modulo bias is immaterial here)."""
        return int.from_bytes(self.take(8), "little") % bound


@dataclass(frozen=True)
class SyntheticSegment:
    """One block of the synthetic package.

    ``payload`` is the block's full Intel HEX coverage, which equals
    ``erase_length`` when that is larger than ``data_length`` — the stock
    shape for the segments whose ``$DL`` stops short of the erase boundary.
    Only the first ``data_length`` bytes are ever streamed to the loader.
    """

    comment: str
    flash_start_addr: int
    data_length: int
    erase_length: int
    data_unit: int
    erase_wait_seconds: int
    payload: bytes
    version_text: str = ""
    setup_checksum: int | None = None

    @property
    def checksum_length(self) -> int:
        """``$CL``: the erase span, or zero for an unerased overlay."""
        return self.erase_length

    @property
    def streamed(self) -> bytes:
        """The exact ``$DL`` bytes the loader should receive."""
        return self.payload[: self.data_length]


def scaled_stock_segments(seed: int = 0xD75) -> tuple[SyntheticSegment, ...]:
    """Build the seven-segment scaled package.

    Sizes are the stock proportions divided by roughly 320 and rounded to
    whole ``$DU`` multiples, so every segment still spans several data
    units and the ``$EL > $DL`` segments still carry erase padding the host
    must trim.
    """
    rng = SeededByteStream(seed)

    def body(length: int) -> bytes:
        # Pseudorandom, not constant: a reassembly that drops, reorders, or
        # duplicates a chunk has to change the bytes to be caught.
        return rng.take(length)

    def padded(data_length: int, erase_length: int) -> bytes:
        return body(data_length) + b"\xff" * (erase_length - data_length)

    return (
        SyntheticSegment(
            comment="Program Data",
            flash_start_addr=0x6020_0000,
            data_length=8 * STOCK_DATA_UNIT,
            erase_length=8 * STOCK_DATA_UNIT,
            data_unit=STOCK_DATA_UNIT,
            erase_wait_seconds=6,
            payload=body(8 * STOCK_DATA_UNIT),
            version_text="V9.99.000      ",
        ),
        SyntheticSegment(
            comment="Portable Image",
            flash_start_addr=0x6060_0000,
            data_length=3 * STOCK_DATA_UNIT,
            erase_length=4 * STOCK_DATA_UNIT,
            data_unit=STOCK_DATA_UNIT,
            erase_wait_seconds=1,
            payload=padded(3 * STOCK_DATA_UNIT, 4 * STOCK_DATA_UNIT),
            version_text="1.00.02.00",
        ),
        SyntheticSegment(
            comment="DSP",
            flash_start_addr=0x60E0_0000,
            data_length=2 * STOCK_DATA_UNIT,
            erase_length=2 * STOCK_DATA_UNIT,
            data_unit=STOCK_DATA_UNIT,
            erase_wait_seconds=3,
            payload=body(2 * STOCK_DATA_UNIT),
            version_text="Dp1.01.00R00",
        ),
        SyntheticSegment(
            comment="Voice Announce",
            flash_start_addr=0x6160_0000,
            data_length=16 * STOCK_DATA_UNIT,
            erase_length=16 * STOCK_DATA_UNIT,
            data_unit=STOCK_DATA_UNIT,
            erase_wait_seconds=22,
            payload=body(16 * STOCK_DATA_UNIT),
        ),
        SyntheticSegment(
            comment="Font",
            flash_start_addr=0x6150_0000,
            data_length=5 * STOCK_DATA_UNIT,
            erase_length=6 * STOCK_DATA_UNIT,
            data_unit=STOCK_DATA_UNIT,
            erase_wait_seconds=2,
            payload=padded(5 * STOCK_DATA_UNIT, 6 * STOCK_DATA_UNIT),
            version_text="1.00",
        ),
        SyntheticSegment(
            comment="CHECKBYTES overlay",
            flash_start_addr=0x6020_0000 + CHECKBYTES_OFFSET,
            data_length=len(CHECKBYTES_D75_V103),
            erase_length=0,
            data_unit=len(CHECKBYTES_D75_V103),
            erase_wait_seconds=0,
            payload=CHECKBYTES_D75_V103,
            setup_checksum=CHECKBYTES_SETUP_CHECKSUM_D75_V103,
        ),
        SyntheticSegment(
            comment="FINAL_ZZZ overlay",
            flash_start_addr=0x6020_0000 + ZZZ_MARKER_OFFSET,
            data_length=len(FINAL_ZZZ_D75_V103),
            erase_length=0,
            data_unit=len(FINAL_ZZZ_D75_V103),
            erase_wait_seconds=0,
            payload=FINAL_ZZZ_D75_V103,
            setup_checksum=FINAL_ZZZ_SETUP_CHECKSUM_D75_V103,
        ),
    )


def build_plaintext_kex(
    segments: tuple[SyntheticSegment, ...],
    *,
    complete_code: int = 0x1DB0,
    always_flash: int = 1,
) -> bytes:
    """Render ``segments`` as a canonical plaintext ``.KEX`` file."""
    blocks = [
        kex.KexBlock(
            metadata=_block_metadata(
                segment,
                header=_package_header(
                    segment_count=len(segments),
                    complete_code=complete_code,
                    always_flash=always_flash,
                )
                if index == 0
                else (),
            ),
            records=_packed_records(segment.payload),
        )
        for index, segment in enumerate(segments)
    ]
    return kex.render(kex.Kex(blocks=tuple(blocks)))


def flash_plan(
    kex_bytes: bytes,
) -> tuple[list[SegmentDescriptor], dict[int, bytes]]:
    """Turn KEX file bytes into the pair ``FlashSession.flash_segments`` takes.

    This is exactly what ``cli._run_flash`` does with a real package: one
    descriptor per block from the block's ``$`` tags, and one flat payload
    per block from its Intel HEX records.
    """
    image = kex.parse_kex_bytes(kex_bytes)
    segments = [SegmentDescriptor.from_kex_block(block) for block in image.blocks]
    payloads = {
        index: intel_hex.parse(block.records).data
        for index, block in enumerate(image.blocks)
    }
    return segments, payloads


def _package_header(
    *,
    segment_count: int,
    complete_code: int,
    always_flash: int,
) -> tuple[bytes, ...]:
    """Return the ``#`` lines the stock package carries in its first block."""
    return (
        b"#TU=1",
        b"#BR=57600,0",
        b"#BR=115200,0",
        b"#BR=576000,1",
        b"#BR=1152000,1",
        f"#AF={always_flash}".encode("ascii"),
        f"#TT={_STOCK_TARGET_TYPE}".encode("ascii"),
        b"#TC=0",
        f"#FC=0x{complete_code:04X}".encode("ascii"),
        b'#FV="V9.99.000      "',
        f"#DN={segment_count}".encode("ascii"),
        b"#ED",
    )


def _block_metadata(
    segment: SyntheticSegment,
    *,
    header: tuple[bytes, ...],
) -> tuple[bytes, ...]:
    """Return the ``$``-tagged segment descriptor lines, in stock order."""
    if segment.setup_checksum is None:
        checksum = kex.firmware_checksum(segment.payload[: segment.checksum_length])
    else:
        checksum = segment.setup_checksum
    lines: list[bytes] = [*header, b";", b"; " + segment.comment.encode("ascii"), b";"]
    lines.extend(
        (
            b"$ST",
            f"$SA=0x{segment.flash_start_addr:08X}".encode("ascii"),
            f"$DU=0x{segment.data_unit:08X}".encode("ascii"),
            f"$DC=0x{segment.data_unit:08X}".encode("ascii"),
            f"$TT={_STOCK_TARGET_TYPE}".encode("ascii"),
            b"$CS=0x00000000",
            b"$VS=0x00000000",
            f"$VL=0x{len(segment.version_text):04X}".encode("ascii"),
            f"$DL=0x{segment.data_length:08X}".encode("ascii"),
            f"$EL=0x{segment.erase_length:08X}".encode("ascii"),
            f"$ET={segment.erase_wait_seconds}".encode("ascii"),
            f"$EM={max(segment.erase_wait_seconds * 4, 1)}".encode("ascii"),
            b"$CT=10",
            f"$CL=0x{segment.checksum_length:08X}".encode("ascii"),
            f"$CB=0x{checksum:04X}".encode("ascii"),
            f"$CA=0x{checksum:04X}".encode("ascii"),
            f'$VA="{segment.version_text}"'.encode("ascii"),
            b"$ED",
            b";",
            b"; Program Data",
            b";",
        )
    )
    return tuple(lines)


def _packed_records(image: bytes) -> bytes:
    """Encode ``image`` as the packed Intel HEX stream a KEX block holds.

    Emits an extended-linear-address record at every 64 KiB boundary (the
    stock artifact's shape), fixed-width data records, and one EOF.
    """
    out = bytearray()
    for base in range(0, max(len(image), 1), _ELA_SPAN):
        out.extend(_record(0x04, 0x0000, (base >> 16).to_bytes(2, "big")))
        window = image[base : base + _ELA_SPAN]
        for offset in range(0, len(window), _RECORD_WIDTH):
            out.extend(
                _record(
                    0x00,
                    offset,
                    window[offset : offset + _RECORD_WIDTH],
                )
            )
    out.extend(_record(0x01, 0x0000, b""))
    return bytes(out)


def _record(record_type: int, address: int, data: bytes) -> bytes:
    header = bytes([len(data), (address >> 8) & 0xFF, address & 0xFF, record_type])
    body = header + data
    return body + bytes([intel_hex.record_checksum(body)])
