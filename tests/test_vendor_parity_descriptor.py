"""Vendor parity tests — segment descriptor (SETUP_SEGMENT payload).

The on-wire SETUP_SEGMENT (verb 0x40) payload is the serialized
`DataBlockInfo` C# struct, followed by the variable-length `$VA`
bytes. Layout extracted from vendor `DataBlockInfo.cs:5-41`:

    Offset  Field             Width  KEX tag  C# type
    0       mStartAddress     4      $SA      uint  (LE)
    4       mDataLength       4      $DL      uint  (LE)
    8       mEraseLength      4      $EL      uint  (LE)
    12      (alignment pad)   4      —        zero  (ulong needs 8-byte align)
    16      mTargetType       8      $TT      ulong (LE)
    24      mEraseTime        4      $ET      uint  (LE)
    28      mCheckSumBefore   2      $CB      ushort(LE)
    30      mCheckSumAfter    2      $CA      ushort(LE)
    32      mCheckSumCalcSA   4      $CS      uint  (LE)
    36      mCheckSumCalcLen  4      $CL      uint  (LE)
    40      mCheckSumCalcT    4      $CT      uint  (LE)
    44      mVersionStartAdd  4      $VS      uint  (LE)
    48      mVersionLength    4      $VL      uint  (LE)
    52      <appended bytes>  var    $VA      byte[]

Total fixed portion: 52 bytes.
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import pytest

from thd75_fw.flash.segments import (
    STOCK_TARGET_TYPE_MASK_D75_V103,
    SegmentDescriptor,
)
from thd75_fw.kex import KexBlock, parse_kex_bytes

# --- field count + names ------------------------------------------------


def test_segment_descriptor_field_set_is_exact() -> None:
    """vendor: DataBlockInfo.cs (12 struct fields) + $VA bytes + the host-only hints.

    Renamed from ``test_segment_descriptor_has_14_named_fields``, and the
    docstring's "exactly 15 fields" dropped: the name and the body had already
    disagreed with the assertion twice as host-only hints were added, which is
    a count in a name doing no work that the assertion below does not do
    better. The assertion is the specification; do not restate its size in
    prose.

    Spec quote: "14-field descriptor ($SA $DL $EL $ET $CB $CA $CS $CL $CT
    $VS $VL $VA + 2 flags)" — the extras beyond that are $TT (target type, an
    8-byte ulong) and the host-only hints $DU (chunk_size), $DC
    (checksum_chunk, official-host scheduling metadata) and $EM
    (erase_budget_seconds).

    $DC describes official-host acknowledged-writer scheduling, but is not
    serialized in SETUP and therefore cannot be a loader requirement. The
    hardware-proven recovery profile deliberately ignores it: stock metadata
    may declare ``$DU=$DC=1024`` while the host sends 256-byte packets followed
    by exactly one END_TRANSFER for the whole segment.

    $EM (``erase_budget_seconds``) was added for the same reason: the host's
    erase watchdog is armed from ``$EM``, not ``$ET``. ``f.cs``'s ``e()``
    calls ``b(h.k() * 1000)``, and ``h.k()`` returns the field the KEX reader
    fills from the ``"EM"`` tag; ``$ET`` goes to ``DataBlockInfo.mEraseTime``,
    which the host never reads back and only ships to the radio inside the
    52-byte descriptor. The comments that said the vendor arms an ``$ET``
    timer were wrong, and so was their ordering claim - ``c(2000)`` is armed
    first, before ``b()``. Stock V1.03 declares $ET 6/1/3/22/2/0/0 against
    $EM 23/5/10/89/8/1/1, so the two are not interchangeable.
    """
    field_names = {f.name for f in fields(SegmentDescriptor)}
    expected = {
        "flash_start_addr",  # $SA
        "data_length",  # $DL
        "erase_length",  # $EL
        "target_type_mask",  # $TT
        "erase_wait_seconds",  # $ET
        "expected_before_checksum",  # $CB
        "expected_after_checksum",  # $CA
        "checksum_start_offset",  # $CS
        "checksum_length",  # $CL
        "checksum_wait_seconds",  # $CT
        "version_start_offset",  # $VS
        "version_length",  # $VL
        "version_check_bytes",  # $VA (variable-length bytes)
        "chunk_size",  # $DU (host-only)
        "checksum_chunk",  # $DC (host-only; recovery ignores it)
        "erase_budget_seconds",  # $EM (host-only, erase watchdog budget)
    }
    assert field_names == expected, (
        f"Field-set mismatch. Missing: {expected - field_names}. "
        f"Unexpected: {field_names - expected}."
    )


# --- wire size ----------------------------------------------------------


def test_wire_size_is_52_bytes_when_va_is_empty() -> None:
    """vendor: DataBlockInfo struct layout = 52 bytes.

    That is 12 fields + 4 bytes alignment padding for the ulong target_type
    at offset 16.

    h.cs:g() computes `Marshal.SizeOf(DataBlockInfo) - 4` for the wire
    buffer; this confirms the C# struct sizeof minus the trailing 4-byte
    field. Our impl emits 52 bytes for the fixed portion plus any $VA bytes.
    """
    desc = SegmentDescriptor(
        flash_start_addr=0x60200000,
        data_length=0x10000,
        erase_length=0x10000,
        target_type_mask=0x02,
        erase_wait_seconds=2,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x1234,
        checksum_start_offset=0x60200000,
        checksum_length=0x10000,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    assert len(desc.to_wire()) == 52


def test_wire_size_is_52_plus_va_when_va_nonempty() -> None:
    """vendor: h.cs:g() appends $VA bytes via list.AddRange(h()).

    They go after the fixed struct portion.
    """
    va = b"\xde\xad\xbe\xef"
    desc = SegmentDescriptor(
        flash_start_addr=0x60200000,
        data_length=0x10000,
        erase_length=0x10000,
        target_type_mask=0x02,
        erase_wait_seconds=2,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x1234,
        checksum_start_offset=0x60200000,
        checksum_length=0x10000,
        checksum_wait_seconds=2,
        version_start_offset=0x60200100,
        version_length=4,
        version_check_bytes=va,
    )
    assert len(desc.to_wire()) == 52 + len(va)


def test_wire_rejects_va_length_mismatch() -> None:
    """Reject $VA bytes whose count disagrees with $VL.

    Vendor appends the quote-stripped $VA bytes after a prefix whose
    $VL field declares their exact count. A disagreement would shift the
    loader's frame parser, so reject it before device I/O.
    """
    with pytest.raises(ValueError, match="must equal version_length"):
        _ = SegmentDescriptor(
            flash_start_addr=0x60200000,
            data_length=0x10000,
            erase_length=0x10000,
            target_type_mask=0x02,
            erase_wait_seconds=2,
            expected_before_checksum=0xFFFF,
            expected_after_checksum=0x1234,
            checksum_start_offset=0x60200000,
            checksum_length=0x10000,
            checksum_wait_seconds=2,
            version_start_offset=0x60200100,
            version_length=4,
            version_check_bytes=b"ABC",
        )


# --- field-by-field byte layout -----------------------------------------


def test_wire_layout_field_offsets_and_widths() -> None:
    """vendor: DataBlockInfo.cs:5-41 + C# Sequential layout rules.

    Spot-check every field with a distinct byte pattern so we can verify
    its offset and width via direct slicing.
    """
    desc = SegmentDescriptor(
        flash_start_addr=0x11223344,  # $SA → offset 0..4
        data_length=0x55667788,  # $DL → offset 4..8
        erase_length=0x99AABBCC,  # $EL → offset 8..12
        # alignment padding at offset 12..16 (must be zero)
        target_type_mask=0x0102030405060708,  # $TT → offset 16..24
        erase_wait_seconds=0xDEADBEEF,  # $ET → offset 24..28
        expected_before_checksum=0xCAFE,  # $CB → offset 28..30
        expected_after_checksum=0xBABE,  # $CA → offset 30..32
        checksum_start_offset=0xF00DF00D,  # $CS → offset 32..36
        checksum_length=0xC0DEC0DE,  # $CL → offset 36..40
        checksum_wait_seconds=0xAA55AA55,  # $CT → offset 40..44
        version_start_offset=0x33CC33CC,  # $VS → offset 44..48
        version_length=4,  # $VL → offset 48..52
        version_check_bytes=b"ABCD",
    )
    wire = desc.to_wire()
    assert wire[0:4] == b"\x44\x33\x22\x11"  # LE u32
    assert wire[4:8] == b"\x88\x77\x66\x55"
    assert wire[8:12] == b"\xcc\xbb\xaa\x99"
    assert wire[12:16] == b"\x00\x00\x00\x00"  # alignment padding
    assert wire[16:24] == b"\x08\x07\x06\x05\x04\x03\x02\x01"  # LE u64
    assert wire[24:28] == b"\xef\xbe\xad\xde"
    assert wire[28:30] == b"\xfe\xca"  # LE u16
    assert wire[30:32] == b"\xbe\xba"
    assert wire[32:36] == b"\x0d\xf0\x0d\xf0"
    assert wire[36:40] == b"\xde\xc0\xde\xc0"
    assert wire[40:44] == b"\x55\xaa\x55\xaa"
    assert wire[44:48] == b"\xcc\x33\xcc\x33"
    assert wire[48:52] == b"\x04\x00\x00\x00"
    assert wire[52:] == b"ABCD"


def test_alignment_padding_is_four_zero_bytes_at_offset_12() -> None:
    """vendor: C# Sequential struct layout aligns ulong to 8-byte boundary.

    After three u32 fields (end of offset 12), 4 bytes of auto-inserted
    padding precede the u64 mTargetType at offset 16.

    Our to_wire() must emit these 4 zero bytes explicitly to mirror
    the vendor's byte layout. Without it, the descriptor would be 48
    bytes (not 52) and target_type_mask would be 4 bytes too early.
    """
    desc = SegmentDescriptor(
        flash_start_addr=0xFFFFFFFF,
        data_length=0xFFFFFFFF,
        erase_length=0xFFFFFFFF,
        target_type_mask=0xFFFFFFFFFFFFFFFF,
        erase_wait_seconds=0,
        expected_before_checksum=0,
        expected_after_checksum=0,
        checksum_start_offset=0,
        checksum_length=0,
        checksum_wait_seconds=0,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    wire = desc.to_wire()
    # Even with all-ones in surrounding fields, the padding stays zero.
    assert wire[12:16] == b"\x00\x00\x00\x00"


def test_target_type_mask_at_offset_16_is_u64_le() -> None:
    """vendor: ulong at DataBlockInfo.cs:17 — 8-byte, little-endian."""
    desc = SegmentDescriptor(
        flash_start_addr=0,
        data_length=0,
        erase_length=0,
        target_type_mask=0x0F,
        erase_wait_seconds=0,
        expected_before_checksum=0,
        expected_after_checksum=0,
        checksum_start_offset=0,
        checksum_length=0,
        checksum_wait_seconds=0,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    wire = desc.to_wire()
    assert wire[16:24] == b"\x0f\x00\x00\x00\x00\x00\x00\x00"


# --- flash-address conventions ------------------------------------------


def test_stock_d75_v103_segments_all_use_cpu_base_addresses() -> None:
    """vendor: f.cs reads $SA tags from KEX, stores in DataBlockInfo.a as-is.

    The KEX values for stock V1.03 are all 0x60xxxxxx — the CPU-visible
    NOR base + offset.

    RE finding: "$SA (descriptor flash_start_addr) is CPU-visible
    (0x60xxxxxx), NOT NOR-relative. Empirically the loader masked off
    high bits when we sent 0x00200000 in earlier tests, but matching
    stock is the predictable path."
    """
    # Stock V1.03 segment 0 (main firmware): $SA = 0x60200000
    desc = SegmentDescriptor(
        flash_start_addr=0x60200000,
        data_length=0x10000,
        erase_length=0x10000,
        target_type_mask=0x02,
        erase_wait_seconds=2,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x1234,
        checksum_start_offset=0x60200000,
        checksum_length=0x10000,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    wire = desc.to_wire()
    # $SA in LE bytes 0..4:
    assert wire[0:4] == b"\x00\x00\x20\x60"  # 0x60200000 LE


def test_descriptor_to_wire_is_deterministic() -> None:
    """vendor: implicit — Marshal.StructureToPtr produces deterministic bytes.

    The bytes follow from the given struct values. Our to_wire() must be
    deterministic too (idempotent, side-effect-free).
    """
    desc = SegmentDescriptor(
        flash_start_addr=0x60200000,
        data_length=0x10000,
        erase_length=0x10000,
        target_type_mask=0x02,
        erase_wait_seconds=2,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x1234,
        checksum_start_offset=0x60200000,
        checksum_length=0x10000,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
    )
    a = desc.to_wire()
    b = desc.to_wire()
    assert a == b


# --- $DU is host-only ---------------------------------------------------


def test_chunk_size_du_is_not_in_wire_format() -> None:
    """vendor: h.cs:g() does `sizeof(DataBlockInfo) - 4`.

    The DataBlockInfo struct contains NO chunk_size field — the chunk_size
    is per-segment but tracked separately on the host (n.cs writes it
    into every SEND_CHUNK header from `c().mKexFile.f()[k].j()`).

    RE finding: "$DU is host-side chunk-size hint, not part of the
    on-wire descriptor — the radio reads chunk_size from the SEND_CHUNK
    payload header (vendor stamps every chunk with the same value)."
    """
    desc_chunk_a = SegmentDescriptor(
        flash_start_addr=0x60200000,
        data_length=0x10000,
        erase_length=0x10000,
        target_type_mask=0x02,
        erase_wait_seconds=2,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x1234,
        checksum_start_offset=0x60200000,
        checksum_length=0x10000,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
        chunk_size=256,
        checksum_chunk=256,
    )
    desc_chunk_b = SegmentDescriptor(
        flash_start_addr=0x60200000,
        data_length=0x10000,
        erase_length=0x10000,
        target_type_mask=0x02,
        erase_wait_seconds=2,
        expected_before_checksum=0xFFFF,
        expected_after_checksum=0x1234,
        checksum_start_offset=0x60200000,
        checksum_length=0x10000,
        checksum_wait_seconds=2,
        version_start_offset=0,
        version_length=0,
        version_check_bytes=b"",
        chunk_size=1024,
        checksum_chunk=1024,
    )
    # Different $DU and $DC host hints → identical SETUP bytes in both
    # explicitly supported serializations.
    assert desc_chunk_a.to_wire() == desc_chunk_b.to_wire()
    assert desc_chunk_a.to_recovery_wire() == desc_chunk_b.to_recovery_wire()


# --- KEX tag wire-byte conventions --------------------------------------


def test_kex_tag_prefixes_top_level_hash_segment_dollar() -> None:
    """vendor: j.cs:b = '#', m_c = '$' (the two KEX-tag prefix characters).

    Top-level tags (#TC, #FC, #TU, #AF) use '#'; per-segment tags
    ($SA, $DL, ..., $VA, $DU) use '$'.
    """
    top_level_prefix = "#"
    segment_prefix = "$"
    assert ord(top_level_prefix) == 0x23
    assert ord(segment_prefix) == 0x24
    assert top_level_prefix != segment_prefix


# --- stock V1.03 whole-descriptor pin ------------------------------------

#: Exact ``$``-tagged metadata of all seven segments of the official D75 V1.03
#: KEX, transcribed verbatim. ``recovery/`` is gitignored (the repository never
#: redistributes Kenwood firmware bytes), so the descriptor metadata is
#: reproduced here to keep this pin runnable without the vendor artifact. No
#: firmware payload bytes are included.
STOCK_V103_SEGMENT_METADATA: tuple[tuple[bytes, ...], ...] = (
    (
        b"$ST",
        b"$SA=0x60200000",
        b"$DU=0x00000400",
        b"$DC=0x00000400",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x000000A0",
        b"$VL=0x000F",
        b"$DL=0x00280000",
        b"$EL=0x00280000",
        b"$ET=6",
        b"$EM=23",
        b"$CT=10",
        b"$CL=0x00280000",
        b"$CB=0x7EB9",
        b"$CA=0x3313",
        b'$VA="V1.03.000      "',
        b"$ED",
    ),
    (
        b"$ST",
        b"$SA=0x60600000",
        b"$DU=0x00000400",
        b"$DC=0x00000400",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x00000000",
        b"$VL=0x000A",
        b"$DL=0x00058000",
        b"$EL=0x00060000",
        b"$ET=1",
        b"$EM=5",
        b"$CT=10",
        b"$CL=0x00060000",
        b"$CB=0xB750",
        b"$CA=0xB750",
        b'$VA="1.00.02.00"',
        b"$ED",
    ),
    (
        b"$ST",
        b"$SA=0x60E00000",
        b"$DU=0x00000400",
        b"$DC=0x00000400",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x0005FFF0",
        b"$VL=0x000C",
        b"$DL=0x00100000",
        b"$EL=0x00100000",
        b"$ET=3",
        b"$EM=10",
        b"$CT=10",
        b"$CL=0x00100000",
        b"$CB=0xE7A7",
        b"$CA=0xE7A7",
        b'$VA="Dp1.01.00R00"',
        b"$ED",
    ),
    (
        b"$ST",
        b"$SA=0x61600000",
        b"$DU=0x00000400",
        b"$DC=0x00000400",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x00000000",
        b"$VL=0x0000",
        b"$DL=0x00A00000",
        b"$EL=0x00A00000",
        b"$ET=22",
        b"$EM=89",
        b"$CT=10",
        b"$CL=0x00A00000",
        b"$CB=0x04AE",
        b"$CA=0x04AE",
        b'$VA=""',
        b"$ED",
    ),
    (
        b"$ST",
        b"$SA=0x61500000",
        b"$DU=0x00000400",
        b"$DC=0x00000400",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x00000010",
        b"$VL=0x0004",
        b"$DL=0x000B8000",
        b"$EL=0x000C0000",
        b"$ET=2",
        b"$EM=8",
        b"$CT=10",
        b"$CL=0x000C0000",
        b"$CB=0xA464",
        b"$CA=0xA464",
        b'$VA="1.00"',
        b"$ED",
    ),
    (
        b"$ST",
        b"$SA=0x60200062",
        b"$DU=0x00000002",
        b"$DC=0x00000002",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x00000000",
        b"$VL=0x0000",
        b"$DL=0x00000002",
        b"$EL=0x00000000",
        b"$ET=0",
        b"$EM=1",
        b"$CT=10",
        b"$CL=0x00000000",
        b"$CB=0x9DB1",
        b"$CA=0x9DB1",
        b'$VA=""',
        b"$ED",
    ),
    (
        b"$ST",
        b"$SA=0x60200040",
        b"$DU=0x00000020",
        b"$DC=0x00000020",
        b'$TT="0F 00 00 00 00 00 00 00"',
        b"$CS=0x00000000",
        b"$VS=0x00000000",
        b"$VL=0x0000",
        b"$DL=0x00000020",
        b"$EL=0x00000000",
        b"$ET=0",
        b"$EM=1",
        b"$CT=10",
        b"$CL=0x00000000",
        b"$CB=0xCBA6",
        b"$CA=0xCBA6",
        b'$VA=""',
        b"$ED",
    ),
)

#: Exact SETUP_SEGMENT (verb 0x40) payload the official updater puts on the
#: wire for each stock V1.03 segment: the 52-byte marshaled ``DataBlockInfo``
#: followed by ``$VL`` bytes of ``$VA``.
#:
#: These are the bytes to change deliberately or not at all. Byte 16..23 is
#: ``$TT``; ``00 00 00 00 00 00 00 0f`` is the vendor's value and follows from
#: ``Convert.ToUInt64("0F00000000000000", 16)`` (``j.cs:1071``) marshaled
#: little-endian (``h.cs:333-339``). Reading the ``$TT`` text as a
#: little-endian byte array instead yields ``0f 00 00 00 00 00 00 00`` here,
#: which is the only respect in which this project and OpenWood ever differed
#: from the vendor on the wire.
STOCK_V103_SETUP_PAYLOADS: tuple[str, ...] = (
    "00002060000028000000280000000000000000000000000f06000000b97e1333"
    "00000000000028000a000000a00000000f00000056312e30332e303030202020"
    "202020",
    "00006060008005000000060000000000000000000000000f0100000050b750b7"
    "00000000000006000a000000000000000a000000312e30302e30322e3030",
    "0000e060000010000000100000000000000000000000000f03000000a7e7a7e7"
    "00000000000010000a000000f0ff05000c0000004470312e30312e3030523030",
    "000060610000a0000000a00000000000000000000000000f16000000ae04ae04"
    "000000000000a0000a0000000000000000000000",
    "0000506100800b0000000c0000000000000000000000000f0200000064a464a4"
    "0000000000000c000a0000001000000004000000312e3030",
    "62002060020000000000000000000000000000000000000f00000000b19db19d"
    "00000000000000000a0000000000000000000000",
    "40002060200000000000000000000000000000000000000f00000000a6cba6cb"
    "00000000000000000a0000000000000000000000",
)

#: The vendor KEX this pin was transcribed from. Gitignored, so the
#: cross-check below skips when the operator has not extracted it.
_STOCK_KEX_PATH = (
    Path(__file__).resolve().parents[1] / "recovery" / "TH-D75_V103_stock_plaintext.KEX"
)


@pytest.mark.parametrize("index", range(7))
def test_stock_v103_setup_payload_is_byte_exact(index: int) -> None:
    """Whole-payload pin for every stock V1.03 segment.

    A field-by-field test cannot catch a change that moves bytes between
    fields, and the SETUP payload is the one message whose contents decide
    what gets erased. Pin all of it.
    """
    block = KexBlock(metadata=STOCK_V103_SEGMENT_METADATA[index], records=b"")
    wire = SegmentDescriptor.from_kex_block(block).to_wire()
    assert wire.hex() == STOCK_V103_SETUP_PAYLOADS[index]


@pytest.mark.parametrize("index", range(7))
def test_stock_v103_target_type_field_matches_vendor_marshal(index: int) -> None:
    """vendor: ``$TT`` occupies offset 16..24.

    Every stock segment ships the same value.

    Called out separately from the whole-payload pin because these eight
    bytes are the ones this project once emitted byte-reversed.
    """
    block = KexBlock(metadata=STOCK_V103_SEGMENT_METADATA[index], records=b"")
    desc = SegmentDescriptor.from_kex_block(block)
    assert desc.target_type_mask == STOCK_TARGET_TYPE_MASK_D75_V103
    assert desc.to_wire()[16:24] == b"\x00\x00\x00\x00\x00\x00\x00\x0f"


@pytest.mark.parametrize("index", range(7))
def test_stock_v103_target_type_field_matches_proven_recovery_wire(index: int) -> None:
    """The empirical D75 recovery profile keeps vendor parity explicit.

    Both retained successful restores sent the stock mask as ``0f 00..``.
    Every descriptor byte outside that field remains identical to the vendor
    marshal.
    """
    block = KexBlock(metadata=STOCK_V103_SEGMENT_METADATA[index], records=b"")
    descriptor = SegmentDescriptor.from_kex_block(block)
    vendor = descriptor.to_wire()
    recovery = descriptor.to_recovery_wire()

    assert recovery[16:24] == b"\x0f\x00\x00\x00\x00\x00\x00\x00"
    assert recovery[:16] == vendor[:16]
    assert recovery[24:] == vendor[24:]


@pytest.mark.parametrize(
    ("index", "expected_erase_budget"),
    list(enumerate((23, 5, 10, 89, 8, 1, 1))),
)
def test_stock_v103_erase_budget_is_read_and_stays_off_the_wire(
    index: int,
    expected_erase_budget: int,
) -> None:
    """vendor: ``$EM`` arms the host's own erase watchdog and nothing else.

    ``f.cs``'s ``e()`` calls ``b(h.k() * 1000)`` before BEGIN_TRANSFER, and
    ``h.k()`` returns the KEX-reader field filled from the ``"EM"`` tag
    (``j.cs`` case 4 -> case 54). It is not a ``DataBlockInfo`` member, so the
    tag has no offset in the 52-byte payload; ``$ET`` is the erase number that
    does travel, at offset 24.

    The whole-payload pin above already fixes those bytes. This adds the two
    things that pin cannot state by itself: that the value is read at all, and
    that removing it changes nothing the radio sees.
    """
    metadata = STOCK_V103_SEGMENT_METADATA[index]
    descriptor = SegmentDescriptor.from_kex_block(
        KexBlock(metadata=metadata, records=b""),
    )

    assert descriptor.erase_budget_seconds == expected_erase_budget
    assert descriptor.to_wire()[24:28] == descriptor.erase_wait_seconds.to_bytes(
        4,
        "little",
    )

    without_em = tuple(line for line in metadata if not line.startswith(b"$EM="))
    stripped = SegmentDescriptor.from_kex_block(
        KexBlock(metadata=without_em, records=b""),
    )
    assert stripped.erase_budget_seconds is None
    assert stripped.to_wire() == descriptor.to_wire()


def test_stock_v103_pin_matches_the_real_vendor_kex() -> None:
    """The transcribed metadata above must equal the shipped artifact.

    Skips when ``recovery/`` has not been populated: that tree is gitignored
    and holds firmware the end user extracts from their own updater binary.
    """
    if not _STOCK_KEX_PATH.is_file():
        pytest.skip(f"vendor KEX not extracted at {_STOCK_KEX_PATH}")

    kex = parse_kex_bytes(_STOCK_KEX_PATH.read_bytes())
    assert len(kex.blocks) == len(STOCK_V103_SEGMENT_METADATA)
    for index, block in enumerate(kex.blocks):
        dollar_lines = tuple(ln for ln in block.metadata if ln.startswith(b"$"))
        assert dollar_lines == STOCK_V103_SEGMENT_METADATA[index]
        wire = SegmentDescriptor.from_kex_block(block).to_wire()
        assert wire.hex() == STOCK_V103_SETUP_PAYLOADS[index]
