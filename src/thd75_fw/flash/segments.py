"""Per-segment descriptor for the 0x40 SETUP_SEGMENT verb.

Maps the ``$``-tagged fields a .KEX file encodes (KEX format from
``thd75_fw.kex``) to the on-wire layout the D75 loader expects. The
descriptor field set, types, and on-wire ordering were extracted
from the ``DataBlockInfo`` struct used by the official Kenwood TH-D75
firmware updater.

Three parsed tags never reach the wire: ``$DU`` (packet-size hint), ``$DC``
(official-host scheduling metadata), and ``$EM`` (the official host's erase
watchdog budget). They remain on the dataclass to preserve the KEX metadata,
but both descriptor serializers ignore them and the hardware-proven recovery
path does not use ``$DC`` or ``$EM`` as transfer deadlines.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from thd75_fw.kex import firmware_checksum

if TYPE_CHECKING:
    from thd75_fw.kex import KexBlock


#: First NOR offset written by the stock D75 V1.03 updater. The two MiB
#: below it is the bootloader-capture target; its internal partitioning and
#: the exact D75 recovery consumers remain uncaptured.
MAIN_FIRMWARE_REGION_START: int = 0x0020_0000

#: CPU-visible base of the 256-Mbit NOR mapped through EMIFA CS2. Stock V1.03
#: descriptors use CPU addresses in this window; some older in-tree callers use
#: the equivalent NOR-relative offsets.
NOR_CPU_WINDOW_START: int = 0x6000_0000

#: One-past-the-end CPU address / relative size of the 32-MiB NOR window.
NOR_CPU_WINDOW_END: int = 0x6200_0000
NOR_RELATIVE_WINDOW_END: int = NOR_CPU_WINDOW_END - NOR_CPU_WINDOW_START

#: First NOR offset after the exact stock V1.03 main `$EL == $CL == 0x280000`
#: envelope. We intentionally do not expand raw writes to the larger linker
#: window that older project notes assumed.
MAIN_FIRMWARE_REGION_END: int = MAIN_FIRMWARE_REGION_START + 0x0028_0000

#: Byte offset within a main-firmware image where the 32-byte
#: ``FINAL_ZZZ`` marker lives. It is confirmed that the official D75
#: updater writes these bytes at this address in its final segment.
#: OpenWood's D74 analysis identifies the marker as the normal-boot
#: validity gate; that consumer behavior is not yet confirmed from a
#: captured D75 bootloader.
ZZZ_MARKER_OFFSET: int = 0x40

#: Length of the FINAL_ZZZ marker (matches the
#: ``firmware_image_finalization::final_zzz_str`` array size).
ZZZ_MARKER_LENGTH: int = 32

#: Exact final marker written by the stock D75 V1.03 updater.
FINAL_ZZZ_D75_V103: bytes = b"ZZzo..(-_- ) EX-5210 2022-07-20\x00"

#: CHECKBYTES are written by the stock updater as the penultimate segment.
CHECKBYTES_OFFSET: int = 0x62
CHECKBYTES_D75_V103: bytes = b"\xb0\x1d"

#: Whole finalization block occupied by FINAL_ZZZ, the erased completion
#: word, CHECKBYTES, and erased padding in the stock main image.
FINALIZATION_OFFSET: int = 0x40
FINALIZATION_LENGTH: int = 0x40

#: Smallest nonzero ``$EL``/``$CL`` quantum observed in every stock D75
#: V1.03 segment. This is updater-resource evidence, not a claim that the
#: uncaptured loader exposes this as a general sector-size API.
D75_V103_ERASE_ALIGNMENT: int = 0x0002_0000

#: Exact ``$EL == $CL`` envelope of the official D75 V1.03 main-firmware
#: segment. The audited raw profile deliberately uses this proven D75 main
#: boundary instead of inventing a one-sector loader profile.
D75_V103_MAIN_ERASE_CHECK_LENGTH: int = 0x0028_0000

#: Stock descriptor ``$CB == $CA`` values for the exact two finalization
#: overlays. Their algorithm is not the ordinary large-segment checksum,
#: so retain the values directly from the official V1.03 KEX.
CHECKBYTES_SETUP_CHECKSUM_D75_V103: int = 0x9DB1
FINAL_ZZZ_SETUP_CHECKSUM_D75_V103: int = 0xCBA6

#: Stock ``$TT`` for every segment of the official D75 V1.03 KEX, in the
#: vendor's integer convention: the KEX text ``"0F 00 00 00 00 00 00 00"``
#: is a most-significant-digit-first hex numeral.
#:
#: Marshaled little-endian by :meth:`SegmentDescriptor.to_wire`, this puts
#: ``0x0F`` at descriptor offset 23, matching the official updater.
#:
#: The hardware-proven OpenWood-compatible recovery path uses the opposite
#: byte order on the SETUP wire. That distinction is explicit in
#: :meth:`SegmentDescriptor.to_recovery_wire`; vendor reconstruction and the
#: empirical recovery control must not be silently conflated.
STOCK_TARGET_TYPE_MASK_D75_V103: int = 0x0F00_0000_0000_0000

#: Largest value of a u16 descriptor field (``$CB``, ``$CA``).
_U16_FIELD_MAX: Final[int] = 0xFFFF

#: Largest value of a u32 descriptor field (``$SA``, ``$DL``, ``$EL``, ``$ET``,
#: ``$CS``, ``$CL``, ``$CT``, ``$VS``, ``$VL``).
_U32_FIELD_MAX: Final[int] = 0xFFFFFFFF

#: Largest value of the u64 ``$TT`` target-type mask.
_U64_FIELD_MAX: Final[int] = 0xFFFFFFFFFFFFFFFF

#: Largest host-side ``$DU`` chunk size a descriptor may carry: the 2048-byte
#: SEND_CHUNK receiver limit that OpenWood's loader implementation documents,
#: which the flash session enforces as its own chunk-size ceiling too.
_MAX_CHUNK_SIZE: Final[int] = 2048

#: Hex digits per byte group in a quoted numeral such as ``$TT``'s
#: ``"0F 00 00 00 00 00 00 00"``.
_HEX_DIGITS_PER_BYTE: Final[int] = 2

#: Stock ``$ET`` of the V1.03 main-firmware segment: the erase wait, in
#: seconds, the loader is told about for the exact ``0x280000`` envelope.
_STOCK_MAIN_ERASE_WAIT_SECONDS: Final[int] = 6

#: Stock ``$EM`` of the same segment: the official host's own total erase
#: budget, in seconds. Host-side only; never serialized.
_STOCK_MAIN_ERASE_BUDGET_SECONDS: Final[int] = 23

#: Stock ``$CT`` of the same segment: the per-section verify wait, in seconds.
_STOCK_MAIN_CHECKSUM_WAIT_SECONDS: Final[int] = 10


def d75_v103_raw_erase_span(data_length: int) -> int:
    """Return the exact stock V1.03 main erase/check envelope."""
    if data_length <= 0:
        msg = f"raw image must be non-empty, got {data_length} bytes"
        raise ValueError(msg)
    if data_length > D75_V103_MAIN_ERASE_CHECK_LENGTH:
        msg = (
            "raw image exceeds the audited D75 V1.03 main data envelope "
            f"({data_length} > {D75_V103_MAIN_ERASE_CHECK_LENGTH})"
        )
        raise ValueError(msg)
    return D75_V103_MAIN_ERASE_CHECK_LENGTH


class BootloaderRegionError(ValueError):
    """Raised when a flash write would touch protected, uncaptured low NOR.

    The CLI translates this into an unconditional refusal. Full
    :class:`~thd75_fw.flash.session.FlashSession` plans independently apply
    :func:`validate_non_bootloader_nor_region`; raw-image callers can apply the
    narrower :func:`validate_main_firmware_region` before constructing a
    descriptor.
    """


def validate_non_bootloader_nor_region(flash_start_addr: int, length: int) -> None:
    """Reject an erase/program span that can touch low NOR or leave the NOR.

    The official V1.03 package legitimately updates several regions above the
    main image, so this session-level guard admits the complete 32-MiB NOR
    window in either vendor CPU-visible form (``0x60xxxxxx``) or legacy
    NOR-relative form. The uncaptured first two MiB remain unconditionally
    excluded. ``length`` must cover the larger of a descriptor's data and erase
    spans when this helper is used for a SETUP plan.
    """
    if length <= 0:
        msg = f"NOR erase/program span must be nonzero, got {length} bytes"
        raise BootloaderRegionError(msg)

    if NOR_CPU_WINDOW_START <= flash_start_addr < NOR_CPU_WINDOW_END:
        relative_start = flash_start_addr - NOR_CPU_WINDOW_START
    elif 0 <= flash_start_addr < NOR_RELATIVE_WINDOW_END:
        relative_start = flash_start_addr
    else:
        msg = (
            f"flash_start_addr 0x{flash_start_addr:08X} is outside the "
            "audited 32-MiB TH-D75 NOR window"
        )
        raise BootloaderRegionError(msg)

    relative_end = relative_start + length
    if relative_start < MAIN_FIRMWARE_REGION_START:
        msg = (
            f"NOR span 0x{relative_start:08X}..0x{relative_end:08X} overlaps "
            "the uncaptured low-NOR region; erase/program operations below "
            f"0x{MAIN_FIRMWARE_REGION_START:08X} are forbidden"
        )
        raise BootloaderRegionError(msg)
    if relative_end > NOR_RELATIVE_WINDOW_END:
        msg = (
            f"NOR span 0x{relative_start:08X}..0x{relative_end:08X} extends "
            "past the audited 32-MiB TH-D75 NOR window"
        )
        raise BootloaderRegionError(msg)


def validate_main_firmware_region(flash_start_addr: int, length: int) -> None:
    """Require ``[flash_start_addr, +length)`` to stay in the main-firmware region.

    Raises ``BootloaderRegionError`` if the write would either start
    below :data:`MAIN_FIRMWARE_REGION_START` (overlapping the
    uncaptured low-NOR region) or extend past
    :data:`MAIN_FIRMWARE_REGION_END` (spilling out of the slot).

    This is intentionally separate from
    :class:`SegmentDescriptor.__post_init__` — `.KEX` files supplied
    by the vendor include small finalization overlays within the main
    envelope, and the generic structure should preserve the exact KEX.
    The CLI calls this
    only for the ``--raw`` flat-binary path where the operator
    supplies the address themselves.
    """
    if flash_start_addr < MAIN_FIRMWARE_REGION_START:
        msg = (
            f"flash_start_addr 0x{flash_start_addr:08X} is below the "
            f"main-firmware region (starts at 0x{MAIN_FIRMWARE_REGION_START:08X}). "
            "Writing here would overlap the uncaptured low-NOR region. "
            "Raw writes to that region are outside this "
            "project's USB-C/Bluetooth-only scope."
        )
        raise BootloaderRegionError(msg)
    end = flash_start_addr + length
    if end > MAIN_FIRMWARE_REGION_END:
        msg = (
            f"flash write 0x{flash_start_addr:08X}..0x{end:08X} would "
            f"extend past the main-firmware region end "
            f"(0x{MAIN_FIRMWARE_REGION_END:08X}). Reduce the image size; "
            "raw writes outside the slot are not supported."
        )
        raise BootloaderRegionError(msg)


def _check_u32(name: str, value: int) -> None:
    if not 0 <= value <= _U32_FIELD_MAX:
        msg = f"{name} must fit in u32 (0..2**32-1), got {value}"
        raise ValueError(msg)


def _check_u64(name: str, value: int) -> None:
    if not 0 <= value <= _U64_FIELD_MAX:
        msg = f"{name} must fit in u64 (0..2**64-1), got {value}"
        raise ValueError(msg)


def _check_u16(name: str, value: int) -> None:
    if not 0 <= value <= _U16_FIELD_MAX:
        msg = f"{name} must fit in u16 (0..65535), got {value}"
        raise ValueError(msg)


@dataclass(frozen=True, slots=True, kw_only=True)
class FlatImageOptions:
    """Descriptor fields :meth:`SegmentDescriptor.for_flat_image` lets a caller set.

    The defaults mirror the stock V1.03 main-firmware segment in the vendor
    KEX, so ``FlatImageOptions()`` describes that exact ``0x280000`` envelope.

    Attributes:
        erase_wait_seconds: ``$ET``, the erase wait the loader is told about
            in the SETUP payload. Default 6 is the stock value for this exact
            ``0x280000`` envelope.
        erase_budget_seconds: ``$EM``, the host's own total erase budget.
            Never serialized. Default 23 is the stock value for the same
            envelope, and is deliberately far above ``$ET``: the vendor allows
            an erase almost four times its declared wait before it gives up.
        checksum_wait_seconds: Per-section verify budget; conservative default
            of 10 s.
        target_type_mask: ``$TT`` compatibility mask; default is the exact
            stock D75 V1.03 value :data:`STOCK_TARGET_TYPE_MASK_D75_V103`.
        erase_checksum_length: Explicit ``$EL``/``$CL`` span. When omitted it
            uses the exact official D75 V1.03 main-firmware envelope
            (``0x280000``). Bytes beyond ``$DL`` are modeled as erased
            ``0xFF`` for ``$CA``.

    """

    erase_wait_seconds: int = _STOCK_MAIN_ERASE_WAIT_SECONDS
    erase_budget_seconds: int = _STOCK_MAIN_ERASE_BUDGET_SECONDS
    checksum_wait_seconds: int = _STOCK_MAIN_CHECKSUM_WAIT_SECONDS
    target_type_mask: int = STOCK_TARGET_TYPE_MASK_D75_V103
    erase_checksum_length: int | None = None


#: The stock V1.03 main-firmware segment's settings, the
#: :meth:`SegmentDescriptor.for_flat_image` default.
_STOCK_MAIN_FLAT_IMAGE: Final[FlatImageOptions] = FlatImageOptions()


@dataclass(frozen=True, slots=True)
class SegmentDescriptor:
    """Payload of the 0x40 SETUP_SEGMENT verb (14 KEX-tagged fields)."""

    flash_start_addr: int  # u32  — $SA
    data_length: int  # u32  — $DL
    erase_length: int  # u32  — $EL
    target_type_mask: int  # u64  — $TT
    erase_wait_seconds: int  # u32  — $ET
    expected_before_checksum: int  # u16  — $CB
    expected_after_checksum: int  # u16  — $CA
    checksum_start_offset: int  # u32  — $CS
    checksum_length: int  # u32  — $CL
    checksum_wait_seconds: int  # u32  — $CT
    version_start_offset: int  # u32  — $VS
    version_length: int  # u32  — $VL
    version_check_bytes: bytes  # u8[] — $VA
    #: Host-side chunk-size hint from the KEX file's ``$DU`` tag.
    #: This is NOT part of the on-wire descriptor — the radio reads
    #: chunk_size from the SEND_CHUNK payload header (vendor stamps
    #: every chunk with the same value). ``$DU`` is the value the
    #: vendor uses for THIS segment: stock V1.03 uses ``1024`` for
    #: the five real-data segments and ``$DL`` (== single-chunk) for
    #: the two sub-sector overlay segments. ``None`` means "fall
    #: back to the FlashSession's ``chunk_size`` default" — used by
    #: ``for_flat_image`` / ``for_unerased_overlay`` constructors
    #: where there is no KEX to read $DU from.
    chunk_size: int | None = None

    #: Host-side data-unit cluster size from the KEX file's ``$DC`` tag.
    #:
    #: The official host uses it in its own acknowledged-writer scheduling,
    #: but it is not serialized in SETUP and therefore cannot be a loader
    #: requirement. The hardware-proven recovery profile deliberately ignores
    #: it: four 256-byte packets are valid even when the KEX declares
    #: ``$DU=$DC=1024``, followed by one END_TRANSFER for the whole segment.
    checksum_chunk: int | None = None

    #: Host-side erase budget from the KEX file's ``$EM`` tag.
    #:
    #: This is NOT part of the on-wire descriptor, and it is not a second
    #: spelling of ``$ET``. ``$ET`` is the erase-wait field inside the
    #: SETUP payload, so it is what the loader receives; ``$EM`` never
    #: leaves the host. The vendor arms its own erase watchdog with it
    #: (``b($EM * 1000)``) immediately before sending BEGIN_TRANSFER, so
    #: ``$EM`` is the total time the host allows one segment erase to take.
    #:
    #: The two are far apart in the stock V1.03 KEX, which is why the
    #: distinction matters: the ``0x280000`` main segment declares
    #: ``$ET=6`` against ``$EM=23``, and the 10 MiB segment declares
    #: ``$ET=22`` against ``$EM=89``. Budgeting a wait from ``$ET`` aborts
    #: a legal but slow erase after BEGIN_TRANSFER has already been sent.
    #:
    #: ``None`` means "no host budget declared", which is the case for
    #: descriptors built without a KEX. The value is retained for
    #: vendor-parity inspection; the proven recovery session instead gives
    #: every BEGIN response its ``$ET`` plus 30-second reference margin and
    #: deliberately does not impose this vendor-host total budget.
    erase_budget_seconds: int | None = None

    def __post_init__(self) -> None:
        """Validate every field against its wire width and host-side limits.

        Raises:
            ValueError: If a numeric field does not fit its u16/u32/u64 wire
                width, ``chunk_size`` is outside 1..2048,
                ``erase_budget_seconds`` is below 1, or ``version_check_bytes``
                is not exactly ``version_length`` bytes long.

        """
        _check_u32("flash_start_addr", self.flash_start_addr)
        _check_u32("data_length", self.data_length)
        _check_u32("erase_length", self.erase_length)
        _check_u64("target_type_mask", self.target_type_mask)
        _check_u32("erase_wait_seconds", self.erase_wait_seconds)
        _check_u16("expected_before_checksum", self.expected_before_checksum)
        _check_u16("expected_after_checksum", self.expected_after_checksum)
        _check_u32("checksum_start_offset", self.checksum_start_offset)
        _check_u32("checksum_length", self.checksum_length)
        _check_u32("checksum_wait_seconds", self.checksum_wait_seconds)
        _check_u32("version_start_offset", self.version_start_offset)
        _check_u32("version_length", self.version_length)
        if self.chunk_size is not None and not 1 <= self.chunk_size <= _MAX_CHUNK_SIZE:
            msg = f"chunk_size must be 1..2048 when present, got {self.chunk_size}"
            raise ValueError(msg)
        if self.erase_budget_seconds is not None and self.erase_budget_seconds < 1:
            msg = (
                "erase_budget_seconds must be at least 1 second when present, "
                f"got {self.erase_budget_seconds}; a zero budget aborts every "
                "erase before the loader can answer"
            )
            raise ValueError(msg)
        if len(self.version_check_bytes) != self.version_length:
            msg = (
                "version_check_bytes length must equal version_length "
                f"({len(self.version_check_bytes)} != {self.version_length})"
            )
            raise ValueError(msg)

    def to_wire(self) -> bytes:
        """Serialize the official-updater descriptor payload for verb 0x40."""
        return (
            self.flash_start_addr.to_bytes(4, "little")
            + self.data_length.to_bytes(4, "little")
            + self.erase_length.to_bytes(4, "little")
            + b"\x00\x00\x00\x00"  # u32 padding field
            + self.target_type_mask.to_bytes(8, "little")
            + self.erase_wait_seconds.to_bytes(4, "little")
            + self.expected_before_checksum.to_bytes(2, "little")
            + self.expected_after_checksum.to_bytes(2, "little")
            + self.checksum_start_offset.to_bytes(4, "little")
            + self.checksum_length.to_bytes(4, "little")
            + self.checksum_wait_seconds.to_bytes(4, "little")
            + self.version_start_offset.to_bytes(4, "little")
            + self.version_length.to_bytes(4, "little")
            + self.version_check_bytes
        )

    def to_recovery_wire(self) -> bytes:
        """Serialize the hardware-proven OpenWood-compatible SETUP payload.

        The official updater reconstruction and the empirical recovery control
        disagree only on the eight ``$TT`` bytes. ``to_wire()`` preserves the
        vendor marshal for parity tests. Both retained successful D75 restores
        instead put the KEX's displayed mask bytes on the wire in displayed
        order (stock: ``0f 00 00 00 00 00 00 00``), so the real-write session
        uses this explicit variant.
        """
        payload = bytearray(self.to_wire())
        payload[16:24] = reversed(payload[16:24])
        return bytes(payload)

    @classmethod
    def from_kex_block(cls, block: KexBlock) -> SegmentDescriptor:
        """Build a SegmentDescriptor from a parsed KexBlock.

        Parses the block's metadata lines (``$SA=...``, ``$DL=...``, etc.)
        into the typed fields. The KexBlock's ``records`` bytes are
        NOT part of the descriptor — those are the per-chunk payloads
        sent later via verb 0x43 SEND_CHUNK.

        ``$DU``, ``$DC``, and ``$EM`` are parsed here alongside the wire
        fields but stay host-side; :meth:`to_wire` does not serialize them.
        """
        tags = _parse_metadata_tags(block.metadata)
        return cls(
            flash_start_addr=_int_tag(tags, "SA", 0),
            data_length=_int_tag(tags, "DL", 0),
            erase_length=_int_tag(tags, "EL", 0),
            target_type_mask=_int_tag(tags, "TT", 0),
            erase_wait_seconds=_int_tag(tags, "ET", 0),
            expected_before_checksum=_int_tag(tags, "CB", 0xFFFF),
            expected_after_checksum=_int_tag(tags, "CA", 0),
            checksum_start_offset=_int_tag(tags, "CS", 0),
            checksum_length=_int_tag(tags, "CL", 0),
            checksum_wait_seconds=_int_tag(tags, "CT", 0),
            version_start_offset=_int_tag(tags, "VS", 0),
            version_length=_int_tag(tags, "VL", 0),
            version_check_bytes=_bytes_tag(tags, "VA_bytes"),
            chunk_size=_int_tag(tags, "DU", 0) or None,
            checksum_chunk=_int_tag(tags, "DC", 0) or None,
            erase_budget_seconds=_int_tag(tags, "EM", 0) or None,
        )

    @classmethod
    def for_flat_image(
        cls,
        *,
        flash_start_addr: int,
        image: bytes,
        options: FlatImageOptions = _STOCK_MAIN_FLAT_IMAGE,
    ) -> SegmentDescriptor:
        """Build a SegmentDescriptor for a raw flat binary.

        :class:`FlatImageOptions` defaults are chosen to mirror the stock V1.03
        main-firmware segment in the vendor KEX: ``target_type_mask =``
        :data:`STOCK_TARGET_TYPE_MASK_D75_V103` (the QUERY_TARGET
        compatibility bytes observed on stock hardware decode to
        ``0x0200000000000000`` in the vendor convention, and the two masks
        intersect),
        ``erase_wait_seconds = 6``, ``erase_budget_seconds = 23``, and
        ``checksum_wait_seconds = 10``. The official D75 host uses the
        first eight response bytes for ``#TT``/``$TT`` checks; bytes
        8..15 are opaque to that host and are not a second mask.

        Convenience constructor for shipping a custom payload (e.g.
        the ``firmware/dumper`` ``.bin``) as a single FLDM segment
        without a `.KEX` wrapper. Takes a flat byte array, computes
        the FLDM ``$CA`` 16-bit additive checksum over the post-write
        body plus erased trailing bytes, and
        fills in the descriptor fields the flasher needs to wrap the
        payload as a single segment the D75 loader will accept.

        Args:
            flash_start_addr: NOR flash address the image will be
                written to (e.g. ``0x00200000`` for the main-firmware
                slot).
            image: The flat binary bytes (e.g. the contents of
                ``firmware/.../dumper.bin``).
            options: ``$ET``, ``$EM``, ``$CT``, ``$TT`` and the ``$EL``/``$CL``
                span; the default is the stock V1.03 main-firmware segment.

        Returns:
            A fully-populated SegmentDescriptor with the right
            ``data_length``, ``erase_length``, ``expected_after_checksum``,
            and ``checksum_length`` for the supplied image. The image
            bytes themselves are sent later via verb 0x43 SEND_CHUNK
            (the descriptor only carries the metadata).

        """
        length = len(image)
        erase_checksum_length = options.erase_checksum_length
        span = (
            d75_v103_raw_erase_span(length)
            if erase_checksum_length is None
            else erase_checksum_length
        )
        if span < length:
            msg = (
                "erase_checksum_length cannot be shorter than image "
                f"({span} < {length})"
            )
            raise ValueError(msg)
        if span == 0:
            msg = "erase_checksum_length must be nonzero"
            raise ValueError(msg)
        checksum = firmware_checksum(image + b"\xff" * (span - length))
        return cls(
            flash_start_addr=flash_start_addr,
            data_length=length,
            erase_length=span,
            target_type_mask=options.target_type_mask,
            erase_wait_seconds=options.erase_wait_seconds,
            # A raw image has no declared predecessor, so no evidence-backed
            # current-image checksum exists for $CB. $VL=0 and raw #AF=1 make
            # this a forced update; $CA below is the value verified after it.
            expected_before_checksum=0xFFFF,
            expected_after_checksum=checksum,
            checksum_start_offset=0,
            checksum_length=span,
            checksum_wait_seconds=options.checksum_wait_seconds,
            version_start_offset=0,
            version_length=0,
            version_check_bytes=b"",
            erase_budget_seconds=options.erase_budget_seconds,
        )

    @classmethod
    def for_unerased_overlay(
        cls,
        *,
        flash_start_addr: int,
        image: bytes,
        target_type_mask: int = STOCK_TARGET_TYPE_MASK_D75_V103,
        setup_checksum: int | None = None,
    ) -> SegmentDescriptor:
        """Build a SegmentDescriptor that *programs without erasing*.

        Used for either post-body overlay in the three-stage stock-shaped
        plan: after the body segment has written the firmware with the whole
        finalization block erased, these descriptors write CHECKBYTES and then
        the 32 FINAL_ZZZ bytes. NOR flash supports
        programming 0xFF → arbitrary without erasing first (writes are
        only 1→0 bit transitions); ``erase_length = 0`` tells FLDM to
        skip the sector erase that would otherwise wipe the surrounding
        firmware bytes we just wrote.

        ``checksum_length = 0`` — empirically required for sub-sector
        overlay segments. The decompiled official Kenwood TH-D75
        firmware updater has explicit logic that **skips the
        VERIFY_SEGMENT step entirely when the descriptor's $CL field
        is zero**, and every overlay segment in the stock V1.03 KEX
        (the CHECKBYTES and FINAL_ZZZ segments) has $CL = 0. Setting
        $CL = length on an overlay forces the radio to checksum the
        flashed bytes and compare to our expected_after_checksum,
        which appears to use a different algorithm for sub-sector
        verifies than the standard $CA — we verified that
        firmware_checksum() matches every real-data segment's $CA in
        the stock KEX (segments 0-4) but produces a different value
        than what stock has for segments 5 and 6. Skipping the verify
        sidesteps that algorithm mismatch.

        The ``expected_before_checksum`` and ``expected_after_checksum``
        fields are set to the same value, matching the stock V1.03 overlay
        pattern. ``$CL = 0`` proves only that the official *host* skips the
        later VERIFY verb; the uncaptured target-side SETUP handler may still
        inspect these descriptor fields, so audited callers preserve the exact
        stock values.

        ``target_type_mask`` defaults to
        :data:`STOCK_TARGET_TYPE_MASK_D75_V103`, the value every segment in the
        stock V1.03 KEX carries. The QUERY_TARGET compatibility bytes observed
        on stock hardware decode to ``0x0200000000000000`` under the same
        convention, so the mask and the radio's reply intersect.
        """
        length = len(image)
        # See module-level NOTE above re: $CL=0 / $CB=$CA pattern. The
        # firmware_checksum supplies a deterministic generic default. The
        # audited raw plan passes the exact stock V1.03 overlay values because
        # target-side SETUP treatment of these fields remains uncaptured.
        csum = firmware_checksum(image) if setup_checksum is None else setup_checksum
        return cls(
            flash_start_addr=flash_start_addr,
            data_length=length,
            erase_length=0,  # ← the key "do not erase" signal
            target_type_mask=target_type_mask,
            erase_wait_seconds=0,
            expected_before_checksum=csum,
            expected_after_checksum=csum,
            checksum_start_offset=0,
            checksum_length=0,  # ← skip VERIFY (vendor pattern)
            checksum_wait_seconds=10,
            version_start_offset=0,
            version_length=0,
            # Stock writes this as ``$VA=""`` in the text KEX, but the
            # updater strips the quotes before serializing the descriptor.
            # With ``$VL=0`` no bytes follow the 52-byte fixed prefix.
            version_check_bytes=b"",
            # Tiny overlays must be written as a single SEND_CHUNK
            # frame because the session-default chunk_size (256)
            # never evenly divides 32-byte (ZZZ marker) or 2-byte
            # (CHECKBYTES) overlays. Vendor uses ``$DU = $DL`` on
            # every overlay segment in the stock V1.03 KEX (segments
            # 5 and 6) for the same reason.
            chunk_size=length,
        )


def split_for_safe_zzz_flash(
    *,
    flash_start_addr: int,
    image: bytes,
) -> list[tuple[SegmentDescriptor, bytes]]:
    """Split a stock-shaped D75 image into body/checkbytes/ZZZ segments.

    Mimics the safety pattern the official Kenwood TH-D75 firmware
    updater uses (verified from its KEX resources): write the main firmware
    with the complete ``0x40..0x7f`` finalization area erased, write the
    two CHECKBYTES at ``0x62``, then write the 32-byte FINAL_ZZZ marker at
    ``0x40`` last. The overlay descriptors retain the stock V1.03 values.

    D74 analysis says deferring FINAL_ZZZ keeps an interrupted image invalid
    and routes back to FLDM. The same consumer behavior remains a D75
    hypothesis, but matching the D75 vendor's exact ordering is the least
    speculative raw-image plan available.

    The input must carry the exact stock-shaped finalization block used by
    the audited dumper. Arbitrary or already-erased finalization bytes are
    rejected; callers must opt into a single-segment diagnostic plan instead
    of silently losing bytes during the split.

    Args:
        flash_start_addr: CPU-visible NOR address the image will be
            written to (e.g. ``0x60200000`` for the main-firmware
            slot — the OMAP-L138 maps NOR through its EMIFA chip-
            select at base ``0x60000000``, so the stock V1.03 KEX's
            $SA fields use the form ``0x60xxxxxx``). The CLI takes
            the NOR-relative form from the user and adds
            ``FLASH_BASE`` before calling this helper.
        image: The flat firmware bytes. The ZZZ marker, if present,
            must be at byte offset :data:`ZZZ_MARKER_OFFSET` of the
            image.

    Returns:
        Exactly three ``(descriptor, payload)`` tuples in vendor order:
        body, CHECKBYTES, FINAL_ZZZ.

    """
    finalization_end = FINALIZATION_OFFSET + FINALIZATION_LENGTH
    if len(image) < finalization_end:
        msg = (
            "raw image is too short to contain the audited D75 finalization "
            f"block (need at least {finalization_end} bytes, got {len(image)})"
        )
        raise ValueError(msg)

    expected_finalization = (
        FINAL_ZZZ_D75_V103 + b"\xff\xff" + CHECKBYTES_D75_V103 + b"\xff" * 28
    )
    actual_finalization = image[FINALIZATION_OFFSET:finalization_end]
    if actual_finalization != expected_finalization:
        msg = (
            "raw image finalization block does not match the audited D75 "
            "V1.03 shape; refusing the default body/CHECKBYTES/FINAL_ZZZ split"
        )
        raise ValueError(msg)

    # Vendor order: body with the whole finalization area erased, exact
    # CHECKBYTES overlay, then exact FINAL_ZZZ overlay last.
    body = bytearray(image)
    body[FINALIZATION_OFFSET:finalization_end] = b"\xff" * FINALIZATION_LENGTH
    body_bytes = bytes(body)
    body_desc = SegmentDescriptor.for_flat_image(
        flash_start_addr=flash_start_addr,
        image=body_bytes,
    )
    checkbytes_desc = SegmentDescriptor.for_unerased_overlay(
        flash_start_addr=flash_start_addr + CHECKBYTES_OFFSET,
        image=CHECKBYTES_D75_V103,
        setup_checksum=CHECKBYTES_SETUP_CHECKSUM_D75_V103,
    )
    zzz_desc = SegmentDescriptor.for_unerased_overlay(
        flash_start_addr=flash_start_addr + ZZZ_MARKER_OFFSET,
        image=FINAL_ZZZ_D75_V103,
        setup_checksum=FINAL_ZZZ_SETUP_CHECKSUM_D75_V103,
    )
    return [
        (body_desc, body_bytes),
        (checkbytes_desc, CHECKBYTES_D75_V103),
        (zzz_desc, FINAL_ZZZ_D75_V103),
    ]


def _int_tag(tags: dict[str, object], name: str, default: int) -> int:
    """Pull an int-valued tag; raise if present but not an int."""
    value = tags.get(name, default)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"$ {name} must be an integer in KEX metadata, got {value!r}"
    raise ValueError(msg)


def _bytes_tag(tags: dict[str, object], name: str) -> bytes:
    """Pull a bytes-valued key from parsed tags; an absent key reads as empty.

    :func:`_parse_metadata_tags` stores the unquoted ``$VA`` payload as bytes
    under ``"VA_bytes"``, but its generic path stores any other ``$TAG`` under
    the tag's own name, so a metadata line spelled literally ``$VA_bytes=...``
    can replace that entry with an integer or text. The value is therefore
    checked rather than trusted.

    Raises:
        ValueError: If the key holds anything other than bytes.

    """
    value = tags.get(name, b"")
    if isinstance(value, bytes):
        return value
    msg = f"parsed KEX metadata key {name!r} must hold bytes, got {value!r}"
    raise ValueError(msg)


def _parse_quoted_hex_u64(value_text: str) -> int | None:
    """Parse a Kenwood-style quoted hex numeral such as ``$TT``.

    Real stock KEX files carry the 64-bit ``$TT`` (target_type_mask) as
    ``"0F 00 00 00 00 00 00 00"``, a double-quoted string of space-separated
    hex digit pairs, not a plain integer literal. Returns the parsed unsigned
    integer, or ``None`` if the input doesn't match the expected shape.

    The official updater strips whitespace and evaluates the result as one
    most-significant-digit-first hex numeral. The empirical recovery wire uses
    a separate serialization method rather than changing this parser.

    Examples:
        ``"0F 00 00 00 00 00 00 00"`` → ``0x0F00_0000_0000_0000``
        ``"00 00 00 00 00 00 00 80"`` → ``0x80``

    """
    s = value_text.strip()
    if not (s.startswith('"') and s.endswith('"')):
        return None
    inner = s[1:-1].strip()
    if not inner:
        return None
    parts = inner.split()
    if not all(
        len(p) == _HEX_DIGITS_PER_BYTE and all(c in "0123456789abcdefABCDEF" for c in p)
        for p in parts
    ):
        return None
    try:
        return int.from_bytes(bytes(int(p, 16) for p in parts), "big")
    except ValueError:
        return None


def _parse_metadata_tags(metadata: tuple[bytes, ...]) -> dict[str, object]:
    """Parse ``$TAG=VALUE`` lines from a KexBlock's metadata.

    Returns a dict keyed by the bare tag (e.g. ``"SA"``). Value
    formats recognised:

    * Plain integers — ``$DL=0x280000`` or ``$ET=5``; accepts
      ``0x``-prefixed hex or decimal.
    * Quoted hex numerals — ``$TT="0F 00 00 00 00 00 00 00"``; the stock
      Kenwood KEX format for the 64-bit target_type_mask. Decoded via
      :func:`_parse_quoted_hex_u64`.
    * ``$VA`` — its quoted string contents are kept as bytes (under
      ``"VA_bytes"``), with the surrounding KEX quotes removed exactly
      as the official updater does; the original text remains under
      ``"VA"`` for diagnostics.

    Any unrecognised value is stored as the raw text for diagnostics.
    """
    out: dict[str, object] = {}
    for raw_line in metadata:
        try:
            line = raw_line.decode("ascii").strip()
        except UnicodeDecodeError:
            continue
        if not line.startswith("$") or "=" not in line:
            continue
        tag, _, value_text = line[1:].partition("=")
        value_text = value_text.strip()
        if tag == "VA":
            # Vendor ``p.cs`` recognizes a quoted value and stores the
            # text after trimming its surrounding quotes. ``j.cs`` then
            # appends UTF-8 bytes of that stripped value to the 52-byte
            # fixed descriptor. Keeping the quote characters here makes
            # the wire payload two bytes longer than ``$VL``.
            if value_text.startswith('"') and value_text.endswith('"'):
                va_text = value_text[1:-1]
            else:
                va_text = value_text
            out["VA_bytes"] = va_text.encode("utf-8")
            out["VA"] = value_text
            continue
        if not value_text:
            continue
        try:
            out[tag] = int(value_text, 0)  # base 0 = auto-detect 0x / decimal
            continue
        except ValueError:
            pass
        # Quoted hex numeral (real Kenwood KEX format for $TT and any
        # other 8-byte mask fields).
        as_hex_u64 = _parse_quoted_hex_u64(value_text)
        if as_hex_u64 is not None:
            out[tag] = as_hex_u64
            continue
        # Unrecognised — keep as string for diagnostics.
        out[tag] = value_text
    return out
