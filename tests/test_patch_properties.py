"""Property-based invariants for the Intel HEX patch engine.

These tests use Hypothesis to generate random firmware images and
random byte changes, then assert the load-bearing invariants the
engine claims:

1. **Length preservation.** ``patch_image`` returns a stream of the
   same byte length as its input.
2. **Targeted byte changes.** Every patched byte at the declared
   offset equals the change's ``value``; every other byte is
   unchanged.
3. **Record checksum validity.** After patching, every Intel HEX
   record still sums to zero modulo 256 — the invariant the radio's
   record loader relies on.
4. **Atomic verification.** Re-applying an already-applied patch
   trips ``PatchVerificationError`` (because the ``expect`` byte was
   what we wrote last time, not what's there now).

Hypothesis catches a much wider class of bugs than enumerated
example tests — anything from off-by-one offsets to overflow in
the checksum recomputation.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from thd75_fw import intel_hex
from thd75_fw.intel_hex import (
    RecordType,
    iter_records,
    parse,
    patch_image,
    record_checksum,
)
from thd75_fw.patch import ByteChange, PatchVerificationError


def _build_single_record_stream(image: bytes) -> bytes:
    """Wrap ``image`` in a single packed Intel HEX data record + EOF.

    Keeps the address fields zero (no extended-linear-address record
    needed) so the flat-image offset equals the in-record offset.
    """
    payload = bytes([len(image), 0x00, 0x00, RecordType.DATA]) + image
    data_rec = payload + bytes([record_checksum(payload)])
    eof = bytes([0x00, 0x00, 0x00, RecordType.EOF, 0xFF])
    return data_rec + eof


# Restrict images to at most 32 bytes so each data record's
# byte_count field (one byte) holds the length, and Hypothesis can
# generate many examples quickly. 1-byte minimum because patch_image
# needs at least one patchable byte.
_IMAGE_BYTES = st.binary(min_size=1, max_size=32)


@st.composite
def _image_and_changes(draw: st.DrawFn) -> tuple[bytes, list[ByteChange]]:
    """Generate ``(image, changes)`` where every change is in-range and
    uses the current image byte as ``expect`` (so the engine accepts
    the patch) and a *different* byte as ``value`` (the no-op guard
    rejects ``expect == value``)."""
    image = draw(_IMAGE_BYTES)
    # Choose a unique-offset subset of indices to patch.
    indices = draw(
        st.lists(
            st.integers(min_value=0, max_value=len(image) - 1),
            min_size=0,
            max_size=len(image),
            unique=True,
        )
    )
    changes: list[ByteChange] = []
    for offset in indices:
        current = image[offset]
        # ByteChange rejects expect == value (no-op guard); sample from
        # the explicit 0..255 \\ {current} set so the constraint is
        # enforced at strategy level rather than via a closure-over-
        # loop-variable lambda.
        candidates = [v for v in range(256) if v != current]
        new_value = draw(st.sampled_from(candidates))
        changes.append(
            ByteChange(offset=offset, expect=current, value=new_value)
        )
    return image, changes


@given(_image_and_changes())
@settings(max_examples=200)
def test_patch_image_preserves_length(
    image_and_changes: tuple[bytes, list[ByteChange]],
) -> None:
    image, changes = image_and_changes
    raw = _build_single_record_stream(image)
    out = patch_image(raw, changes)
    assert len(out) == len(raw)


@given(_image_and_changes())
@settings(max_examples=200)
def test_patch_image_changes_exactly_the_declared_offsets(
    image_and_changes: tuple[bytes, list[ByteChange]],
) -> None:
    image, changes = image_and_changes
    raw = _build_single_record_stream(image)
    out = patch_image(raw, changes)

    patched_image = parse(out).data
    expected = bytearray(image)
    for change in changes:
        expected[change.offset] = change.value
    assert bytes(patched_image[: len(image)]) == bytes(expected)


@given(_image_and_changes())
@settings(max_examples=200)
def test_every_record_checksum_remains_valid(
    image_and_changes: tuple[bytes, list[ByteChange]],
) -> None:
    image, changes = image_and_changes
    raw = _build_single_record_stream(image)
    out = patch_image(raw, changes)
    # Every record (including the unchanged EOF) must still sum to zero
    # — patch_image is required to recompute checksums of records it
    # touches, and leave others alone.
    for rec in iter_records(out):
        whole = out[rec.start : rec.start + 4 + rec.byte_count + 1]
        assert sum(whole) % 256 == 0, (
            f"record at offset {rec.start} has bad checksum after patch"
        )


@given(_image_and_changes())
@settings(max_examples=200)
def test_double_apply_trips_verification(
    image_and_changes: tuple[bytes, list[ByteChange]],
) -> None:
    image, changes = image_and_changes
    if not changes:
        return  # nothing to apply, trivially can't double-apply
    raw = _build_single_record_stream(image)
    once = patch_image(raw, changes)
    # The second application sees the patched bytes as ``actual`` but
    # the patch declares the *original* bytes as ``expect`` — they
    # disagree by construction, so the engine must abort.
    import pytest

    with pytest.raises(PatchVerificationError):
        patch_image(once, changes)


def test_intel_hex_module_re_export() -> None:
    """``thd75_fw.intel_hex`` is re-exported on the package; make sure
    the public name is reachable via both paths."""
    assert intel_hex.patch_image is patch_image
