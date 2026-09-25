# Patch format

This reference describes TOML patch manifests and their validation. For
ready-made patches and complete build recipes, see the
[patch catalog](../src/thd75_fw/patches/README.md). For basic commands, see
[usage](USAGE.md#patch-firmware-plug-in-patches).

## Minimal manifest

A patch requires a nonempty name, description, and at least one byte change.
This illustrates the format; use a reviewed catalog entry for a complete
firmware patch:

```toml
name = "my-patch"
description = "What this patch changes and why."
target_firmware = "TH-D75 V1.03"
change_count = 1

[[contexts]]
offset = 0x10444
expect = "1B 29"

[[changes]]
offset = 0x10444
expect = 0x1B
value = 0x33
```

Apply a local manifest by passing its path:

```bash
thd75-patch TH-D75_V103_e.exe out.KEX --patch ./my-patch.toml
thd75-repack TH-D75_V103_e.exe out.exe --patch ./my-patch.toml
```

Offsets are relative to the selected section's flat extracted image. For
FIRMWARE, offset zero is the start of `FIRMWARE_0x00200000.bin`; it is not a
physical NOR or DDR address. See the [address reference](FORMAT.md#section-catalog).

## Top-level fields

| Field | Meaning |
| --- | --- |
| `name` | Required nonempty patch identifier. |
| `description` | Required nonempty explanation; may be a multiline TOML string. |
| `target_firmware` | Optional descriptive label. Actual compatibility is enforced by expected bytes, contexts, and hash pins. |
| `source_sha256` | SHA-256 of the complete source FIRMWARE image. |
| `result_sha256` | SHA-256 of the complete resulting FIRMWARE image. |
| `result_kex_sha256` | SHA-256 of the canonical plaintext KEX after this patch stage. |
| `source_updater_sha256` | SHA-256 of the input updater executable, subject to the stacking rules below. |
| `result_encrypted_resource_sha256` | SHA-256 of the resulting encrypted resource text when repacking. |
| `result_updater_sha256` | SHA-256 of the final updater executable for a single-patch repack. |
| `change_count` | Optional positive count of changed bytes, after expanding byte runs. |
| `contexts` | Array of source-byte windows, declared with `[[contexts]]`. |
| `changes` | Required array of changes, declared with `[[changes]]`. |
| `sections` | Optional tables of non-FIRMWARE section pins and version metadata. |

Hash values must be strings containing exactly 64 hexadecimal characters.
Unknown fields, blank required text, invalid field types, duplicate changes
at the same section and offset, and duplicate context starting offsets are
rejected. A declared `change_count` must match the expanded changes exactly.

Top-level FIRMWARE pins are checked even if all byte changes target another
section. Put FIRMWARE hashes at the top level; `[sections.FIRMWARE]` is rejected.

## Changes and contexts

Each `[[changes]]` entry requires `offset`, `expect`, and `value`, and may
specify `section` (default `FIRMWARE`). For single-byte changes, `expect` and
`value` are integers in `0..255` and must differ. Offsets are nonnegative
integers; booleans are not accepted as integer fields.

A `[[contexts]]` entry requires a nonnegative `offset` and a nonempty
hexadecimal `expect` string, with the same optional `section`. Contexts check
the entire source window before patching, including bytes that remain
unchanged. They are useful for checking complete instructions surrounding a
changed byte.

## Sections and byte runs

Changes and contexts may name any known section from the
[section catalog](FORMAT.md#section-catalog). `expect` and `value` may also be
equal-length hexadecimal strings. A run expands to one change per differing
byte and adds a context check for the whole source window; unchanged bytes
within the run do not count toward `change_count`.

```toml
[[changes]]
section = "IMAGE_DATA"
offset = 0x56F10
expect = "00 00 FF FF F8 1F"
value = "00 00 60 FC F8 1F"
```

This run changes two bytes. Do not add an explicit context at the same section
and starting offset as a run, because the run already creates that context.
An all-unchanged run is rejected.

A non-FIRMWARE section can declare `source_sha256`, `result_sha256`, or
`version` under `[sections.<NAME>]`. At least one must be present. For example,
this version-only table changes the IMAGE_DATA descriptor:

```toml
[sections.IMAGE_DATA]
version = "1.00.02.01"
```

Add complete 64-character `source_sha256` and `result_sha256` values to pin the
section's raw image before and after patching. A table does not replace the
requirement for at least one byte change elsewhere in the manifest.

`version` rewrites the block's quoted `$VA` metadata. It must be nonempty
ASCII and have exactly the same byte length as the original value. It does
not itself change the version bytes inside the section image: include those
changes in `[[changes]]` as needed. The loader compares `$VA` with the bytes at
`$SA + $VS`; keeping the image and descriptor consistent makes subsequent
SETUP checks recognize the installed version.

## Stacking patches

Repeat `--patch` on either command to apply compatible patches in the stated
order. Every stage sees the section images produced by the previous stage;
its expected bytes, contexts, and section source/result hashes are checked
at that point. Its plaintext KEX result pin is also checked on its own stage,
even when the requested final output is an updater executable.

Use the catalog's complete recipes for supported combinations. A patch intended
to stack should pin only the sections or artifacts its stage determines. For
example, `orange-on-black` pins IMAGE_DATA and the FIRMWARE windows it changes,
so it can follow compatible normal-GM firmware patches without requiring one
complete FIRMWARE hash.

Updater and encrypted-resource pins have output-specific rules:

| Check | `thd75-patch` | `thd75-repack` |
| --- | --- | --- |
| Source updater hash | First patch only, when reading an updater. | First patch only. |
| Source/result section hashes and contexts | Every stage. | Every stage. |
| Plaintext KEX result hash | Every stage. | Every stage. |
| Encrypted-resource result hash | Not produced or checked. | Every stage. |
| Result updater hash | Not produced or checked. | Checked for a single patch; not checked for a multi-patch stack. |

Later stages' updater source pins describe separately repacked intermediate
executables. A single stacked invocation does not construct those executable
intermediates, so it reports that their source updater pins are not checked.
Likewise, single-patch result updater pins do not describe a combined updater;
`thd75-repack` reports this when building a stack.

To verify an exact chain of separately repacked executables, run one
`thd75-repack` invocation per stage and feed each output into the next. Each
invocation can then verify that manifest's source and result updater pins.
When `thd75-patch --resource FILE` selects an extracted encrypted resource,
the positional updater is unused and no source updater hash is checked;
section and plaintext KEX checks still apply.

## Output guarantees and hardware admission

Both commands apply and validate patches in memory. They update affected
Intel HEX record checksums and each changed block's `$CA` checksum, and change
`$VA` only when a section version is declared. Repacking preserves the
resource's byte length so it can replace the original embedded resource.
The output is staged in a temporary file beside the destination, flushed and
fsynced, then atomically replaces that destination. A failed write leaves an
existing output intact.

Successful patching or a matching stage hash does not admit a new artifact to
native hardware writes. `thd75-flash` admits only the complete audited KEX
hashes listed under [supported artifacts](FLASHING.md#supported-artifacts).
A custom patch or stack remains dry-run-only until separately reviewed and
allowlisted. Follow the [flashing guide](FLASHING.md) for hardware operations.
