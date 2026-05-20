# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under a `0.x` minor-version-as-breaking-change policy until `1.0.0`.

## [Unreleased]

## [0.2.0] - 2026-05-19

### Added

- `thd75-patch` CLI: builds a patched plaintext `.KEX` firmware file from
  the updater `.exe` by applying a user-selected patch
  (`--patch <name-or-path>`). Fixes the affected Intel HEX record
  checksums and recomputes the firmware block's `$CA` checksum.
  Pre-validates input paths before printing `[N/M]` progress, so a
  missing input fails cleanly without confusing half-progress output.
- `thd75-repack` CLI: builds a patched copy of the updater `.exe` itself.
  The same `--patch` selection mechanism is applied to the embedded
  firmware resource, re-ciphered, and spliced back in place as a
  same-length, in-place edit, so the patched updater flashes exactly
  like the official one. Pre-validates input paths.
- `thd75-list-patches` CLI: prints every patch in the built-in catalog
  (name, target firmware, byte changes, full RE rationale). Stdout is
  the real output (operators may pipe through `grep` / `head`); a
  `BrokenPipeError` from a closed downstream pipe is handled as a
  successful exit. Catalog read failures produce a clean error message.
- Patches-as-plug-ins library API: `thd75_fw.patch` exposes `ByteChange`,
  `Patch`, `PatchVerificationError`, `parse_patch`, `load_patch`, and
  `iter_catalog`. Patch files are TOML; the engine verifies every
  declared `expect` byte against the firmware before writing, so a
  patch written for V1.03 cannot silently mangle a different byte on
  V1.05. Construction-time validation rejects:
  - `ByteChange` with `bool` fields (TOML `true`/`false` would otherwise
    silently mean `1`/`0`), out-of-range bytes, negative offsets, and
    no-op changes (`expect == value`).
  - `Patch` with whitespace-only `name`/`description`, empty
    `target_firmware`, no `changes`, or duplicate offsets across
    `changes` (the engine's dict-by-offset dedup would otherwise
    silently drop the first of two changes with the same offset).
  - TOML documents with unknown top-level or per-change fields (typos
    like `targets_firmware` or `expects` were previously silently
    dropped); per-change errors include the `changes[N]:` index.
  `PatchVerificationError` carries structured `offset` / `expected` /
  `actual` attributes (keyword-only constructor) so callers can react
  to a mismatch programmatically without parsing the message string.
  `load_patch` distinguishes a path-looking argument that doesn't exist
  (e.g. `./typo.toml`, names containing `/` or `\`) from a catalog
  miss with separate error messages, and rejects duplicate `name`
  declarations across catalog files. `iter_catalog` yields patches
  sorted by their parsed `name`.
- `thd75_fw.kex` library module: decrypts the updater's embedded
  firmware resource to its plaintext `.KEX` form, applies a `Patch`,
  recomputes the affected Intel HEX record checksums and the firmware
  block's `$CA` checksum, and re-ciphers a patched copy back to the
  updater's on-disk format. Surfaces `intel_hex.parse(...).errors`
  rather than computing `$CA` over a silently-truncated image (the
  previous would-be brick-risk failure mode is now loud). Refuses when
  `$CS + $CL > len(image)` — Python slicing would otherwise truncate
  the checksummed region silently. Preserves the original `$CA=`
  line's hex digit width so the same-length splice into the updater
  `.exe` stays exact. Metadata-parse failures name the offending field
  (`$SA=`/`$CS=`/`$CL=`/`$CA=`) rather than raising a bare `int()`
  `ValueError`.
- `intel_hex` module gains five new public exports (in addition to the
  v0.1.0 surface of `ParseResult` / `RecordType` / `parse`):
  - `patch_image`: applies byte changes to a packed Intel HEX stream,
    verifying every `expect` byte before writing and recomputing the
    affected records' checksums. Defensive duplicate-offset rejection
    at this layer complements the construction-time check in
    `Patch.__post_init__`.
  - `iter_records`: walks a packed Intel HEX stream and yields a
    `Record` per record, tracking the extended-linear base address.
    Raises `ValueError` on a truncated record rather than silently
    stopping — symmetric with `parse()`, which surfaces truncation
    via `ParseResult.errors`.
  - `to_text_lines`: re-emits a packed stream as textual
    `:LLAAAATT...CC` lines (the form a plaintext `.KEX` uses).
  - `record_checksum`: computes the two's-complement checksum byte
    of a record payload, the invariant the radio's record loader
    relies on.
  - `Record`: frozen dataclass yielded by `iter_records`.
- Built-in catalog under `thd75_fw/patches/` shipping one seed entry,
  `pf-screen-capture`, which widens the front-panel PF-key decoders'
  lookup-table scan so the front-panel PF1/PF2 keys can be assigned
  Screen Capture (stock firmware allows that function only on the
  microphone PF keys).
- `file_cipher.encrypt_line`: new public function and `__all__` entry —
  the inverse of `decrypt_line`, needed for re-ciphering a patched
  resource line-by-line in `kex.patch_resource`.
- `docs/USAGE.md`: full per-CLI examples, the patch TOML schema, and
  Python library usage. Relocated from the README to keep the project
  landing page focused on the pitch, install, and section catalog.
- Hypothesis-based property tests in `tests/test_patch_properties.py`
  covering the `patch_image` length-preservation, targeted-change,
  record-checksum, and double-apply-trips-verification invariants.
- `tomli` runtime dependency on Python &lt; 3.11 (stdlib `tomllib` on
  3.11+).

### Changed

- README's `## Usage` section relocated to `docs/USAGE.md` to keep the
  README focused; the README retains a CLI overview table and a
  one-line example.
- `docs/FORMAT.md` section-catalog prose rewritten to distinguish
  *flash-relative offsets* (e.g. `0x00200000` — what the table actually
  contains) from *runtime physical addresses* (`0x60000000 + offset`),
  preventing patch authors from using the wrong address space.
- Source-distribution build policy tightened. `pyproject.toml`'s new
  `[tool.hatch.build.targets.sdist]` whitelists `src/`, `tests/`,
  `docs/FORMAT.md`, `docs/USAGE.md`, `loaders/`, and a handful of root
  files; cache/editor/local content (`.vscode/`, `.hypothesis/`,
  `dist/`, internal planning notes, local `*.exe` / `*.KEX` outputs)
  is now kept out of published artifacts. Sdist size dropped from
  ~81 MB to ~97 KB.
- `pyrightconfig.json` adds an `executionEnvironments` entry that
  disables `reportPrivateUsage` inside `tests/` only, so tests can
  exercise underscore-prefixed internals without weakening strictness
  for `src/`.

### Removed

- `resource.load(exe_path)` no longer auto-discovers a sibling
  `THD75_Updater_E.Resources.TH-D75_Firm_E.txt` next to the requested
  `.exe`. That shortcut — a documented v0.1.0 behavior (the docstring
  read *"Checks for a sibling ILSpy-extracted file first, then falls
  back to scanning the PE binary"*) — was a firmware-version footgun:
  a stale sibling from a prior extraction would silently override the
  requested updater, and the function's documented `FileNotFoundError`
  contract was violated when the sibling existed but `exe_path` did
  not. Pre-extracted resources must now be passed explicitly through
  the CLI's `--resource` flag. **This documented-behavior removal is
  the breaking change that motivates the 0.1 → 0.2 minor bump under
  the project's 0.x-minor-as-breaking policy.**

### Fixed

- `intel_hex.parse` now verifies every record's stored checksum byte
  against the recomputed value. Previously the parser read the checksum
  byte but never checked it; a corrupt original record would slip
  through and any downstream recomputation (e.g. after a patch) would
  silently mask the original corruption with a fresh-but-wrong
  checksum.
- `intel_hex.parse` now flags streams that contain data records but no
  End-Of-File marker, even when the stream ends cleanly at a record
  boundary with no trailing bytes. The radio's record loader relies on
  EOF; its absence is a truncation signal.
- `voice.load` validates monotonically non-decreasing cumulative
  offsets. Previously, a decreasing offset silently produced a prompt
  with negative size, negative duration, and empty data.
- `voice.load` validates that the index table ends at or before the
  documented audio-base offset. Previously, a header claiming an
  excessive entry count could overflow the table into the audio region
  and silently shadow the first audio bytes.
- `serial_cipher.encrypt`, `decrypt`, and `verify_round_trip` validate
  that `0 ≤ key ≤ 255` and reject `bool`. Previously, `key=-1` silently
  produced wrong roundtrips (Python's negative-int semantics propagate
  through the cipher), and `key=300` raised an opaque `IndexError` from
  inside the decrypt loop when the `rev[xored]` lookup overflowed.
- `thd75-serial-cipher --key` argument validates the 0..255 range at
  argparse time, producing a clean `argument --key: invalid value`
  line instead of a runtime error.
- CLI error handling for the v0.1.0 commands (`thd75-extract`,
  `thd75-extract-voice`, `thd75-extract-images`,
  `thd75-serial-cipher`) broadened from `FileNotFoundError` only to
  all `OSError` subclasses: `PermissionError`, `IsADirectoryError`,
  and `BrokenPipeError` now produce clean stderr messages with
  appropriate exit codes instead of Python tracebacks.
- The "Other tools in this package:" enumerations in `thd75-extract`,
  `thd75-extract-voice`, `thd75-extract-images`, and
  `thd75-serial-cipher` updated to list all seven shipped commands
  (previously stale at the v0.1.0 set of four).

## [0.1.0] - 2026-05-06

### Added

- `thd75-extract` CLI: extracts the 7 firmware sections from the official
  Kenwood TH-D75 updater `.exe` (FIRMWARE, IMAGE_DATA, DATA_00E0, DATA_0160,
  FONT_DATA, CHECKBYTES, FINAL_ZZZ).
- `thd75-extract-voice` CLI: extracts the 749-prompt voice database as 8 kHz
  mono WAV files (327 English, 356 Japanese, 66 Chinese).
- `thd75-extract-images` CLI: extracts 862 PNG images from the IMAGE_DATA
  section.
- `thd75-serial-cipher` CLI: encrypt/decrypt/selftest subcommands for the
  USB serial transfer cipher used during firmware updates.
- Library API: `thd75_fw.serial_cipher`, `thd75_fw.file_cipher`,
  `thd75_fw.intel_hex`, `thd75_fw.sections`, `thd75_fw.voice`,
  `thd75_fw.images`, `thd75_fw.resource`. All modules ship with `py.typed`;
  pyright/mypy strict clean.
- Two independent ciphers, implemented from scratch from decompiled
  `THD75_Updater_E.exe` v1.03.000: a file-storage cipher (rolling-key XOR
  + alternating inversion, key=39, step=39, continuous across all lines,
  producing Intel HEX records) and a serial-transfer cipher (256-byte
  substitution + XOR + 3-bit rotation, key=0x75, passthrough at key=0).
- 256-byte substitution table validated as a permutation at construction.
- Round-trip self-test (`thd75-serial-cipher selftest`) covering all 256
  byte values.
- GitHub Actions release workflow using PyPI trusted publishing (OIDC).
- `loaders/ida_thd75.py` and `loaders/ghidra_thd75.py`: drop-in setup
  scripts for IDA Pro and Ghidra that auto-configure ARM processor, segment
  permissions, exception-vector annotations, and rebase to the flash
  address parsed from the filename.
- `docs/FORMAT.md`: consolidated reference for cipher algorithms, section
  layout, OMAP-L138 memory map, and voice/image database structures.

[Unreleased]: https://github.com/swiftraccoon/thd75-fw/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/swiftraccoon/thd75-fw/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/swiftraccoon/thd75-fw/releases/tag/v0.1.0
