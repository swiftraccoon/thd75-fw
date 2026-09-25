# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under a `0.x` minor-version-as-breaking-change policy until `1.0.0`.

## [Unreleased]

## [0.3.0] - 2026-09-24

### Added

- `thd75-theme` CLI and `thd75_fw.theme` package: derive a display theme patch
  from the stock FIRMWARE and IMAGE_DATA sections. Catalog entry
  `orange-on-black` re-skins menu 906's "White" option as deep orange
  (255,140,0) on black: White palette set, White text palette, 127 icon
  twins, two digit palettes inverted in place, label "Orange", and the
  IMAGE_DATA header version bumped to 1.00.02.01 so the loader writes the section.
  `build_theme` takes its naming and table settings as `ThemeOptions`, and
  `render_patch_toml` takes a `PatchTomlContent`.
- Patch TOML: `section` on changes and contexts, `[sections.<NAME>]` hash
  pins, `version` to assign a block's `$VA`, and equal-length hex
  `expect`/`value` runs that pin their window.
- `kex.section_image`, `kex.patch_kex_stack`, `kex.patch_resource_stack`;
  `thd75-patch` and `thd75-repack` accept repeated `--patch`, print the
  rendered KEX SHA-256 (patch) or the patched updater SHA-256 (repack), and
  summarise large patches per section. In a stack, only the first stage's
  `source_updater_sha256` is checked against the official updater; later
  stages pin the exe chain that built them and are reported as not checked.
- `thd75-flash` CLI: native cross-platform flasher for `.KEX` firmware
  images. Speaks the Kenwood FLDM serial protocol the official .NET
  updater uses, so a Windows VM is no longer required. Supports
  `--probe-only` (unlock handshake only, with no NOR-write verb) and
  `--probe-target` (unlock + ENTER + target identification, also with no
  NOR-write verb) for staged hardware bring-up. `--dry-run` performs
  image/plan validation entirely offline and never opens a serial device. Prints the
  official pre-flash checklist (battery, [PTT]+[1] programming-mode
  entry, USB cable) and the post-flash Full Reset reminder. Real writes keep
  pyserial's read timeout fixed instead of reassigning it before every ACK;
  on macOS that setter repeatedly invoked `IOSSIOSPEED` at the custom
  576000-baud rate, and holding the deadline brought the hardware-qualified
  V18 flash to 19.3 seconds while preserving direct-open, write/`tcdrain`,
  and exact-read ordering.
- `thd75_fw.flash` library: `FlashSession` orchestrator,
  `SegmentDescriptor` (the 14-field per-segment payload), `Verb` /
  `AckCode` / `NakSubcode` / `UnframedResponse` for the typed wire
  protocol, `Probe` / `HandshakeResult` for the encrypted-unlock
  exchange, `FlashError` / `FlashOutcome` / `TargetInfo` for typed
  results, and `FlashSessionOptions` / `FlashRunOptions` /
  `FlatImageOptions` for session, run and raw-image settings. Sans-io discipline: every layer except `serial_io.py` is
  pure and unit-testable; `pyserial` is the only I/O dependency. Rich-
  based progress UI lives in `thd75_fw.flash_ui`.
- Artifact-specific `--acknowledge-service-9r-write` safety gate for the exact
  experimental service-9r KEX. It is independent of `--yes` and cannot be used
  with stock/unpinned KEX, dry-run, raw, probe, or SETUP modes. Its attestation
  covers only the ordered pre-write prerequisites; the patched small-read and
  bounds check follows the write, and `9r-dump` repeats that gate before any
  full reads.
- Exact hash-pinned `normal-gm-nor-read-usb-recover` V18 artifact for the
  TH-D75 V1.03 USB mass-storage path. It corrects the advertised SD geometry,
  preserves storage ownership through the asynchronous USB handoff, services
  host reads with bounded stock CMD17 operations, and exposes fail-closed live
  telemetry. The tested TH-D75A/card/macOS combination automatically
  enumerated and passed 93 read operations over 2,604 sectors without a
  firmware failure or recovery.
- Catalog patches `normal-gm-ddr-read` and `normal-gm-nor-read`: turn the
  normal-mode CAT command `GM` into a bounded DDR or NOR reader, both
  hardware-qualified on TH-D75 V1.03, and the experimental
  `service-9r-nor-read` manifest with its dedicated write gate.
- Catalog patch `normal-gm-nor-read-usb-recover-azimuth`: the closed-loop
  Azimuth automation overlay (identity `V1.03.AZM`, ABI-3) on the exact
  V18 USB-storage recovery firmware; built deterministically by
  `scripts/build_radio_automation.py` and described in
  `firmware/RADIO_AUTOMATION.md`.
- The AZM firmware with the orange theme (`normal-gm-nor-read`,
  `normal-gm-nor-read-usb-recover`, `normal-gm-nor-read-usb-recover-azimuth`,
  `orange-on-black`) renders KEX SHA-256 `c9a42fabbb5accd6da0a459e0238b4e79ce13ce1126127d738e9c317f4487ce2` and is admitted to
  `thd75-flash` real writes as "TH-D75 V1.03.AZM Azimuth automation + orange-on-black"
  under the normal-GM fast plan. Hardware-confirmed on the TH-D75 on
  2026-09-24: FIRMWARE, IMAGE_DATA and both overlays wrote and verified
  through the fast plan, and the Orange option renders as designed; the
  log and wire trace are retained privately under `dist/`.
- `firmware/` low-NOR capture toolkit: the audited `capture_dump.py` receiver,
  the static `audit.py` checks, and the retained Rust dumper workspace (not
  cleared for flashing). These trees are not part of the distributed package.
- `docs/USAGE.md` documents stock-firmware recovery from a pinned plaintext
  KEX rendered from the official updater.
- Reverse-engineering scope for the flasher: the FLDM ("FldmLoader") serial
  protocol used to flash firmware: 11 verbs
  (`30 31 33 40 42 43 44 45 50 a0 a3`),
  `ab ab 00 [len:u32] [verb] [data] [cksum]` frame format with 8-bit
  additive checksum, XOR encryption derived per-session from the handshake
  exchange, and the 14-field SegmentDescriptor that maps directly to KEX-file
  `$`-tagged metadata. Protocol structure cross-referenced against community
  RE docs for related Kenwood handhelds; D75-specific deltas (magic word
  `"Thd75tw"`, XOR-key derivation formula) verified against the .NET updater
  decompilation. Subsequent D75 V1.03 hardware work established the 17-byte
  `TargetInfo` payload, a cleartext `FPROMOD` update path, and the stock entry
  sequence without `SELECT_TARGET`; model-specific boot-image semantics remain
  unresolved until the low D75 NOR is captured.

### Changed

- `patch_kex` and `patch_resource` patch every KEX block a change names,
  recomputing that block's `$CA`. FIRMWARE-only patches render unchanged.
- New runtime dependencies `pyserial` and `rich`, and two new console scripts
  (`thd75-flash`, `thd75-theme`). Under the `0.x` policy this is a minor bump.
- `serial_cipher.verify_round_trip` raises `AssertionError` explicitly, so the
  round-trip check also runs under `python -O`.
- Development: ruff runs every rule, mypy runs `--strict` with every optional
  error code and bans explicit `Any`, and pyright runs strict with every
  optional check; each exemption is documented in `pyproject.toml`. CI checks
  formatting, lint and types across `src`, `tests`, `scripts`, `firmware` and
  `loaders` with pinned tool versions, and runs the firmware tool tests.

### Fixed

- `thd75-extract --verify` without `--section` no longer reports PASS when the
  reference directory is missing or holds no `*.bin` files; verification now
  fails when there is nothing to compare.

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

[Unreleased]: https://github.com/swiftraccoon/thd75-fw/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/swiftraccoon/thd75-fw/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/swiftraccoon/thd75-fw/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/swiftraccoon/thd75-fw/releases/tag/v0.1.0
