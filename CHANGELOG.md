# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under a `0.x` minor-version-as-breaking-change policy until `1.0.0`.

When the first release is cut, the `[Unreleased]` section below will be
renamed to `[X.Y.Z] - YYYY-MM-DD` (with the actual tag date) and a
fresh empty `[Unreleased]` section started.

## [Unreleased]

### Added

- `thd75-extract` CLI: extracts the 7 firmware sections from the official Kenwood
  TH-D75 updater `.exe` (FIRMWARE, IMAGE_DATA, DATA_00E0, DATA_0160, FONT_DATA,
  CHECKBYTES, FINAL_ZZZ).
- `thd75-extract-voice` CLI: extracts the 749-prompt voice database as 8 kHz
  mono WAV files (327 English, 356 Japanese, 66 Chinese).
- `thd75-extract-images` CLI: extracts 862 PNG images from the IMAGE_DATA section.
- `thd75-serial-cipher` CLI: encrypt/decrypt/selftest subcommands for the USB
  serial transfer cipher used during firmware updates.
- Library API: `thd75_fw.serial_cipher`, `thd75_fw.file_cipher`,
  `thd75_fw.intel_hex`, `thd75_fw.sections`, `thd75_fw.voice`, `thd75_fw.images`,
  `thd75_fw.resource`. All modules ship with `py.typed`; pyright/mypy strict
  clean.
- 256-byte substitution table validated as a permutation at construction.
- Round-trip self-test (`thd75-serial-cipher selftest`) covering all 256 byte
  values.
- GitHub Actions release workflow using PyPI trusted publishing (OIDC).
- `loaders/ida_thd75.py` and `loaders/ghidra_thd75.py`: drop-in setup scripts
  for IDA Pro and Ghidra that auto-configure ARM processor, segment
  permissions, exception-vector annotations, and rebase to the flash address
  parsed from the filename.
- `docs/FORMAT.md`: consolidated reference for cipher algorithms, section
  layout, OMAP-L138 memory map, and voice/image database structures.

### Reverse-engineering scope

Both ciphers used by the updater are implemented from scratch based on
decompiled `THD75_Updater_E.exe` v1.03.000:

- **File-storage cipher**: rolling-key XOR + alternating inversion (key=39,
  step=39, continuous across all lines), producing Intel HEX records.
- **Serial transfer cipher**: 256-byte substitution + XOR + 3-bit rotation,
  key=0x75 (passthrough at key=0).
