# thd75-fw

[![CI](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml/badge.svg)](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/swiftraccoon/thd75-fw/graph/badge.svg?token=M7EJ9BQ8CG)](https://codecov.io/gh/swiftraccoon/thd75-fw)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Typed](https://img.shields.io/badge/typed-pyright%20strict-brightgreen.svg)](https://github.com/microsoft/pyright)

Extract, inspect, patch, and flash firmware for the **Kenwood TH-D75** amateur
radio. The package provides nine command-line tools and a typed Python library,
including display-theme generation and a native USB firmware flasher.

Supply an official firmware updater obtained from Kenwood. The patch catalog
and hardware-qualified workflows target **TH-D75 V1.03**.

## Install

Requires Python 3.10 or later.

```bash
pip install thd75-fw
```

Or install all nine CLIs with uv:

```bash
uv tool install thd75-fw
```

For a Python project, use `uv add thd75-fw`.

## Quickstart

Extract the updater's firmware and data sections:

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
```

The output includes the main ARM firmware, display images, voice prompts,
fonts, and DSP data. See the [section reference][formats] for filenames and
layouts, and the [usage guide][usage] for extracting images and audio.

To try extraction without installing the tools:

```bash
uvx --from thd75-fw thd75-extract TH-D75_V103_e.exe ./extracted/
```

## Tools

| CLI | Purpose |
| --- | --- |
| `thd75-extract` | Extract firmware sections from the updater |
| `thd75-extract-images` | Extract display images as PNG |
| `thd75-extract-voice` | Extract voice prompts as WAV |
| `thd75-list-patches` | Inspect the built-in patch catalog |
| `thd75-patch` | Apply patches and produce a plaintext KEX |
| `thd75-repack` | Apply patches to a copy of the updater EXE |
| `thd75-theme` | Generate a display-theme patch |
| `thd75-flash` | Inspect a KEX offline or flash an admitted image over USB |
| `thd75-serial-cipher` | Encrypt/decrypt individual serial packets |

Use `COMMAND --help` for options. The [patch catalog][patches] explains each
patch, its required base, compatible stacks, and flashing availability.

**Flashing can leave the radio unusable.** Retain a verified stock recovery
image and read the [flashing and recovery guide][flashing] before a hardware
write. The native flasher admits only specific audited images; generating a
patch does not automatically make its output eligible for native flashing.

## Documentation

| Task | Guide |
| --- | --- |
| Use the CLIs or Python library | [Usage][usage] |
| Choose a patch or build a supported stack | [Patch catalog][patches] |
| Flash, recover stock firmware, or qualify a flash | [Flashing and recovery][flashing] |
| Write a patch manifest | [Patch format][patch-format] |
| Understand ciphers, containers, and section layouts | [Format reference][formats] |
| Load extracted binaries in IDA or Ghidra | [Loader setup][loaders] |
| Work with capture tools or experimental firmware | [Firmware workspace][firmware] |
| Inspect the Azimuth automation ABI | [Automation reference][automation] |
| See release changes | [Changelog][changelog] |

The `firmware/` and `scripts/` research tools require a repository checkout;
their setup and hardware status are documented separately from the installed
Python package.

## Development

From a repository checkout:

```bash
uv sync
make check
```

Tests include synthetic fixtures and integrations that use locally supplied
reference artifacts. The slow cases require `--run-slow`; see the
[development test notes][usage-tests].

## Credits and license

Built on [DD4CR's TH-D74 research](https://github.com/cr/thd74) and informed by
[OpenWood's flasher work](https://github.com/linux4life798/openwood). Related-model
research is distinguished from TH-D75 observations in the technical docs.

[GPL-3.0][license]. This project is not affiliated with or endorsed by
JVCKENWOOD. See the [legal and interoperability notice][legal] for the full
notice and warranty terms.

[usage]: https://github.com/swiftraccoon/thd75-fw/blob/main/docs/USAGE.md
[usage-tests]: https://github.com/swiftraccoon/thd75-fw/blob/main/docs/USAGE.md#development-tests
[patches]: https://github.com/swiftraccoon/thd75-fw/blob/main/src/thd75_fw/patches/README.md
[flashing]: https://github.com/swiftraccoon/thd75-fw/blob/main/docs/FLASHING.md
[patch-format]: https://github.com/swiftraccoon/thd75-fw/blob/main/docs/PATCH_FORMAT.md
[formats]: https://github.com/swiftraccoon/thd75-fw/blob/main/docs/FORMAT.md
[loaders]: https://github.com/swiftraccoon/thd75-fw/blob/main/loaders/README.md
[firmware]: https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/README.md
[automation]: https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/RADIO_AUTOMATION.md
[changelog]: https://github.com/swiftraccoon/thd75-fw/blob/main/CHANGELOG.md
[license]: https://github.com/swiftraccoon/thd75-fw/blob/main/LICENSE
[legal]: https://github.com/swiftraccoon/thd75-fw/blob/main/docs/LEGAL.md
