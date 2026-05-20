# thd75-fw

[![CI](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml/badge.svg)](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/swiftraccoon/thd75-fw/graph/badge.svg?token=M7EJ9BQ8CG)](https://codecov.io/gh/swiftraccoon/thd75-fw)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Typed](https://img.shields.io/badge/typed-pyright%20strict-brightgreen.svg)](https://github.com/microsoft/pyright)

Firmware extraction and cipher tools for the Kenwood TH-D75 amateur radio transceiver.

## What This Does

Extracts the 7 firmware sections from the official Kenwood TH-D75 firmware updater executable, and applies user-defined patches to that firmware — as a plaintext `.KEX` image, or by repacking the updater `.exe` itself. Patches are TOML files: ship your own, or pick from the built-in catalog. Also provides encrypt/decrypt for the serial transfer cipher used during USB firmware updates.

**Two independent ciphers are implemented:**

| Cipher | Purpose | Algorithm |
|--------|---------|-----------|
| File-storage | Firmware embedded in updater `.exe` | Rolling-key XOR + alternating inversion (key=39, step=39) → Intel HEX |
| Serial transfer | USB packets during firmware update | 256-byte substitution + XOR + 3-bit rotation (key=0x75) |

## Install

With pip:

```bash
pip install thd75-fw
```

With uv:

```bash
uv tool install thd75-fw    # all seven CLIs globally
uv add thd75-fw             # or add as a project dependency
```

### Try without installing

```bash
uvx --from thd75-fw thd75-extract TH-D75_V103_e.exe ./out/
```

## Usage

The package installs seven CLIs and a typed Python library:

| CLI | Purpose |
|-----|---------|
| `thd75-extract` | Extract the 7 firmware sections from the updater `.exe` |
| `thd75-extract-voice` | Extract 749 voice prompts as 8 kHz mono WAV |
| `thd75-extract-images` | Extract 862 PNG display images |
| `thd75-patch` | Apply a patch and emit a plaintext `.KEX` image |
| `thd75-repack` | Apply a patch and emit a flashable updater `.exe` |
| `thd75-list-patches` | List the built-in patch catalog |
| `thd75-serial-cipher` | Encrypt/decrypt individual serial packets |

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
thd75-repack TH-D75_V103_e.exe out.exe --patch pf-screen-capture
```

**Reflashing firmware carries inherent risk.** Use a fully charged radio.

See [`docs/USAGE.md`](./docs/USAGE.md) for per-CLI examples, the patch TOML schema, and Python library usage.

## Extracted Sections

| Section | Flash Address | Size | Content |
|---------|--------------|------|---------|
| FIRMWARE | 0x00200000 | 2.5 MB | ARM926EJ-S executable (OMAP-L138) |
| CHECKBYTES | 0x00200062 | 2 B | Bootloader integrity checksum (0xB01D in V1.03) |
| FINAL_ZZZ | 0x00200040 | 32 B | Build marker confirming update completion |
| IMAGE_DATA | 0x00600000 | 384 KB | 862 PNG display images |
| DATA_00E0 | 0x00E00000 | 1.0 MB | TI C6748 AMBE2+ DSP firmware |
| FONT_DATA | 0x01500000 | 768 KB | Shift-JIS display fonts (16x16 and 24x24, 1-bit mono) |
| DATA_0160 | 0x01600000 | 10.0 MB | Voice prompt database (8-bit PCM, 8 kHz) |

CHECKBYTES and FINAL_ZZZ are patched into the FIRMWARE region's exception vector padding (0x40-0x7F) after the main firmware write completes.

## Reverse-engineering with IDA Pro / Ghidra

Drop-in setup scripts for both tools live under [`loaders/`](./loaders/).
They auto-configure the processor, segment permissions, and ARM
exception vectors so you don't have to manually figure out why a raw
`.bin` won't decode as ARM. See [`loaders/README.md`](./loaders/README.md)
for setup.

For format/protocol details (cipher algorithms, section layout, OMAP-L138
memory map, voice/image database structure), see [`docs/FORMAT.md`](./docs/FORMAT.md).

## Development

With pip (≥25.1):

```bash
pip install -e . --group dev
```

With uv:

```bash
uv sync
```

Both read the same `[dependency-groups]` table in `pyproject.toml`.

## Acknowledgments

This project builds on the prior reverse engineering work by [DD4CR](https://github.com/cr) on the Kenwood TH-D74: [github.com/cr/thd74](https://github.com/cr/thd74). Their documentation of the D74 firmware update protocol, `.NET` updater structure, and XOR permutation cipher provided the foundation for the D75 analysis. The D75 ciphers are evolutionary variations on the same cryptographic primitives (modular arithmetic, XOR, single-byte keys), though with different compositions and key schedules.

## Legal Disclaimer & Interoperability Notice

**This software is provided for amateur radio interoperability and educational research only.**

### Interoperability & Essentiality

The decryption and re-encryption implementations provided in this project are **required for interoperability** with the Kenwood TH-D75 transceiver. Without these technical measures, it is impossible for an owner of the device to:

1. **Analyze and verify** the firmware running on their own equipment (security research).
2. **Maintain and repair** their equipment by modifying or updating firmware outside of official, closed-source tools (right to repair).
3. **Develop independent software** that can interact with the radio's serial update protocol.

These implementations were derived solely through black-box analysis of the publicly available firmware updater binary to understand the undocumented protocols necessary for cross-platform interoperability.

### Reverse-Engineering Methodology

All analysis underlying this project was conducted under strict clean-room methodology:

- **Source material**: Solely the publicly distributed Windows firmware updater binary (`TH-D75_V*_e.exe`), obtained from JVCKENWOOD's official public download channels and lawfully accessible to any member of the public.
- **Tooling**: Only commercially licensed or open-source reverse engineering tools (e.g., IDA Pro, Ghidra, standard UNIX utilities). No Kenwood-proprietary tools, undisclosed utilities, or non-public debugging interfaces were used.
- **Non-use of confidential material**: No JVCKENWOOD source code, internal documentation, datasheets under non-disclosure agreement, leaked materials, or other confidential information was consulted at any stage of analysis or implementation.
- **No insider involvement**: No contributor to this project has any past or present employment, consulting relationship, contractual obligation, or non-disclosure agreement with JVCKENWOOD Corporation or any of its affiliates that bears on the subject matter of this work.

This methodology comports with the intermediate-copying-for-interoperability fair-use analysis established in *Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510 (9th Cir. 1992), and with prevailing clean-room reverse engineering practice.

### Non-Distribution of Copyrighted Firmware

This repository **does not contain, embed, redistribute, or mirror** any portion of Kenwood firmware, voice data, image data, fonts, DSP code, or other copyrighted material owned by JVCKENWOOD Corporation. The tools provided operate exclusively on firmware updater binaries that the end user has independently obtained from JVCKENWOOD's official public distribution channels and is legally entitled to use on hardware they own. No copyrighted Kenwood output is generated, transmitted, or stored by this project itself.

### Compliance & Rights

Modification of lawfully acquired software for use on hardware owned by the user, and reverse engineering performed for the purpose of achieving interoperability, are protected under:

**United States:**
- **17 U.S.C. §117(a)** — the owner of a copy of a computer program may make or authorize the making of adaptations of that program as an essential step in its utilization in conjunction with a machine.
- **17 U.S.C. §1201(f)** ([DMCA interoperability exception](https://www.law.cornell.edu/uscode/text/17/1201)) — circumvention of technological protection measures is permitted for the sole purpose of enabling interoperability of an independently created computer program with other programs.
- **U.S. Copyright Office, 9th Triennial §1201 Rulemaking (2024)**, codified at 37 C.F.R. §201.40 — renewed and expanded [exemptions](https://www.copyright.gov/1201/) covering (i) good-faith security research on lawfully acquired software-enabled devices and (ii) diagnosis, maintenance, and repair of lawfully acquired consumer devices, including those incorporating computer programs.
- **15 U.S.C. §2302(c)** (Magnuson-Moss Warranty Act) — a warrantor may not condition warranty coverage on the consumer's use of articles or services identified by brand or trade name unless provided without charge or by FTC waiver; consumer warranty rights are preserved when third-party software or repair is used.
- Case law: *Chamberlain Group, Inc. v. Skylink Techs., Inc.*, 381 F.3d 1178 (Fed. Cir. 2004) (a §1201 claim requires a reasonable nexus between the access sought and protected rights under the Copyright Act); *Lexmark Int'l, Inc. v. Static Control Components, Inc.*, 387 F.3d 522 (6th Cir. 2004) (technological measures that lock out competing interoperable products, without protecting copyrighted expression, are not shielded by §1201); *Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510 (9th Cir. 1992) (intermediate copying for the purpose of understanding unprotected functional elements is fair use); *Google LLC v. Oracle America, Inc.*, 593 U.S. 1 (2021) (transformative use of functional software interfaces is fair use).

**European Union:**
- [**Directive 2009/24/EC**](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024), **Articles 5(3) and 6** — the lawful acquirer of a program may observe, study, and test its functioning, and may decompile it where necessary to achieve interoperability with an independently created program.
- **Directive (EU) 2024/1799** (Right to Repair Directive, adopted 2024) and **Directive (EU) 2019/771** (Sale of Goods Directive) — consumer right to repair and continued use of lawfully acquired goods.

### User Responsibilities

- **Firmware ownership**: Users must obtain Kenwood firmware through legitimate means (e.g., from JVCKENWOOD's official website) and must possess the legal right to use and modify that firmware on hardware they own.
- **Non-infringement**: This tool is not intended to, and must not be used to, facilitate the unauthorized distribution of copyrighted works or to bypass access controls for the purpose of copyright infringement.
- **Regulatory compliance**: Users are solely responsible for ensuring any firmware modifications comply with applicable amateur radio regulations (e.g., FCC Part 97 in the United States; equivalent national regulations elsewhere). Transmitting outside one's licensed privileges — frequency, mode, bandwidth, or power — remains the user's sole responsibility regardless of what this software makes technically possible.

### Trademark Notice

"Kenwood" and "TH-D75" are trademarks of JVCKENWOOD Corporation. These marks are used here under **nominative fair use** solely to identify the equipment for which this interoperability tool is designed. This project is not affiliated with, endorsed by, or sponsored by JVCKENWOOD Corporation.

### Severability and Warranty

If any provision of this notice is held to be invalid or unenforceable in any jurisdiction, the remaining provisions shall remain in full force and effect, and the invalid provision shall be reformed only to the extent necessary to make it enforceable while preserving its intent.

**No warranty.** This software is provided "as is", without warranty of any kind, express or implied, including without limitation the warranties of merchantability, fitness for a particular purpose, and non-infringement. Reflashing radio firmware carries inherent risk and may render the device permanently inoperable. Use entirely at your own risk.

## License

[GPL-3.0](LICENSE)
