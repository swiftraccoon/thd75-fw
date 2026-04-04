# thd75-fw

[![CI](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml/badge.svg)](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Typed](https://img.shields.io/badge/typed-pyright%20strict-brightgreen.svg)](https://github.com/microsoft/pyright)

Firmware extraction and cipher tools for the Kenwood TH-D75 amateur radio transceiver.

## What This Does

Extracts the 7 firmware sections from the official Kenwood TH-D75 firmware updater executable. Also provides encrypt/decrypt for the serial transfer cipher used during USB firmware updates.

**Two independent ciphers are implemented:**

| Cipher | Purpose | Algorithm |
|--------|---------|-----------|
| File-storage | Firmware embedded in updater `.exe` | Rolling-key XOR + alternating inversion (key=39, step=39) → Intel HEX |
| Serial transfer | USB packets during firmware update | 256-byte substitution + XOR + 3-bit rotation (key=0x75) |

## Install

```bash
pip install -e .
```

## Usage

### Extract firmware from updater

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
```

### Verify against known-good files

```bash
thd75-extract TH-D75_V103_e.exe ./out/ --verify ./known-good/
```

### Serial cipher (encrypt/decrypt individual packets)

```bash
thd75-serial-cipher decrypt packet.bin -o plain.bin
thd75-serial-cipher encrypt plain.bin -o packet.bin
thd75-serial-cipher verify
```

### Extract voice prompts as WAV

```bash
thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/
thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/ --lang en
```

Extracts 749 voice prompts (327 English, 356 Japanese, 66 Chinese) as 8 kHz mono WAV files.

### Extract display images as PNG

```bash
thd75-extract-images ./extracted/IMAGE_DATA_0x00600000.bin ./images/
```

Extracts 862 PNG images (APRS symbols, status icons, splash screens, UI elements).

## Extracted Sections

| Section | Flash Address | Size | Content |
|---------|--------------|------|---------|
| FIRMWARE | 0x00200000 | 2.5 MB | ARM926EJ-S executable (OMAP-L138) |
| CHECKBYTES | 0x00200062 | 2 B | Bootloader integrity checksum (0xB01D in V1.03) |
| FINAL_ZZZ | 0x00200040 | 32 B | Build marker confirming update completion |
| IMAGE_DATA | 0x00600000 | 357 KB | 862 PNG display images |
| DATA_00E0 | 0x00E00000 | 1.0 MB | TI C6748 AMBE2+ DSP firmware |
| FONT_DATA | 0x01500000 | 736 KB | Shift-JIS display fonts (6,962 glyphs) |
| DATA_0160 | 0x01600000 | 10.0 MB | Voice prompt database (8-bit PCM, 8 kHz) |

CHECKBYTES and FINAL_ZZZ are patched into the FIRMWARE region's exception vector padding (0x40-0x7F) after the main firmware write completes.

## Legal Disclaimer

**This software is provided for amateur radio interoperability and educational purposes only.**

This project reverse-engineers the encryption used by the Kenwood TH-D75 firmware updater to enable firmware analysis, interoperability research, and amateur radio experimentation. It does not contain, distribute, or facilitate unauthorized access to any copyrighted firmware. Users are responsible for obtaining firmware images through legitimate means.

Reverse engineering for interoperability is protected under:
- **United States**: DMCA §1201(f) (reverse engineering for interoperability); *Sega v. Accolade* (9th Cir. 1992); *Oracle v. Google* (S.Ct. 2021)
- **European Union**: Directive 2009/24/EC, Article 6 (decompilation for interoperability)

"Kenwood" and "TH-D75" are trademarks of JVCKENWOOD Corporation. This project is not affiliated with, endorsed by, or sponsored by JVCKENWOOD Corporation.

**No warranty.** This software is provided "as is" without warranty of any kind. Use at your own risk. Do not use this software to modify radio firmware in ways that violate FCC Part 97 or your local amateur radio regulations.

## Acknowledgments

This project builds on the prior reverse engineering work by [DD4CR](https://github.com/cr) on the Kenwood TH-D74: [github.com/cr/thd74](https://github.com/cr/thd74). Their documentation of the D74 firmware update protocol, `.NET` updater structure, and XOR permutation cipher provided the foundation for the D75 analysis. The D75 ciphers are evolutionary variations on the same cryptographic primitives (modular arithmetic, XOR, single-byte keys), though with different compositions and key schedules.

## License

[GPL-3.0](LICENSE)
