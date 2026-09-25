# Usage

Worked examples for the nine CLIs and Python library. Start with the
[installation instructions](../README.md#install); every CLI also provides
`--help`. Examples below work with a local copy of the official V1.03 updater
and create files without contacting the radio.

For patch choices and complete build recipes, use the
[patch catalog](../src/thd75_fw/patches/README.md). For hardware writes and
recovery, use the [flashing guide](FLASHING.md).

## Extract firmware from updater

Extract all seven sections, or select one section:

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
thd75-extract TH-D75_V103_e.exe ./firmware-only/ --section FIRMWARE
```

Output filenames contain the section name and flash-relative offset. See the
[section catalog](FORMAT.md#section-catalog) for their contents and addresses.
Stock V1.03 has four nonstandard Intel HEX checksum bytes; full extraction
accepts only the exact official final-overlay streams described in the
[format reference](FORMAT.md#encrypted-resource-versus-external-kex).
Scoped extraction still checks every block's address metadata and rejects any
checksum error in the selected section.

## Verify against known-good files

```bash
thd75-extract TH-D75_V103_e.exe ./out/ --verify ./known-good/
```

The reference directory must exist and contain `.bin` files with the standard
extracted filenames. The command compares each reference file byte-for-byte
with its extracted counterpart and fails on missing or differing output.
With `--section FIRMWARE`, it compares only `FIRMWARE_0x00200000.bin` and
requires that reference file to exist.

## Serial cipher (encrypt/decrypt individual packets)

```bash
thd75-serial-cipher decrypt packet.bin -o plain.bin
thd75-serial-cipher encrypt plain.bin -o packet.bin
thd75-serial-cipher selftest
```

These commands process saved packet bytes. The serial transfer cipher and the
updater's file-storage cipher are [independent formats](FORMAT.md#the-two-ciphers).

## Extract voice prompts as WAV

```bash
thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/
thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/ --lang en
```

Stock V1.03 contains 749 prompts: 327 English, 356 Japanese, and 66 Chinese.
The output is 8 kHz mono WAV.

## Extract display images as PNG

```bash
thd75-extract-images ./extracted/IMAGE_DATA_0x00600000.bin ./images/
```

Stock V1.03 contains 862 PNG images, including APRS symbols, status icons,
splash screens, and UI elements.

## Patch firmware (plug-in patches)

List the installed catalog, then build a plaintext KEX for offline inspection:

```bash
thd75-list-patches
thd75-patch TH-D75_V103_e.exe out.KEX --patch pf-screen-capture
thd75-flash --dry-run out.KEX
```

`--dry-run` validates the image and prints its hashes and resolved flash plan
without opening a serial device. The example `pf-screen-capture` KEX is
currently dry-run-only in the native flasher. Build availability and native
hardware-write admission are separate; see
[supported artifacts](FLASHING.md#supported-artifacts).

To produce a patched updater executable instead:

```bash
thd75-repack TH-D75_V103_e.exe out.exe --patch pf-screen-capture
```

Both commands accept a catalog name or a local TOML path:

```bash
thd75-patch TH-D75_V103_e.exe out.KEX --patch ./my-patch.toml
```

Patches check the expected source bytes before changing them. They may also
pin complete sections, instruction contexts, and output hashes. For the TOML
schema and the checks performed by each command, see
[patch format](PATCH_FORMAT.md). Repeat `--patch` to apply a compatible stack
in order; use the [catalog's build recipes](../src/thd75_fw/patches/README.md)
for the required dependencies.

External KEX files contain byte-oriented plaintext metadata and literal Intel
HEX lines. Renaming an encrypted updater resource to `.KEX` does not convert
it; see the [container reference](FORMAT.md#encrypted-resource-versus-external-kex).
For an actual radio write, follow the
[hardware-write procedure](FLASHING.md#hardware-writes).

## Recover with stock firmware

Follow [stock recovery](FLASHING.md#stock-recovery) to generate and validate the
pinned recovery artifact, enter programming mode, and restore stock firmware.
The separate [qualification procedure](FLASHING.md#qualification) is for
validating the native flasher itself.

## Generate a display theme

Generate a patch from the stock updater, or from its two extracted sections:

```bash
thd75-theme orange-on-black.toml --exe TH-D75_V103_e.exe
thd75-theme amber.toml --exe TH-D75_V103_e.exe --rgb 255,191,0 --name amber-on-black
thd75-theme out.toml \
  --firmware ./extracted/FIRMWARE_0x00200000.bin \
  --image-data ./extracted/IMAGE_DATA_0x00600000.bin
```

The tool recolours menu 906's White scheme: palettes, text, icon twins, and the
two digit palettes. It currently relabels the option "Orange" even when a
custom colour or patch name is supplied; MCP-D75 still labels it "White".
It bumps IMAGE_DATA's version to `1.00.02.01` so the loader can detect the
changed section. The generated TOML pins IMAGE_DATA and checks the FIRMWARE
bytes it changes, allowing compatible firmware stacks.

Apply the generated patch with `thd75-patch` or `thd75-repack` as above.
A custom theme or stack needs its own native-write admission; the shipped
orange theme's supported combination is listed in the
[patch catalog](../src/thd75_fw/patches/README.md).

## Use as a Python library

The same primitives that power the CLIs are importable:

```python
from pathlib import Path
from thd75_fw.serial_cipher import encrypt, decrypt
from thd75_fw.sections import lookup_by_address
from thd75_fw import voice

ciphertext = encrypt(b"hello world")
assert decrypt(ciphertext) == b"hello world"

info = lookup_by_address(0x01600000)
assert info is not None and info.name == "DATA_0160"

data = Path("./extracted/DATA_0160_0x01600000.bin").read_bytes()
database = voice.load(data)
print(f"{len(database.prompts)} prompts: {len(database.by_language('en'))} en")
```

Inline single-file scripts work too. Save this as `decode.py`, then run
`uv run decode.py < packet.bin > plain.bin`:

```python
# /// script
# requires-python = ">=3.10"
# dependencies = ["thd75-fw"]
# ///
import sys
from thd75_fw.serial_cipher import decrypt

sys.stdout.buffer.write(decrypt(sys.stdin.buffer.read()))
```

## Development tests

From a repository checkout, install the development dependencies and run the
Python checks:

```bash
uv sync --group dev
make check
```

`make check` runs formatting, lint, strict type checks, pytest, and the
firmware Python tool tests. Tests use simulated transports and do not contact
hardware. Tests marked `slow` are skipped by default; include them explicitly:

```bash
uv run pytest tests/ --run-slow
```

Some integration tests use local vendor updater/extracted files under `ref/`
or generated artifacts under `recovery/` and skip when those files are absent.
This applies to some default tests as well as slow tests; `--run-slow` enables
the marker but does not supply missing inputs. Obtain reference inputs from
the official updater and retain their provenance privately. Firmware images,
local captures, and private qualification traces must stay out of commits.
For Rust payload build and audit checks, see the repository's
[firmware workspace](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/README.md).
