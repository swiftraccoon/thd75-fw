# Usage

Worked examples for every CLI and the Python library API. For a one-screen
overview and the install instructions, see the [main README](../README.md).

## Extract firmware from updater

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
```

## Verify against known-good files

```bash
thd75-extract TH-D75_V103_e.exe ./out/ --verify ./known-good/
```

## Serial cipher (encrypt/decrypt individual packets)

```bash
thd75-serial-cipher decrypt packet.bin -o plain.bin
thd75-serial-cipher encrypt plain.bin -o packet.bin
thd75-serial-cipher selftest
```

## Extract voice prompts as WAV

```bash
thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/
thd75-extract-voice ./extracted/DATA_0160_0x01600000.bin ./prompts/ --lang en
```

Extracts 749 voice prompts (327 English, 356 Japanese, 66 Chinese) as 8 kHz mono WAV files.

## Extract display images as PNG

```bash
thd75-extract-images ./extracted/IMAGE_DATA_0x00600000.bin ./images/
```

Extracts 862 PNG images (APRS symbols, status icons, splash screens, UI elements).

## Patch firmware (plug-in patches)

Patches are TOML files: each declares which firmware bytes to change and what value each byte *must* currently hold (`expect`). The engine refuses to write if any `expect` mismatches, so a patch written for V1.03 cannot brick a V1.05 radio by silently mangling a different byte.

List the built-in catalog:

```bash
thd75-list-patches
```

Apply a catalog patch to the updater, producing a new flashable `.exe`:

```bash
thd75-repack TH-D75_V103_e.exe out.exe --patch pf-screen-capture
```

Or inspect the patched firmware as a plaintext `.KEX` image without rebuilding the updater:

```bash
thd75-patch TH-D75_V103_e.exe out.KEX --patch pf-screen-capture
```

Apply your own patch from a TOML file by passing its path:

```bash
thd75-repack TH-D75_V103_e.exe out.exe --patch ./my-patch.toml
```

A patch file looks like this:

```toml
name        = "my-patch"
description = "What this patch does and why."
target_firmware = "TH-D75 V1.03"

[[changes]]
offset = 0x10444  # flat-image byte offset
expect = 0x1B    # current value (refuse to write if firmware differs)
value  = 0x33    # new value
```

The patched `.exe` flashes exactly like the official updater — only the patched bytes (and the Intel HEX record checksums covering them, plus the firmware block's `$CA` checksum) differ from the official image; every other byte is left identical.

**The catalog ships with one seed entry, `pf-screen-capture`**, which widens the front-panel PF-key decoders' lookup-table scan so the front-panel PF1/PF2 keys can be assigned Screen Capture (the stock firmware allows that function only on the microphone PF keys). Inspect it with `thd75-list-patches` for the full RE rationale.

**Reflashing firmware carries inherent risk.** Use a fully charged radio.

## Use as a Python library

The same primitives that power the CLIs are exposed as importable functions:

```python
from pathlib import Path
from thd75_fw.serial_cipher import encrypt, decrypt
from thd75_fw.sections import lookup_by_address
from thd75_fw import voice

# Round-trip a serial packet (default key 0x75)
ciphertext = encrypt(b"hello world")
assert decrypt(ciphertext) == b"hello world"

# Look up a section by flash address
info = lookup_by_address(0x01600000)
assert info is not None and info.name == "DATA_0160"

# Parse a voice prompt database
data = Path("./extracted/DATA_0160_0x01600000.bin").read_bytes()
database = voice.load(data)
print(f"{len(database.prompts)} prompts: {len(database.by_language('en'))} en")
```

Inline single-file scripts work too — paste this into `decode.py` and run with `uv run decode.py`:

```python
# /// script
# requires-python = ">=3.10"
# dependencies = ["thd75-fw"]
# ///
import sys
from thd75_fw.serial_cipher import decrypt
sys.stdout.buffer.write(decrypt(sys.stdin.buffer.read()))
```
