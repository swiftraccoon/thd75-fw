# TH-D75 firmware updater formats

This document consolidates the format and protocol details that
`thd75-fw` implements. Most of this is also present in module
docstrings; this file is a single reference for the cipher
algorithms, container layout, and section structure.

## Table of contents

1. [The two ciphers](#the-two-ciphers)
2. [File-storage cipher (firmware-resident)](#file-storage-cipher-firmware-resident)
3. [Serial transfer cipher (USB protocol)](#serial-transfer-cipher-usb-protocol)
4. [Resource extraction from the .NET updater](#resource-extraction-from-the-net-updater)
5. [Block / section metadata format](#block--section-metadata-format)
6. [Intel HEX records (packed binary form)](#intel-hex-records-packed-binary-form)
7. [Section catalog](#section-catalog)
8. [OMAP-L138 memory map](#omap-l138-memory-map)
9. [Voice prompt database (DATA_0160)](#voice-prompt-database-data_0160)
10. [Image database (IMAGE_DATA)](#image-database-image_data)
11. [References and prior work](#references-and-prior-work)

---

## The two ciphers

The Kenwood TH-D75 firmware updater (a Windows .NET 4.8 executable)
uses **two independent ciphers**, never compose:

| Cipher | Where used | Algorithm summary |
|--------|------------|-------------------|
| File-storage | The firmware embedded inside the updater `.exe` (a managed string resource) | Rolling-key XOR + alternating byte inversion. Output is text: hex pairs prefixed with `$` (metadata) or other char (data). |
| Serial transfer | USB packets sent during firmware update | 256-byte substitution table + XOR + 3-bit left rotation. Operates on raw bytes. |

The two ciphers share no key material, no state, and no algorithmic
primitive beyond "XOR with a key." Treat them as completely separate.

---

## File-storage cipher (firmware-resident)

Reverse-engineered from class `j` in `THD75_Updater_E v1.03.000`,
decompiled with [ILSpy](https://github.com/icsharpcode/ILSpy).

### Algorithm

For each hex character pair at 1-based index `i` within a line:

```
raw_byte     = int(hex_pair, 16)
xored        = raw_byte ^ ((i & 1) * 0xFF)
plaintext    = (xored - rolling_key) & 0xFF
rolling_key  = (rolling_key + step) & 0xFF
```

### Critical invariant

> **The rolling key is continuous across all lines.** Every hex pair —
> whether on a `$`-prefixed metadata line or a data line — advances
> the key by `step`. There is no per-line reset.

### Defaults

```python
key  = 39   # initial rolling-key value
step = 39   # advance per byte
```

### Line types

| First char of line | Type | Decrypted content |
|--------------------|------|-------------------|
| `$` | Metadata | ASCII text (e.g., `$SA=0x60200000`) |
| Anything else | Data | Raw bytes (interpreted as packed Intel HEX) |

### Encryption (the inverse)

```
xored        = (plaintext + rolling_key) & 0xFF
raw_byte     = xored ^ ((i & 1) * 0xFF)
hex_pair     = f"{raw_byte:02X}"
rolling_key  = (rolling_key + step) & 0xFF
```

`thd75-fw`'s test suite exposes encoder helpers (`encrypt_line`,
`encrypt_resource`) as pytest fixtures in `tests/conftest.py` that
demonstrate this round-trip.

---

## Serial transfer cipher (USB protocol)

Reverse-engineered from `Form1::b()` (encrypt) and `Form1::a()`
(decrypt) in the same updater.

### Algorithm

**Encrypt (per byte):**

```
index       = (key + plaintext_byte) & 0xFF
substituted = SUBST_TABLE[index]
xored       = substituted ^ key
ciphertext  = ROL3(xored)              # rotate left 3 bits within a byte
```

**Decrypt (per byte):**

```
rotated   = ROR3(ciphertext)
xored     = rotated ^ key
index     = REVERSE_TABLE[xored]
plaintext = (index - key) & 0xFF
```

### Substitution table

A 256-byte permutation (each value 0..255 appears exactly once). The
table is hardcoded in `serial_cipher.py:_SUBST_TABLE` and validated as
a true permutation at module load time.

### Key

- Default during firmware update handshake: `0x75`
- `0x00` disables the cipher (passthrough)

### Properties

- The cipher is **stateless** (no rolling key between bytes).
- Round-trip property is verified by `verify_round_trip()` for all 256
  byte values; `thd75-fw`'s test suite property-tests it via Hypothesis
  with arbitrary lengths and key values.

---

## Resource extraction from the .NET updater

The Kenwood updater (`TH-D75_V103_e.exe`) is a Windows PE32 .NET 4.8
binary obfuscated with Dotfuscator. The firmware data lives as a
managed string resource named:

```
THD75_Updater_E.Resources.TH-D75_Firm_E.txt
```

`thd75-fw` extracts this resource via two paths:

1. **Fast path:** if a sibling `THD75_Updater_E.Resources.TH-D75_Firm_E.txt`
   file exists next to the `.exe` (e.g., produced by
   `ilspycmd <file.exe> -p -o <dir>` and copied alongside), `thd75-fw`
   reads it directly.

2. **Byte-scan fallback:** scans the PE binary linearly for the first
   `$`-prefixed hex region of size ≥ 1 MB. The resource boundary is
   detected by trailing binary content (`\x00\x00` within the first
   10 bytes of a candidate "line").

Both paths produce **byte-identical** output, verified across all 7
sections via SHA-256.

The byte scanner is O(n) on file size; the worst case (43 MB updater)
runs in roughly 100 ms on modern hardware. Cipher decryption + Intel
HEX parsing dominates the end-to-end runtime, not the scan.

---

## Block / section metadata format

Decrypted resource lines come in two flavors. Metadata lines start
with `$`; data lines do not. Multiple metadata lines may precede each
block of data.

### Recognized metadata fields

| Field | Format | Meaning |
|-------|--------|---------|
| `$SA=` | `$SA=0xHHHHHHHH` (or decimal) | Start address of the section in physical memory. The flash-relative offset is computed by subtracting the OMAP-L138's NOR flash base (`0x60000000`, exposed as `thd75_fw.sections.FLASH_BASE`). |

`thd75-fw` accepts both `0x`-prefixed hex and decimal values (via
`int(val, 16) if val.startswith("0x") else int(val)`). Unknown
metadata fields are preserved as part of the block but otherwise
ignored.

### Block boundary

A new block begins each time a `$`-prefixed line follows accumulated
data. Each block typically corresponds to one firmware section; the
order in the resource matches the order of writes during a firmware
update.

---

## Intel HEX records (packed binary form)

The data inside each block is **packed** Intel HEX records — binary
bytes, NOT the usual `:LLAAAATT...` ASCII representation.

### Record layout

```
Byte 0     : LL (data byte count)
Bytes 1-2  : AAAA (16-bit address within the current segment, big-endian)
Byte 3     : TT (record type)
Bytes 4..  : DD... (LL data bytes)
Byte LL+4  : CC (checksum byte; not validated by thd75-fw)
```

### Record types used

| Type | Name | Purpose |
|------|------|---------|
| `0x00` | Data | Write `LL` bytes at `(base_address + AAAA)` in the section image |
| `0x01` | EOF | End of stream — stops parsing this block |
| `0x04` | Extended Linear Address | Set the upper 16 bits of `base_address` from the 2 data bytes; the lower 16 bits come from each subsequent `0x00` record's `AAAA` field |

### Notes

- `thd75-fw` does NOT validate Intel HEX checksums. Truncated records,
  unknown record types, and extended-address records with `byte_count
  < 2` are surfaced via `ParseResult.errors` for callers to react to.
- Padding (all-zero 4-byte regions between records) is accepted and
  skipped silently.

---

## Section catalog

V1.03 produces 7 sections. The "Flash address" column below shows
each section's **offset from the NOR flash base** (`0x60000000` in
the OMAP-L138 memory map). The full physical address at which the
section lives at runtime is `0x60000000 + offset` — e.g. `FIRMWARE`
sits at physical `0x60200000`, derived from offset `0x00200000`.
The filenames `thd75-fw` writes use these offsets directly, matching
the `$SA=` value in the encrypted resource minus the flash base.
Patch authors should write `offset = <flat-image-offset>` against
the FIRMWARE section's flat image, which starts at offset 0 within
the `FIRMWARE_0x00200000.bin` file (i.e. flash offset `0x00200000`
maps to flat-image offset `0`).

| Section | Flash address | Size (V1.03) | Purpose |
|---------|---------------|--------------|---------|
| `FIRMWARE` | `0x00200000` | 2.5 MB | ARM926EJ-S executable + initial boot code |
| `IMAGE_DATA` | `0x00600000` | 384 KB | 862 PNG images (UI, APRS symbols, splash) |
| `DATA_00E0` | `0x00E00000` | 1.0 MB | TI C674x AMBE2+ DSP firmware (proprietary, not parsed) |
| `FONT_DATA` | `0x01500000` | 768 KB | Shift-JIS bitmap fonts (16x16 and 24x24, 1-bit mono) |
| `DATA_0160` | `0x01600000` | 10.0 MB | Voice prompt database (749 prompts, 8-bit signed PCM at 8 kHz) |
| `CHECKBYTES` | `0x00200062` | 2 bytes | Bootloader integrity checksum (`0xB01D` in V1.03) |
| `FINAL_ZZZ` | `0x00200040` | 32 bytes | Build marker, written last to confirm update completion |

`CHECKBYTES` and `FINAL_ZZZ` overlap with `FIRMWARE` (both fall within
`0x00200040..0x0020007F`) — they're patched into the FIRMWARE region's
exception-vector padding area after the main FIRMWARE write completes.

---

## OMAP-L138 memory map

The TH-D75's main SoC is the [TI OMAP-L138](https://www.ti.com/product/OMAP-L138)
(ARM926EJ-S + C674x DSP, dual-core).

| Region | Address | Size | Purpose |
|--------|---------|------|---------|
| ARM Internal RAM | `0x80000000` | 128 KB | Boot, fast-access |
| DSP Internal RAM | `0x11800000` | varies | DSP-side code/data |
| External Flash (NOR) | `0x60000000` | 32 MB | Where the updater writes — section addresses are FROM 0x60000000 |
| External DDR | `0xC0000000` | 64 MB max | Where most code runs after boot |

Implications for reverse-engineering:

- The `FIRMWARE` blob starts with ARM exception vectors at flash
  `0x00200000` (file offset 0).
- Each vector is `LDR PC, [PC, #imm]` referencing a literal pool entry
  immediately after — the literal pool addresses are all in DDR at
  `0xC0xxxxxx`.
- The bootloader (running from flash) copies the bulk of the firmware
  into DDR at `0xC0000000+`, then jumps to it.
- Flash-resident code is the boot path + the vectors; the runtime
  image lives in DDR after boot.

Tools like IDA Pro and Ghidra need to be told this — see
`loaders/README.md` for setup scripts that pre-configure the
processor, segment, and vector annotations.

---

## Voice prompt database (DATA_0160)

749 indexed segments of signed 8-bit linear PCM at 8 kHz mono. Three
language groups (V1.03 layout):

- English: indices 0-326 (327 segments, ~131 s)
- Japanese: indices 327-682 (356 segments, ~131 s)
- Chinese: indices 683-748 (66 segments, ~22 s)

The first 36 entries are organized as 12 triplets (EN/JA/ZH) of concept
prompts. After that, digits/letters use 10-step spacing.

### File layout

```
0x0000 - 0x003F   Header (model ID, engine version, entry count at 0x20)
0x0040 - 0x0BF3   Index table (749 × 4-byte LE cumulative offsets)
0x0BF4 - 0x0BF7   End marker (total indexed audio size)
0x0BF8 - EOF      Audio data (8-bit signed PCM, 8 kHz mono)
```

### Header fields

| Offset | Size | Field |
|--------|------|-------|
| `0x00` | 7 | Model ID (ASCII, e.g., `E5210`) |
| `0x07` | 17 | Engine version (ASCII, e.g., `VTE0816SQ1.00.00`) |
| `0x18` | 8 | (unused / reserved) |
| `0x20` | 4 | Entry count (uint32 LE) |
| `0x24` | 28 | (unused / reserved) |

Entries are cumulative end-offsets relative to `AUDIO_BASE = 0x0BF8`.
Prompt N's audio occupies the byte range
`AUDIO_BASE + offsets[N-1]..AUDIO_BASE + offsets[N]` (with prompt 0
starting at `AUDIO_BASE`).

WAV output by `thd75-extract-voice` converts the signed 8-bit samples
to unsigned by flipping the sign bit (XOR `0x80`), which is the
canonical signed↔unsigned 8-bit PCM conversion.

---

## Image database (IMAGE_DATA)

862 PNG images used for the radio's display. Sizes range from 1×10 to
240×180 pixels. Content includes APRS symbols, status icons, splash
screens, menu labels, and UI elements.

### File layout

```
0x0000 - 0x002F   Header (version string at 0x00, table offset at 0x28)
0x0030 - 0x0DA7   PNG offset table (862 × 4-byte LE offsets to PNG data)
0x0DA8 - EOF      Concatenated PNG image data with 0xFF padding between
```

### Extraction algorithm

For each entry `i` in the offset table:

1. PNG starts at `offsets[i]` (absolute file offset).
2. PNG ends just past its IEND chunk, found by walking the PNG chunk
   structure (`length:4 + type:4 + data:length + crc:4`) starting from
   the signature at `offsets[i]`.
3. Padding bytes (typically `0xFF`) between the IEND and the next
   `offsets[i+1]` are correctly excluded by chunk-walking.

The chunk-walk approach is exact, not heuristic — earlier versions of
`thd75-fw` used `data.find(b"IEND")` which can produce false positives
(e.g., when a tEXt chunk contains "IEND" as data) or truncate when a
PNG's CRC happens to end in `0xFF`.

---

## Font data (FONT_DATA) — not yet documented

The `FONT_DATA` section (768 KB at flash `0x01500000`) holds the radio's
Shift-JIS bitmap fonts at 16×16 and 24×24 sizes (1-bit mono). Internal
structure — table format, glyph indexing, encoding-to-offset mapping —
is **not yet documented** in this project, and no extractor ships with
`thd75-fw`.

Researchers wanting to start: inspect the first 256 bytes for header
signatures and version strings, then look for repeating-period structure
that would suggest fixed-size glyph cells (16×16 = 32 bytes per glyph at
1-bit; 24×24 = 72 bytes; both are likely candidates).

## DSP firmware (DATA_00E0) — out of scope

The `DATA_00E0` section (1.0 MB at flash `0x00E00000`) is the TI C674x
AMBE2+ DSP firmware. AMBE2+ is patent-encumbered (DVSI), and the
on-the-wire format is not documented in any of DVSI's public
specifications. `thd75-fw` extracts the section as bytes but provides
no parser; downstream RE work for this section is out of scope.

## References and prior work

- **DD4CR's TH-D74 reverse-engineering**:
  https://github.com/cr/thd74
  The D75 ciphers are evolutionary variations of the D74's cipher
  primitives (modular arithmetic, XOR, single-byte keys). The D74
  documentation of the .NET updater structure and XOR permutation
  cipher provided the foundation for the D75 analysis.

- **OMAP-L138 documentation** (TI):
  https://www.ti.com/product/OMAP-L138
  Reference for the ARM926EJ-S processor, memory map, and boot flow.

- **Intel HEX format specification**:
  https://www.kanda.com/files/IntelHexFormat.pdf
  Standard reference (textual `:`-prefixed form). The TH-D75 firmware
  uses the binary-packed equivalent of these records.

- **PNG format specification**:
  https://www.w3.org/TR/png/
  Used by the IMAGE_DATA chunk-walker.
