# thd75-fw

[![CI](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml/badge.svg)](https://github.com/swiftraccoon/thd75-fw/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/swiftraccoon/thd75-fw/graph/badge.svg?token=M7EJ9BQ8CG)](https://codecov.io/gh/swiftraccoon/thd75-fw)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Typed](https://img.shields.io/badge/typed-pyright%20strict-brightgreen.svg)](https://github.com/microsoft/pyright)

Firmware extraction and cipher tools for the Kenwood TH-D75 amateur radio transceiver.

## What This Does

Extracts the 7 firmware sections from the official Kenwood TH-D75 firmware updater executable, and applies user-defined patches to that firmware — as a plaintext `.KEX` image, or by repacking the updater `.exe` itself. Patches are TOML files: ship your own, or pick from the built-in catalog. Also provides encrypt/decrypt for the serial transfer cipher used during USB firmware updates.

The official V1.03 package has four nonstandard Intel HEX checksum bytes in
two tiny final-overlay streams. Extraction admits only those byte-exact vendor
streams at their exact block indices and addresses; every other checksum error
is fatal. `thd75-extract --section FIRMWARE` is the least-authority path when
only the independently valid main firmware image is needed.

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

The package installs nine CLIs and a typed Python library:

| CLI | Purpose |
|-----|---------|
| `thd75-extract` | Extract the 7 firmware sections from the updater `.exe` |
| `thd75-extract-voice` | Extract 749 voice prompts as 8 kHz mono WAV |
| `thd75-extract-images` | Extract 862 PNG display images |
| `thd75-patch` | Apply a patch and emit a plaintext `.KEX` image |
| `thd75-repack` | Apply a patch and emit a flashable updater `.exe` |
| `thd75-list-patches` | List the built-in patch catalog |
| `thd75-flash` | Flash a `.KEX` to a connected radio over USB serial (cross-platform; no Windows VM required) |
| `thd75-serial-cipher` | Encrypt/decrypt individual serial packets |
| `thd75-theme` | Generate a display theme patch (menu 906 colour scheme) |

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
thd75-patch TH-D75_V103_e.exe out.KEX --patch service-9r-nor-read
thd75-flash --dry-run out.KEX
```

The catalog also ships `orange-on-black`, a data-only display theme: the
"White" option of menu 906 becomes deep orange on black (palettes, text
palette and icon twins in IMAGE_DATA and FIRMWARE; no code change). It stacks
on the normal-GM family firmware with repeated `--patch`.

**Reflashing firmware carries inherent risk.** Use a fully charged radio.

An external `.KEX` is byte-oriented plaintext with literal `:` Intel HEX lines;
it is not the encrypted hex resource embedded in the updater. The flasher rejects
an encrypted resource merely renamed `.KEX`, logs both the input and canonical
plaintext hashes, and currently permits a real KEX write only for the exact
audited stock V1.03, `service-9r-nor-read`, `normal-gm-ddr-read`,
`normal-gm-nor-read`, `normal-gm-nor-read-usb-recover` V18, Azimuth automation
(`V1.03.AZM`), and Azimuth plus `orange-on-black` plaintext hashes. Other valid
KEX files are dry-run-only.

The exact `normal-gm-ddr-read` artifact and all four exact
`normal-gm-nor-read` family artifacts share one artifact-specific planning
exception. Before any loader command, the host pins source segment 3's complete
`DATA_0160` recovery descriptor and transmitted payload hash against the
stock-identical values, then omits that source segment from the plan. Its
`$VL=0` descriptor makes the target report a SETUP mismatch even when the
10 MiB voice database is unchanged. Dry-run and trace diagnostics expose the
omission and preserve the original source indices `[0,1,2,4,5,6]`. Internal
plan indices are not evidence that the source layout changed.

`--force-all-segments` is dry-run-only and retains all seven source segments
for inspection.

This omission is never applied to stock recovery: the exact stock artifact
retains its complete seven-segment plan so it can repair `DATA_0160`. Removing
the unnecessary 10 MiB transfer reduced a hardware-qualified normal-GM flash
from 207.1 seconds to 42.0 seconds. The fast run actually rewrote and verified
the 2,621,440-byte main firmware plus both overlays; its retained trace contains
six SETUP commands and no `DATA_0160` SETUP.

A real write of the exact service-9r artifact additionally requires
`--acknowledge-service-9r-write`. That dedicated flag is independent of
`--yes` and attests, in order, that the untouched-stock USB-C `9R` baseline
passed; the fixed SETUP positive controls passed; a separately power-cycled
exact mismatch/repeat SETUP returned `(1,0)`; and a verified stock restore
artifact is retained. The patched 1/16/256-byte and bounds check is not a
pre-write attestation: it must be the first post-flash service operation. It is
also repeated automatically by `9r-dump` before that mode issues any full-read
request. The write flag is rejected for stock or unpinned KEX files and for
dry-run, raw, probe, or SETUP modes.

A real write of `normal-gm-nor-read` requires the separate
`--acknowledge-gm-nor-read-write` flag. Its FIRMWARE differs from the
hardware-qualified DDR reader by exactly one byte: the read-base immediate is
`0x60`, producing CPU address `0x60000000`. After the mandatory power cycle,
`gm-nor-check` must be the first GM operation. It first attests that live `0x60`
byte and every complete patch window, then checks only the bounded 2 MiB
low-NOR candidate range. `gm-nor-dump` repeats the gate and retains a file only
after two exact 2 MiB passes agree:

```bash
python3 firmware/capture_dump.py --mode gm-nor-check \
  --acknowledge-cat-preflight --acknowledge-gm-nor-read \
  --transport usb --verbose
python3 firmware/capture_dump.py --mode gm-nor-dump \
  --acknowledge-cat-preflight --acknowledge-gm-nor-read \
  --transport usb --output thd75-low-nor.bin --verbose
```

The dump host exposes no arbitrary address option. Apart from the exact
one-byte base probe and four flashed-main attestation reads, it permits only
offsets `0x000000..0x1FFFFF`; the remainder of the GM command's 16 MiB grammar
range is out of scope.

This route is hardware-qualified. The native fast flash completed in 41.7
seconds, the mandatory check passed, and two matching 2 MiB passes produced
SHA-256
`daaf1dbc4750fc200ee8cd33ae57b5c5923e0ea7c01697470efbf751aab47734`.
The capture contains a 128 KiB Boot Program slot and a 256 KiB FLDM loader
slot.

The exact `normal-gm-nor-read-usb-recover` V18 artifact uses the same
`--acknowledge-gm-nor-read-write` gate. It fixes a stock V1.03 capacity bug at
CPU `0xC0101178`: `adds r0,r0,#1` turns an already complete partition-sector
count into `N+1`, so READ CAPACITY exposes one nonexistent terminal LBA. V18
replaces that instruction with a Thumb NOP. On the tested card this corrected
the count from `0x03B70401` to `0x03B70400` and the final LBA from invalid
`0x03B70400` to valid `0x03B703FF`.

V18 is broader than that two-byte fix. It also preserves asynchronous storage
ownership, services host multi-sector requests through bounded repeated stock
CMD17 reads, provides one fail-closed full-reinitialization/replay opportunity,
and exposes live telemetry over the retargeted DDR GM reader. It adds no
NOR-write primitive. The exact artifact flashed in 19.3 seconds, automatically
enumerated on macOS as USB mass storage VID:PID `2166:9024`, mounted the FAT32
card, and passed 93 read operations covering 2,604 sectors with no firmware
failure, retry, recovery, suppression, or geometry error.

The exact Azimuth artifact, `normal-gm-nor-read-usb-recover-azimuth`, is the
only shipped automation overlay. It layers bounded stock key dispatch and
coherent, CRC-checked LCD publication over V18, carries the ABI-3 automation
runtime, and rewrites the payload identity to the exact 16-byte field
`V1.03.AZM      \0`. Its real write uses the same
`--acknowledge-gm-nor-read-write` gate and fast plan. The overlay is
deterministically built, emulated, hash-pinned, and admitted by the flasher.
Guarded single-key input dispatches only when the live framebuffer matches the
last stable snapshot, and every ABI query invalidates the prior snapshot lease
under the metadata seqlock. The guarded decimal route authenticates the
complete top-level Menu framebuffer once, before any input, then synchronously
dispatches all three zero-hold digits in the same CAT handler. This permits the
stock numeric-entry redraw after digit one without accepting an unauthenticated
starting context; refusals authenticate the empty prefix and never invite a
blind retry. The gate prescribes a byte-exact qualifier plus missing-snapshot,
changed-context, command-4 zero-prefix, and atomic 991 route canaries before
menu automation. See
[`firmware/RADIO_AUTOMATION.md`](firmware/RADIO_AUTOMATION.md) for the exact
artifact chain, protocol, and live sequence.

The unchanged 1,300-byte ABI-3 runtime and hooks passed live TH-D75A/V1.03
qualification and the full menu audit on 2026-07-31 in the package that
preceded the identity rename, and the Azimuth plus `orange-on-black` stack
wrote and verified FIRMWARE, IMAGE_DATA and both overlays through the fast plan
on the TH-D75 on 2026-09-24; see [`CHANGELOG.md`](CHANGELOG.md). The earlier
automation overlays are superseded by Azimuth and no longer shipped: their
catalog patches, build path, and write admission are removed. The 2026-07-28
hardware qualification of the first such overlay established the
key-to-screen loop with MENU, direction-pad, Enter, nested-screen, CRC,
pixel-difference, and exact OCR assertions; it does not qualify Azimuth.

`thd75-flash --raw` is also dry-run-only. No retained raw payload has an
allowed, verified return transport: the current dumper emits on physical UART0,
not USB-C or Bluetooth. Real writes remain limited to the seven exact plaintext
KEX artifacts above.

To enter Firmware Programming Mode: power the radio off, then power it on while holding `[PTT] + [1]`. The `thd75-flash` CLI prints the full checklist and a post-flash Full Reset reminder. Every `thd75-flash` hardware mode requires an explicit, currently enumerated TH-D75 USB VID:PID `2166:9023` endpoint; Bluetooth and unrelated serial nodes are rejected. Non-write hardware transports open the endpoint exclusively. Real writes intentionally leave pyserial's `exclusive` option unset because that is part of the twice-proven OpenWood-compatible recovery transport. VID/PID selects the radio but does not distinguish normal CAT from FLDM, so the front-panel state remains mandatory. Real KEX writes are otherwise locked to that proven D75 profile: direct-open 576000, cleartext `FPROMOD`, `12 01`, 256-byte packets with an ACK after each, BEGIN for every written segment (including `$EL=0` overlays), `$CT/$ET` plus a 30-second base reply margin, one END_TRANSFER per segment, and u32 completion. `thd75-flash --probe-only --port PORT` sends only the unlock probe (no NOR-write verb, but it advances loader state and requires a USB disconnect plus full power-cycle afterward). `thd75-flash --dry-run IMAGE.KEX` is strictly offline: it validates and prints the resolved plan without opening a serial device.

The first native qualification attempt failed mid-segment on 2026-07-26.
After restoring literal `tcdrain` ordering and the reference response-read
cadence, the transport-ordering repair completed the same native stock recovery
in 204.5 seconds. The corrected normal-mode GM DDR reader was then flashed and
passed escalating, bounds, live-byte, and duplicate-reply tests. The session
records, traces, and logs behind these hardware results are kept outside the
repository. To restore stock firmware after a failed experiment, follow
[Recover with stock firmware](docs/USAGE.md#recover-with-stock-firmware).

See [`docs/USAGE.md`](./docs/USAGE.md) for per-CLI examples, the patch TOML schema, and Python library usage.

## Extracted Sections

| Section | Flash Address | Size | Content |
|---------|--------------|------|---------|
| FIRMWARE | 0x00200000 | 2.5 MB | ARM926EJ-S executable (OMAP-L138) |
| CHECKBYTES | 0x00200062 | 2 B | Stock V1.03 post-write bytes `B0 1D`; D75 early-boot use is unconfirmed |
| FINAL_ZZZ | 0x00200040 | 32 B | Stock final overlay; its D75 early-boot meaning is unconfirmed |
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

Thanks also to **[`linux4life798/openwood`](https://github.com/linux4life798/openwood)** by [@linux4life798](https://github.com/linux4life798) — a cross-platform Python flasher for the TH-D74 (which itself uses `thd75-fw` as a dependency for KEX parsing). Its D74 reflashing and recovery work motivated the flasher here, but it is reference evidence for a related model, not proof of TH-D75 bootloader semantics or recoverability.

## Legal Disclaimer & Interoperability Notice

**This software is provided for amateur radio interoperability and educational research only.**

### Interoperability & Essentiality

The decryption and re-encryption implementations provided in this project are **required for interoperability** with the Kenwood TH-D75 transceiver. Without these technical measures, it is impossible for an owner of the device to:

1. **Analyze and verify** the firmware running on their own equipment (security research).
2. **Maintain and repair** their equipment by modifying or updating firmware outside of official, closed-source tools (right to repair).
3. **Develop independent software** that can interact with the radio's serial update protocol.

These implementations were derived through independent analysis of the publicly
distributed firmware updater, public Kenwood manuals, owner-operated hardware
observations, and openly published related-model reverse engineering. None of
those sources establishes undocumented TH-D75 behavior by itself; the project
records provenance and model-specific gaps where they matter.

### Reverse-Engineering Methodology

The project uses independent interoperability research methods:

- **Source material**: Publicly distributed Kenwood updater binaries and manuals,
  observations of personally controlled TH-D75 hardware, and public TH-D74
  research cited in this repository. Related-model material is reference
  evidence, not asserted as TH-D75 proof.
- **Tooling**: Only commercially licensed or open-source reverse engineering tools (e.g., IDA Pro, Ghidra, standard UNIX utilities). No Kenwood-proprietary tools, undisclosed utilities, or non-public debugging interfaces were used.
- **Non-use of confidential material**: No JVCKENWOOD source code, non-public
  internal documentation, NDA material, leaked material, or other confidential
  information was consulted.
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
