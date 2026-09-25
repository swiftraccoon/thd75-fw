# Closed-loop Azimuth automation

[Firmware tools](README.md) · [Patch catalog](../src/thd75_fw/patches/README.md) ·
[Flashing and recovery](../docs/FLASHING.md)

This is the technical reference for the Azimuth ABI-3 overlay: its CAT protocol,
screen publication, reproducible build, and live acceptance requirements. For
patch selection and stacking, start with the
[catalog](../src/thd75_fw/patches/README.md).

The overlay turns the exact, hash-pinned V1.03 normal-mode `GM` reader into a
closed-loop test interface. A host sends a bounded stock
front-panel event, asks the radio to freeze a coherent LCD frame, reads the
published pixels, verifies their metadata and CRC-32, and only then evaluates
what the radio actually displayed.

It builds on the exact V18 USB-recovery FIRMWARE identified in
[artifact pins](#artifact-pins), preserving `GW 2` storage recovery and ordinary
thirteen-byte `GM` reads. The build rejects a different source image, occupied
code/data cave, unexpected source instruction or linked section, retained
relocation, or non-reproducible object/ELF.

- [Status](#status)
- [CAT protocol](#cat-protocol)
- [Screen publication](#atomic-screen-publication)
- [Metadata ABI](#metadata-abi)
- [Front-panel input](#front-panel-input)
- [Reproducible build](#reproducible-build)
- [Artifact pins](#artifact-pins)
- [Live acceptance specification](#live-acceptance-specification)
- [Historical evidence](#historical-evidence)

## Status

The recorded evidence applies to specific artifacts:

| Artifact | Recorded verification |
| --- | --- |
| Predecessor package with the same 1,300-byte ABI-3 runtime and hooks | Live TH-D75A/V1.03 qualification and full menu audit on 2026-07-31, before the Azimuth payload-identity rename. |
| Bare Azimuth with `V1.03.AZM` identity | Deterministic dual build, emulation, patch/repack, extraction, and flasher admission. No separate physical flash/readback of this exact bare artifact is recorded here. |
| Azimuth plus `orange-on-black` | Flashed and verified FIRMWARE, IMAGE_DATA, and both overlays on 2026-09-24; the Orange display option was observed. This records the themed artifact's flash and display result, not completion of every live acceptance step below. |

The host qualifier, menu runner, and private evidence bundles used for the
historical hardware work are not distributed in this repository. The
[live sequence](#live-acceptance-specification) specifies the checks a host
implementation must perform; it is not a runnable qualifier command supplied
by `thd75-fw`. ABI-1 and ABI-2 overlays are superseded and no longer shipped or
buildable.

## CAT protocol

Azimuth provides framebuffer-guarded single-key and three-digit numeric-route
operations. It resolves the route with one verified starting-context guard
followed by all three synchronous digits.

Every automation request is exactly eleven bytes including its final carriage
return. A successful command echoes the first ten request bytes, appends
uppercase hexadecimal result data, and ends with a carriage return. Invalid
lengths, delimiters, hexadecimal fields, keys, and phases use the stock `?\r`
error response.

| Request | Result data | Meaning |
|---|---:|---|
| `GM A000000\r` | `44373541037F1802` | Attest magic `D75A`, ABI 3, feature bits `0x7F`, maximum key `0x18`, and maximum phase `2` |
| `GM Sssssss\r` | one byte | Capture a stable screen with six-hex-digit host sequence `ssssss`; `00` is success and `01` is unstable |
| `GM Khh,Pss\r` | one byte | Dispatch key `hh`, phase `P`, and two-hex-digit host sequence `ss`; `00` means the stock dispatcher returned |

Azimuth also provides two framebuffer-guarded commands:

| Request | Result data | Meaning |
|---|---:|---|
| `GM Ghh,Pss\r` | one byte | Dispatch only if the live 86,400-byte framebuffer exactly matches the last successful stable raw snapshot; `00` means it matched and the stock dispatcher returned, while `02` means no valid matching context existed and no input was dispatched |
| `GM Rddd,ss\r` | one byte | Route exactly three decimal digits. Sample and compare the complete framebuffer once, before any input; on a match, synchronously dispatch press then release for key `0x0A + digit` for all three digits. `00` means all three taps completed. `02` means the guard refused before any input. |

Azimuth's `R` command samples and compares the complete framebuffer exactly
once, before any input, then synchronously dispatches all three zero-hold
press/release pairs. Status `02` therefore always authenticates an empty prefix;
status `00` authenticates all six events. The single initial guard is
intentional: stock direct-menu entry redraws after digit one, so a per-digit
framebuffer guard would refuse otherwise-valid second and third digits.

For the Azimuth build, `GM A000000\r` is also a fail-closed qualification
boundary. Before replying, it invalidates any prior guarded-input snapshot
under the metadata seqlock: capture result becomes unstable, CRC-32, capture
attempts, and RLE length become zero, and the last-command fields are cleared.
Generation remains monotonic and the old raw bytes may remain for forensic
continuity, but neither `G` nor `R` can use them. The query increments command
count, dispatches no input, samples no framebuffer, and changes no persistent
radio setting or UI state. Thus a repeated runtime qualification cannot inherit
a snapshot lease from an earlier automation session.

Each guard takes one sequential full-frame sample into snapshot B, compares
that offline copy with stable snapshot A, and only then calls the synchronous
stock dispatcher. These steps run in one CAT handler invocation, but they are
not an atomic framebuffer transaction: a preemptive framebuffer writer can
still run after the sample and before dispatch. Snapshot B is scratch, so a
guarded attempt clears the optional RLE length; snapshot A and its CRC remain
unchanged.

`R` validates all three decimal digits before doing anything. Azimuth performs
one guard, then all three press/release pairs; its receipt has guard count `1`
and either completed taps/event mask `0`/`0x00` or `3`/`0x3F`. It performs no
OCR, file I/O, journaling, or screen transfer between digits. This batches the
overloaded numeric route into one CAT request with no host turn between digits;
it does not assume or depend on any undocumented numeric-entry timeout. “Atomic
route” refers to that single handler transaction, not to an atomic framebuffer
snapshot or a guarantee against preemptive display writers.

An ordinary request of the form `GM oooooo,ll\r` remains byte-for-byte
compatible with the V18 reader. The automation data are exposed in a disjoint
virtual aperture:

| GM offset | Length | Contents |
|---:|---:|---|
| `0xF00000` | `0x100` | Automation metadata |
| `0xF00100` | `0x15180` | Stable 240 × 180, top-down RGB565 little-endian pixels |
| `0xF15300` | metadata-selected | Optional `RLE3` records for the same stable pixels |

The raw aperture ends exactly at `0xF15280`; the separate RLE aperture ends at
`0xF2A480`. A read must lie wholly inside one aperture to be translated. All
other reads, including aperture-crossing reads, retain ordinary V18 DDR
semantics. The stock 16 MiB end bound still rejects requests that cross the
reader's overall window.

## Atomic screen publication

The stock live framebuffer is at `0xC2349A40`, with width 240, height 180,
stride 480, and length 86,400 bytes. A snapshot command:

1. marks the metadata seqlock odd;
2. copies the complete live framebuffer to `0xC01A0100`;
3. copies it again to `0xC01B5300`;
4. compares all `0x5460` 32-bit words;
5. retries at most three times when the copies differ;
6. reuses the now-unneeded second copy for bounded `RLE3` encoding;
7. computes the standard reflected IEEE CRC-32 over the published raw copy;
8. increments the generation and marks the metadata seqlock even.

An unstable screen is never published as a successful new generation. The
host reads metadata, pixels, and metadata again and accepts a frame only when
both metadata records identify the same completed generation and the locally
computed CRC-32 matches.

Each `RLE3` record is exactly three bytes: a nonzero run count followed by one
RGB565 little-endian pixel. Counts range from 1 through 255. The encoder never
writes beyond the second frame buffer; if another complete record would cross
its exact 86,400-byte capacity, metadata publishes RLE length zero and the host
uses the raw aperture. A host accepts RLE only when its byte length is a
multiple of three, every count is nonzero, it expands to exactly 86,400 bytes,
and the expanded raw frame matches the published CRC-32.

## Metadata ABI

All fields are little-endian `u32`. Unlisted bytes are zero. The full record is
exactly `0x100` bytes.

| Offset | Field | Required value or meaning |
|---:|---|---|
| `0x00` | magic | `0x41353744` (`D75A`) |
| `0x04` | ABI version | `3` for Azimuth |
| `0x08` | seqlock sequence | even when published |
| `0x0C` | feature bits | `0x0000007F` for Azimuth |
| `0x10` | width | `240` |
| `0x14` | height | `180` |
| `0x18` | stride | `480` |
| `0x1C` | pixel format | `0x35363552` (`R565`) |
| `0x20` | pixel length | `0x15180` |
| `0x24` | pixel offset | `0x100` |
| `0x28` | generation | increments after each stable capture |
| `0x2C` | capture result | `0`, `1`, or busy sentinel `0xFFFFFFFF` |
| `0x30` | CRC-32 | published-frame CRC |
| `0x34` | capture attempts | `1..3` after capture; Azimuth query invalidation resets it to `0` |
| `0x38` | command count | increments for each accepted automation command |
| `0x3C` | last command | Azimuth `0` query invalidation, `1` snapshot, `2` unconditional key, `3` guarded key, `4` guarded route |
| `0x40` | last host sequence | parsed sequence from the last command |
| `0x44` | last key | raw stock key identifier; for command 4, the final released key on success or first refused would-be key on status `2` |
| `0x48` | last phase | `0` press, `1` release, `2` repeat; command 4 ends at release on success and would-be press on refusal |
| `0x4C` | last key result | `0` after the stock dispatcher returns; Azimuth `2` when the guard refuses without dispatch |
| `0x50` | live framebuffer address | `0xC2349A40` |
| `0x54` | published snapshot address | `0xC01A0100` |
| `0x58` | limits | maximum key in bits 0–7, maximum phase in bits 8–15 |
| `0x5C` | RLE format | `0x33454C52` (`RLE3`) |
| `0x60` | RLE virtual offset | `0x15300` |
| `0x64` | RLE byte length | `0` for raw fallback, otherwise a multiple of 3 |
| `0x68` | route digits | command 4 raw ASCII `D0 | D1 << 8 | D2 << 16`; zero for other accepted commands |
| `0x6C` | route guard attempts | Azimuth command 4 is exactly `1`; zero for other accepted commands |
| `0x70` | route completed taps | Azimuth command 4 is `0` on refusal or `3` on success; zero for other accepted commands |
| `0x74` | route event mask | command 4 bit `2*i` means digit `i` press returned and bit `2*i+1` means release returned; full success is `0x3F`; Azimuth refusal is `0x00`; zero for other accepted commands |
| `0xFC` | trailing magic | `0x41353744` |

Both magic words, every fixed geometry/format field, the command and host
sequence, the result, the generation, and the CRC are host-side acceptance
conditions. The ABI query alone is not sufficient qualification: the host also
attests exact patched instruction windows and a runtime signature from the
running DDR image before it exposes the automation capability.

## Front-panel input

The overlay calls the stock raw-input dispatcher at `0xC0056318`. It accepts
only the normal key range `0x00..0x18` and phases press `0`, release `1`, and
repeat `2`; the stock special paths above that range cannot be reached.

| ID | Control | ID | Control |
|---:|---|---:|---|
| `00` | MODE | `0D` | CALL / 3 |
| `01` | MENU | `0E` | MSG / 4 |
| `02` | A/B | `0F` | LIST / 5 |
| `03` | F | `10` | BCN / 6 |
| `04` | MONI | `11` | REV / 7 |
| `05` | Up | `12` | TONE / 8 |
| `06` | Down | `13` | PF1 / 9 |
| `07` | Left | `14` | MHz / `*` |
| `08` | Right | `15` | PF2 / `#` |
| `09` | ENT | `16` | microphone PF1 |
| `0A` | MARK / 0 | `17` | microphone PF2 |
| `0B` | VFO / 1 | `18` | microphone PF3 |
| `0C` | MR / 2 |  |  |

A key reply proves only that the bounded stock dispatcher returned. It does
not prove that the active UI accepted the event. The subsequent accepted
screen snapshot is the behavioral oracle. Host code normally emits a press
and release pair; the lower-level phase API documents that a press requires a
matching release.

The four direction IDs were established by retained live key-to-screen tests:
`05` moved the selected main-menu label from `SD Card` to `APRS`, `06` moved
it back, `07` moved from `SD Card` to `Broadcasting`, and `08` moved it back.
All four exact label assertions passed at confidence 1.0. IDs above `0x18`,
PTT, power, and the stock special-input paths are outside this ABI. A coherent
frame proves which pixels were displayed; semantic claims still require an
explicit host pixel or OCR assertion. No key-command reply by itself is a UI
validation.

## Reproducible build

Use a repository checkout, Python 3.10 or newer, an ARM-capable `clang`, and
LLVM's `ld.lld`. `llvm-objdump` is optional for disassembly. The builder accepts
`--clang`, `--linker`, and `--objdump` paths when these tools are not discoverable.
The `--emulate` check also requires Unicorn in the same Python environment:

```bash
python3 -m pip install -e . unicorn
python3 scripts/build_radio_automation.py --help
```

The repository's `uv sync` development environment also includes Unicorn.
The builder and assembly sources under `scripts/` are checkout tools, not
installed console commands. Obtain the official V1.03 updater separately.

Rebuild the complete updater chain from the repository root. Every stage
refuses a source whose complete pinned hash is not the expected predecessor:

```bash
thd75-repack TH-D75_V103_e.exe \
  TH-D75_V103_normal-gm-nor-read.exe \
  --patch normal-gm-nor-read
thd75-repack TH-D75_V103_normal-gm-nor-read.exe \
  TH-D75_V103_usb-recovery-v18.exe \
  --patch normal-gm-nor-read-usb-recover
thd75-extract TH-D75_V103_usb-recovery-v18.exe ./v18-extracted \
  --section FIRMWARE
python3 scripts/build_radio_automation.py --emulate \
  ./v18-extracted/FIRMWARE_0x00200000.bin \
  ./radio-automation-build
thd75-repack TH-D75_V103_usb-recovery-v18.exe \
  TH-D75_V103_azimuth.exe \
  --patch normal-gm-nor-read-usb-recover-azimuth
thd75-patch TH-D75_V103_usb-recovery-v18.exe \
  TH-D75_V103_azimuth.KEX \
  --patch normal-gm-nor-read-usb-recover-azimuth
shasum -a 256 TH-D75_V103_azimuth.exe \
  TH-D75_V103_azimuth.KEX
```

The FIRMWARE-only extraction validates the selected main block, which is the
builder's input. See the [Intel HEX format notes](../docs/FORMAT.md#notes) for
the stock updater's unrelated final-overlay checksum exceptions.

The output contains the twice-built object and ELF files, flat
`radio_automation.bin`, `audit.json`, command log, optional disassembly, and a
fail-closed patch-manifest draft. `--emulate` requires Unicorn and executes the
linked Thumb machine code against command, ABI, CRC, RLE boundary/canary,
unstable-capture, register-preservation, stack-alignment, and virtual-mapping
vectors. KEX, encrypted-resource, and updater hashes are added only after the
normal deterministic patch/repack loop produces those artifacts. The final
patch/repack commands above apply the shipped catalog manifest; the builder's
draft remains an audit output until its complete artifact pins are populated.

## Artifact pins

The builder emits the Azimuth ABI-3 single-guard route runtime and exact
`V1.03.AZM` payload identity. The complete artifact chain is independently
hash-pinned:

| Current Azimuth single-guard route build | SHA-256 or value |
|---|---|
| Pinned source updater | `28e9ae17ab85e7831d04bb7a520e9e735081ea78c22e64e57daafa50f7bce23d` |
| Pinned source FIRMWARE | `239128bca8f608398dc23865c336bd48a00484ea598202a000fd9f5647aa92a6` |
| Payload identity | `V1.03.AZM      \0` at FIRMWARE offset `0xA0` |
| Azimuth FIRMWARE | `e4ee2338b0483acfc4fea2d7cb7805aacf1fdfe2102b2f2252d19e750dfc1c29` |
| Runtime at `0xC019D280`, 1,300 bytes | `3be7e8a35e43e6eb773f9f11a709063a353783688bbc4bf0962f872d72523f71` |
| Azimuth plaintext KEX | `6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d` |
| Azimuth encrypted resource | `3f867a3e00b5f4b24bc6e2ffef117f7a6845e0e1c73aabf2a1b2fe7b1738cb36` |
| Azimuth repacked updater | `14353287f3d56b1829b00f6d0877e5f0915440ba2657f9fa886ed64d05d7a2e4` |
| Main FIRMWARE descriptor checksum | `0x445C` |
| Changed FIRMWARE bytes | `1267` |

The built-in manifest pins the complete source/result chain. For the separate
themed artifact and stack order, see the
[patch catalog](../src/thd75_fw/patches/README.md). The
[flashing guide](../docs/FLASHING.md) owns the exact-artifact admission policy,
offline plan inspection, write acknowledgement, and recovery procedure.

## Live acceptance specification

The following is the required post-flash acceptance sequence for a host
qualifier. The qualifier and menu runner are external to this repository; the
builder's offline emulator does not perform these live checks. The complete
sequence must pass before ordinary menu-audit input:

1. The ABI-3 byte-exact qualifier attests CAT `FV 1.03.AZM`, both patched
   hooks, all 1,300 runtime bytes, the exact ABI reply, aperture bounds, and
   stable invalidated metadata.
2. Without a new snapshot, guarded input returns status `02` and an exact
   missing-snapshot receipt with no dispatch.
3. After a stable top-level Menu snapshot and a deliberate UI change, guarded
   input returns the exact changed-context refusal with no probe dispatch.
4. Against deliberately changed context, command 4 route `991` returns status
   `02`, guard count `1`, completed taps `0`, and event mask `0x00`.
5. From a fresh, independently validated top-level Menu snapshot, one atomic
   route `991` returns status `00`, guard count `1`, completed taps `3`, and
   event mask `0x3F`; the captured result must be exact `Firmware Version` /
   `V1.03`, and the runner must restore and validate its original UI. Menu 991
   intentionally uses a separate five-byte formatter and does not display the
   full CAT suffix.

Predecessor qualification evidence cannot substitute for any Azimuth step. The
word “atomic” in the 991 canary means one non-retried CAT handler transaction
with no host gap between digits; the documented framebuffer-writer TOCTOU
boundary remains.

## Historical evidence

### Predecessor ABI-3 menu audit

The unchanged 1,300-byte ABI-3 runtime and hooks passed live TH-D75A/V1.03
qualification and the full menu audit in the predecessor package on 2026-07-31.
The predecessor runner reported
`FULL_217_ROWS_162_VALUES_14_SAFE_INSPECTIONS_PASS`: all 217 rows were attempted,
located, and restored; all 162 value/information pages and 14 safe inspections
were validated; all 41 editor/action pages remained unentered; and no result
was inconclusive. The before/after 350-page MCP snapshots each contained 89,600
payload bytes and a 90,300-byte raw artifact spanning 400 schema fields. Their
shared SHA-256 was
`d08367d70813f5edb822757cad700416e770b59621741cae632573864439734e`,
and the raw artifacts were byte-identical. The final home oracle proved
146.940 MHz on Band A, the quiet 446.000 MHz baseline on Band B, and operation
band B. The private JSONL/BMP/snapshot evidence bundle is intentionally not
distributed with this repository.

### Superseded overlays

The superseded ABI-2 overlay reached deterministic dual-build checks, Thumb
emulation, manifest/repack pinning, and flasher dry-run, but was never
hardware-qualified. It is superseded by Azimuth and is no longer shipped or
buildable.

The superseded ABI-1 overlay passed deterministic dual-build checks, Thumb
emulation, manifest/repack pinning, flasher dry-run, host-side decoder tests,
and a retained live hardware qualification: the exact artifact flashed in 19.6
seconds, the live qualifier matched every runtime byte, MENU changed 19,658
pixels and produced exact `Menu`, the restore returned exact `146.940`, all four
direction IDs were resolved with selected-label assertions, and Enter opened an
exact `SD Card` screen whose options were read automatically. That overlay is
superseded by Azimuth and is no longer shipped.

### Transfer and OCR measurements

The transport uses the existing hexadecimal `GM` reader. At the measured
34 ms per 256-byte Bluetooth read, one full raw frame takes about 11.6 seconds.
Four real stock D75 captures encoded to 7,137–8,241 bytes with `RLE3`, 8.3–9.5%
of the raw length, reducing a typical validated transfer to roughly one
second. Raw fallback remains available without weakening atomic publication,
pixel checksums, or host assertions.

The hardware runner observed 5,787–18,693-byte RLE frames, taking roughly
0.35–1.2 seconds. Host OCR runs both native pixels and a deterministic 4×
nearest-neighbor representation: the former preserves small menu labels while
the latter makes the large frequency font reliable. Same-text observations are
deduplicated only when their bounds overlap; strict assertions remain exact,
confidence-bounded, ROI-bounded, and unique.
