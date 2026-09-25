# Usage

Worked examples for every CLI and the Python library API. For a one-screen
overview and the install instructions, see the [main README](../README.md).

## Extract firmware from updater

```bash
thd75-extract TH-D75_V103_e.exe ./extracted/
```

Stock V1.03 has four nonstandard Intel HEX checksum bytes in the exact
19-byte `CHECKBYTES` and 54-byte `FINAL_ZZZ` final-overlay streams. Full
extraction recognizes only those complete streams at their exact block indices
and physical addresses; any changed byte, address, or order remains fatal. To
extract one independently validated section without exercising that vendor
exception, select it explicitly:

```bash
thd75-extract TH-D75_V103_e.exe ./firmware-only/ --section FIRMWARE
```

Scoped extraction still parses every block's `$SA` metadata, requires exactly
one matching block, and rejects every checksum error in the selected stream.
With `--verify`, only the selected section's standard filename is compared.

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

Patches are TOML files: each declares which firmware bytes to change and what value each byte *must* currently hold (`expect`). Safety-critical patches can additionally pin the complete source/result SHA-256 values, complete source instruction contexts, an exact change count, and the deterministic plaintext-KEX result hash. Every declared check runs before an output file is written.

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

That output is the updater's external **plaintext** KEX container: opaque
metadata bytes and literal `:` Intel HEX lines with canonical CRLF. It is not
the marker-plus-encrypted-hex resource embedded in the `.exe`. `thd75-flash`
reads KEX files as bytes (the stock metadata is not valid UTF-8), rejects an
encrypted resource renamed `.KEX`, and prints the exact input/canonical hashes
during dry-run:

```bash
thd75-flash --dry-run out.KEX
```

For hardware, the current KEX path admits only the exact audited stock V1.03
plaintext SHA-256
`e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e`,
the exact `service-9r-nor-read` plaintext SHA-256
`fa95a673156c2d47b06a85fd6038682bbe1adfcbd1b7bdfdb7529ecfc1ca9541`,
the exact `normal-gm-ddr-read` plaintext SHA-256
`38d435f655d1d999802efba6d116a7aedc41bc2ffdaa662eac7473a37fe7b077`,
the exact `normal-gm-nor-read` plaintext SHA-256
`f619fbb6b6fd91ad5bcdaf85bcc3bcd31483564fc5a5643aad73ce5915f5f30e`,
the exact `normal-gm-nor-read-usb-recover` V18 plaintext SHA-256
`257a93cbefb843c61676e5ca61e03ce4bc72b071658c936757f89477f1fa792a`,
the exact Azimuth automation plaintext SHA-256
`6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d`,
and the exact Azimuth plus `orange-on-black` stack plaintext SHA-256
`c9a42fabbb5accd6da0a459e0238b4e79ce13ce1126127d738e9c317f4487ce2`.
Every other structurally valid KEX—including `pf-screen-capture` at present—is
dry-run-only unless its complete artifact is separately audited and allowlisted.
All `thd75-flash` hardware modes reject a `--port` unless it is currently
enumerated as the TH-D75 USB VID:PID `2166:9023`. Non-write FLDM transports
open the endpoint exclusively. Real writes intentionally leave pyserial's
`exclusive` option unset to reproduce the proven OpenWood-compatible
transport. That identity does not prove FPM—the same VID:PID was captured in
both radio states—so the `[PTT] + [1]` power-on checklist is still mandatory.
Bluetooth serial nodes are never admitted to FLDM.

Real KEX writes are locked to the twice-proven recovery profile: open directly
at 576000, cleartext `FPROMOD`, `BAUD_AND_ACK=12 01`, 256-byte packets with an
ACK after each, BEGIN for every written segment (including `$EL=0` overlays),
`$CT/$ET` plus a 30-second base reply margin, one END_TRANSFER per segment, and
little-endian u32 completion. The CLI rejects unproven 1024-byte or legacy
live-baud-reconfiguration write profiles before opening the serial device.

Only the exact pinned `normal-gm-ddr-read` artifact and all four
`normal-gm-nor-read` family artifacts use a host-pruned plan. Before opening
the transport or sending SETUP, the CLI checks the complete source segment 3
`DATA_0160` recovery descriptor and transmitted payload SHA-256 against their
stock-identical pins. It then omits that segment because its `$VL=0`
descriptor makes the target report a mismatch even when the unchanged 10 MiB
voice database is already present. The resolved dry-run and wire-trace
diagnostics make the omission explicit and preserve the retained source
indices `[0,1,2,4,5,6]`, even though the session necessarily numbers its
six-entry plan contiguously.

`--force-all-segments` is dry-run-only and retains all seven source segments
for offline comparison. The stock V1.03 recovery artifact always retains its
complete seven-segment plan so it can repair `DATA_0160`; it never inherits the
normal-GM omission. A hardware-qualified fast-path run completed in 42.0
seconds instead of the earlier 207.1 seconds. It rewrote and verified the full
2,621,440-byte main firmware and both overlays; the retained six-SETUP trace
contains no `DATA_0160` SETUP.

The exact `normal-gm-nor-read` FIRMWARE differs from the qualified DDR reader
by one byte at flat offset `0x6F8A0`: `C0` becomes `60`, retargeting the same
reader to CPU-visible NOR at `0x60000000`. Its real write requires
`--acknowledge-gm-nor-read-write` in addition to any `--yes`. After a full
power cycle, the dedicated normal-CAT check must be the first GM operation:

```bash
python3 firmware/capture_dump.py --mode gm-nor-check \
  --acknowledge-cat-preflight --acknowledge-gm-nor-read \
  --transport usb --verbose
```

The check first reads the exact live base byte and full patch windows from
known main-firmware addresses, then validates 1/16/64/256-byte prefix agreement
at low-NOR offset zero and one byte at `0x1FFFFF`. The full capture mode repeats
that gate, reads exactly `0x000000..0x1FFFFF` twice, compares every chunk and
both SHA-256 digests, and publishes only a match:

```bash
python3 firmware/capture_dump.py --mode gm-nor-dump \
  --acknowledge-cat-preflight --acknowledge-gm-nor-read \
  --transport usb --output thd75-low-nor.bin --verbose
```

No arbitrary GM address is exposed. Apart from the exact one-byte base probe
and four flashed-main attestations, the host rejects every request outside the
2 MiB candidate window before writing any serial bytes.

The exact route was hardware-qualified on 2026-07-26. The native fast flash
completed in 41.7 seconds; `gm-nor-check` passed; and two matching capture
passes produced a 2,097,152-byte image with SHA-256
`daaf1dbc4750fc200ee8cd33ae57b5c5923e0ea7c01697470efbf751aab47734`.
The D75 boot code itself proves the Boot Program slot is
`0x000000..0x01FFFF` and the FLDM loader slot is
`0x020000..0x05FFFF`.

The V18 USB-recovery patch must be applied to the exact hash-pinned
`normal-gm-nor-read` updater, not directly to the stock updater:

```bash
thd75-repack TH-D75_V103_e.exe \
  TH-D75_V103_normal-gm-nor-read.exe \
  --patch normal-gm-nor-read
thd75-patch TH-D75_V103_normal-gm-nor-read.exe \
  TH-D75_V103_usb-recovery-v18.KEX \
  --patch normal-gm-nor-read-usb-recover
thd75-flash TH-D75_V103_usb-recovery-v18.KEX \
  --port /dev/cu.usbmodemXXXX --cleartext --reference-transport \
  --acknowledge-gm-nor-read-write --yes
```

The manifest refuses any other source/result chain. V18 corrects the stock
off-by-one sector count, preserves asynchronous USB storage ownership, and
services every host READ request through bounded repeated stock CMD17 reads.
It also retargets the diagnostic GM reader to DDR so the sibling Rust
qualifier can attest live code and telemetry; it adds no NOR-write primitive.
On the tested TH-D75A/card/macOS setup, the exact artifact flashed in 19.3
seconds, automatically enumerated as VID:PID `2166:9024`, mounted as FAT32,
and passed 93 read operations over 2,604 sectors with no failure or recovery.

The Azimuth manifest, `normal-gm-nor-read-usb-recover-azimuth`, uses that exact
hash-pinned source updater. It pins its required source updater, complete
source/result FIRMWARE, plaintext KEX, encrypted resource, and repacked
updater. It is the only shipped automation overlay: the earlier automation
overlays it supersedes are no longer shipped, their catalog patches and write
admission are removed, and nothing in the catalog builds them.

```bash
thd75-repack TH-D75_V103_usb-recovery-v18.exe \
  TH-D75_V103_azimuth.exe \
  --patch normal-gm-nor-read-usb-recover-azimuth
thd75-patch TH-D75_V103_usb-recovery-v18.exe \
  TH-D75_V103_azimuth.KEX \
  --patch normal-gm-nor-read-usb-recover-azimuth
```

Azimuth preserves V18 USB-storage recovery and ordinary DDR `GM` reads, then
adds bounded key events plus seqlocked raw/RLE LCD publication from stable
double-copy snapshots. A host must attest the exact live runtime, accept
matching even-generation metadata around the pixel read, verify CRC-32, and
make an explicit pixel/OCR assertion; a successful key reply alone is not
evidence that the UI changed. See
[`firmware/RADIO_AUTOMATION.md`](../firmware/RADIO_AUTOMATION.md) for the
protocol, the pinned artifact chain, and the retained hardware records.

The guarded single-key command `GM Ghh,Pss` dispatches only if the live
framebuffer exactly matches the last stable snapshot. The guard samples the
complete framebuffer and compares that offline copy with the last stable
snapshot before synchronous dispatch; this is not an atomic framebuffer
transaction. Every exact `GM A000000\r` ABI query first invalidates the prior
guarded-input lease under the metadata seqlock. It retains the monotonic
generation and may retain old raw bytes, but publishes an unstable capture
result with zero CRC, attempts, and RLE length, records command `0`, and
dispatches no input. Re-running qualification therefore cannot reuse a
snapshot from an earlier session; a guarded command must refuse until the host
completes a new validated capture.

The three-decimal-digit route `GM Rddd,ss` makes one complete framebuffer
sample and comparison before the first digit, then synchronously dispatches
all three zero-hold press/release pairs without another guard or host turn.
The initial context is therefore authenticated while the stock numeric-entry
redraw after digit one does not invalidate the remaining digits. ABI 3
receipts admit only two route outcomes: refusal before any input (`guard count
1`, completed taps `0`, event mask `0x00`) or complete success (`guard count
1`, completed taps `3`, event mask `0x3F`). Status `02` therefore always
authenticates an empty prefix, never an unauthenticated guess.

The exact Azimuth artifact chain is:

- payload identity: `V1.03.AZM      \0` at FIRMWARE offset `0xA0`
- FIRMWARE: `e4ee2338b0483acfc4fea2d7cb7805aacf1fdfe2102b2f2252d19e750dfc1c29`
- runtime at `0xC019D280`, 1,300 bytes: `3be7e8a35e43e6eb773f9f11a709063a353783688bbc4bf0962f872d72523f71`
- plaintext KEX: `6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d`
- encrypted resource: `3f867a3e00b5f4b24bc6e2ffef117f7a6845e0e1c73aabf2a1b2fe7b1738cb36`
- repacked updater: `14353287f3d56b1829b00f6d0877e5f0915440ba2657f9fa886ed64d05d7a2e4`
- main FIRMWARE descriptor checksum: `0x445C`

Inspect and write only that exact KEX with the existing automation/NOR gate:

```bash
thd75-flash --dry-run TH-D75_V103_azimuth.KEX
thd75-flash TH-D75_V103_azimuth.KEX \
  --port /dev/cu.usbmodemXXXX --cleartext --reference-transport \
  --acknowledge-gm-nor-read-write --yes
```

The first post-flash operation must be the ABI-3 byte-exact qualifier, including
the exact CAT reply `FV 1.03.AZM`. Before any audit key, the live runner must
then prove: query invalidation causes a
missing-snapshot guarded refusal; a deliberate framebuffer change causes a
guarded-key changed-context refusal; stale context causes command 4 to refuse
route 991 with the exact zero-prefix receipt; and a fresh authenticated
top-level Menu snapshot permits one atomic `991` command that reports the full
receipt and opens exact `Firmware Version` / `V1.03`, followed by validated UI
restoration. Menu 991 still renders `V1.03`; its UI formatter is independent of
the full CAT identity. The hardware records of the superseded automation
overlays do not qualify Azimuth. The unchanged 1,300-byte ABI-3 runtime and
hooks passed live TH-D75A/V1.03 qualification and the full menu audit on
2026-07-31 in the package that preceded the identity rename, and the Azimuth
plus `orange-on-black` stack wrote and verified FIRMWARE, IMAGE_DATA and both
overlays through the fast plan on the TH-D75 on 2026-09-24; see
[`CHANGELOG.md`](../CHANGELOG.md).

The first native qualification attempt failed mid-segment on 2026-07-26. The
transport-ordering repair then completed a native stock recovery in 204.5
seconds. The session records, traces, and logs behind these hardware results
are kept outside the repository.

Native-flasher hardware qualification has an additional stock-only gate:

```bash
thd75-flash recovery/TH-D75_V103_stock_plaintext.KEX \
  --port /dev/cu.usbmodemXXXX \
  --cleartext --cleartext-baud 576000 --chunk-size 256 \
  --reference-transport \
  --qualification-rewrite-stock-image-data \
  --wire-trace recovery/native-qualification.trace
python -m thd75_fw.flash.qualification \
  recovery/native-qualification.trace
```

This is not a routine force-write option. It is admitted only for the exact
stock KEX and exact retained `IMAGE_DATA` payload, refuses an existing trace
path, and selectively rewrites segment 1 even when SETUP reports it current.
A valid proof has every other body segment current except `DATA_0160`, whose
stock descriptor carries no version bytes, so the loader requests it on every
run and it is rewritten with its unchanged stock payload. It transfers the two
normal stock overlays and reports exactly segments `[1,3,5,6]`, 42,370 chunks,
and 10,846,242 bytes. The trace includes local paths and short firmware-byte
samples; retain it as private evidence rather than committing it.

The exact service-9r artifact has a second, artifact-specific real-write gate:
`--acknowledge-service-9r-write`. It is required in addition to any `--yes` and
attests, in order, that the untouched-stock USB-C `9R` baseline passed; the
fixed SETUP positive controls passed; a separately power-cycled exact
mismatch/repeat SETUP returned `(1,0)`; and a verified stock restore artifact
is retained. It does not claim that a patched read has already succeeded. The
standalone `9r-patched-check` must be the first post-flash service operation;
`9r-dump` also repeats that complete 1/16/256-byte and bounds gate before its
first full-read request. The write flag is rejected for stock/unpinned KEX
files and for dry-run, raw, probe, or SETUP modes.

Raw images have no hardware-write allowlist at present. `thd75-flash --raw`
accepts only `--dry-run` for offline descriptor/packet inspection; the retained
custom dumper returns data over physical UART0 and therefore has no permitted
USB-C/Bluetooth capture path. A real raw write stays disabled until an allowed
transport payload and its complete artifact hash are separately audited and
pinned. For offline inspection only:

```bash
thd75-flash --dry-run --raw payload.bin \
  --flash-addr 0x00200000 --complete-code 0x1DB0
```

Every host-side service `9R` mode runs in the normally powered ordinary UI, not
`[PTT] + [1]` firmware programming mode. For USB-C, use a direct data cable with
no hub. Record Menu
980 as COM + AF/IF Output, set Menu 405 GPS PC Output and Menu 590 APRS PC
Output Off, make KISS and DV/DR inactive, and record DV Gateway state/interface
with the selected CAT interface not consumed. Close all other CAT/MCP clients
and disconnect the unused transport. Only then pass the required acknowledgement.
The normal and service tables share `ID` and `FV`, so those replies do not prove
normal state. The receiver requires exact read-only `ID\r` -> `ID TH-D75\r` and
`FV\r` -> `FV 1.03\r`, then a silent service transition. Exact `0G\r` means the
session was already dirty and requires cleanup plus a full power-cycle. Baseline
also requires truthful attestation that official stock V1.03 was freshly
restored and power-cycled. FV confirms version only:

```bash
python3 firmware/capture_dump.py --mode 9r-baseline \
  --acknowledge-cat-preflight \
  --acknowledge-stock-v103-restored \
  --transport usb --verbose
```

USB-C is auto-discovered and exclusively opened only when enumeration reports
the TH-D75 VID:PID `2166:9023`; an explicit port cannot bypass that check. That
VID:PID identifies the radio endpoint but is not accepted as proof of normal CAT
rather than FLDM—the normal-power/front-panel attestation and byte-exact CAT
proof establish state. Any pre-entry proof failure requires disconnect and a
full power-cycle. The Python receiver rejects pyserial Bluetooth paths on every platform.
The sibling thd75-repl project now has the same fixed byte-exact
baseline sequence, bypassing its incorrect typed service API, but deliberately
admits only an exclusively opened TH-D75 USB endpoint. It refuses native
Bluetooth before opening it: a canceled IOBluetooth `writeSync` can outlive its
Rust future and make bounded service cleanup impossible. Normal native-Bluetooth
CAT remains hardware-proven; exact service-mode SPP is not yet qualified. This
is a fixed 258-byte consistency check with no output file, not another dumper.

Apply your own patch from a TOML file by passing its path:

```bash
thd75-repack TH-D75_V103_e.exe out.exe --patch ./my-patch.toml
```

A patch file looks like this:

```toml
name        = "my-patch"
description = "What this patch does and why."
target_firmware = "TH-D75 V1.03"
source_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" # replace
result_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" # replace
result_kex_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" # replace
# Optional exact-repack chain (used by service-9r-nor-read):
source_updater_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" # replace
result_encrypted_resource_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" # replace
result_updater_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" # replace
change_count = 1

[[contexts]]
offset = 0x10444
expect = "1B 29" # complete original instruction/context bytes

[[changes]]
offset = 0x10444  # flat-image byte offset
expect = 0x1B    # current value (refuse to write if firmware differs)
value  = 0x33    # new value
```

The patched `.exe` flashes exactly like the official updater — only the patched bytes (and the Intel HEX record checksums covering them, plus the firmware block's `$CA` checksum) differ from the official image; every other byte is left identical. Both patch commands complete every integrity check in memory, then flush and fsync a temporary file beside the destination before atomically replacing the requested output path; a failed write leaves an existing output intact.

### Sections, hash pins per section, and byte runs

A change or context may name the section it patches; the default is
`FIRMWARE`. `[sections.<NAME>]` pins that section's raw image before and
after patching. `expect` and `value` may be equal-length hex strings: every
differing byte becomes a change and the whole window is pinned as context.

```toml
[sections.IMAGE_DATA]
source_sha256 = "..."
result_sha256 = "..."

[[changes]]
section = "IMAGE_DATA"
offset = 0x56F10
expect = "00 00 FF FF F8 1F"
value  = "00 00 60 FC F8 1F"
```

`change_count` counts single-byte changes after expansion. `version` under
`[sections.<NAME>]` rewrites that block's `$VA` at the same length; the
loader's SETUP compares `$VA` with the bytes at `$SA+$VS` on the radio and
writes the segment only when they differ.

### Stacking patches

`--patch` may repeat on `thd75-patch` and `thd75-repack`. Patches apply in
the order given; each is verified against the output of the previous one,
and each patch's result pins are checked on its own stage. A patch meant to
stack pins only what its own stage determines. Only the first stage's
`source_updater_sha256` is checked against the official updater; later stages
pin the exe chain that built them, which the KEX path never materialises.

```bash
thd75-patch TH-D75_V103_e.exe azm-orange.KEX \
  --patch normal-gm-nor-read --patch normal-gm-nor-read-usb-recover \
  --patch normal-gm-nor-read-usb-recover-azimuth --patch orange-on-black
```

`thd75-patch` prints the SHA-256 of the rendered plaintext KEX. `thd75-flash`
admits only audited hashes to a real write; a stacked artifact needs its own
admission entry after review.

The catalog includes:

- `pf-screen-capture`, which widens the front-panel PF-key decoders' lookup-table scan so front PF1/PF2 can be assigned Screen Capture.
- `service-9r-nor-read`, an experimental, hash-pinned 19-byte edit to the existing V1.03 service CAT `9R` handler. It reads the first two MiB of CPU-visible NOR while leaving the stock source-aware CAT response path untouched; it adds no dumper, handler, code cave, or flash-write operation. Its repack path additionally pins the complete official input updater, patched encrypted resource, and final output updater hashes. This does not prove Bluetooth SPP service-mode reachability. Baseline stock `9R` and its maximum response over USB-C before considering a flash, and start any patched-radio test with a one-byte USB-C read.

- `orange-on-black`, a data-only display theme generated by `thd75-theme`: the "White" option of menu 906 becomes deep orange (255,140,0) on black. It recolours the White palette set, the White text palette and 127 icon twins, inverts the two per-scheme digit palettes in place, and relabels the option "Orange". It pins IMAGE_DATA but not the whole FIRMWARE image, so it stacks on the normal-GM family firmware.

Inspect any entry with `thd75-list-patches` for its exact changes and rationale.

**Reflashing firmware carries inherent risk.** Use a fully charged radio.

## Recover with stock firmware

This procedure writes stock firmware and is appropriate only when a deliberate
main-slot experiment has already occurred and the FLDM loader is intact.

The updater's embedded firmware resource is encrypted text, not an external
plaintext KEX. Renaming an extracted copy does not decrypt it, and
`thd75-flash` rejects it before any device I/O.

Generate the untracked canonical recovery artifact from the exact official
updater. This command pins both the source updater and rendered result and does
not contact hardware:

```bash
uv run python - <<'PY'
from hashlib import sha256
from pathlib import Path
from thd75_fw import kex, resource

source = Path("ref/TH-D75_V103_E/TH-D75_V103_e.exe")
output = Path("recovery/TH-D75_V103_stock_plaintext.KEX")
source_expected = "a76f0c80525c942c983bd62494109e15270380a6b5964d6c2a6b4726331f60ad"
result_expected = "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"

if sha256(source.read_bytes()).hexdigest() != source_expected:
    raise SystemExit("official updater SHA-256 mismatch")
plaintext = kex.render(kex.parse_encrypted_resource(resource.load(source)))
if sha256(plaintext).hexdigest() != result_expected:
    raise SystemExit("rendered stock plaintext KEX SHA-256 mismatch")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(plaintext)
print(f"{result_expected}  {output}")
PY
```

Keep the 43,137,429-byte result out of version control: it contains Kenwood
firmware.

**Raw bootloader writes are not supported. Never pass
`--flash-addr 0x00000000`.** `--raw` accepts only the main-firmware start
`0x00200000`, and every `--raw` invocation is dry-run-only.

Before a recovery write:

1. Disconnect USB and external power, remove the battery if state appears stuck,
   then restore power.
2. Validate the exact plaintext container and complete flash plan offline:

   ```bash
   thd75-flash --dry-run recovery/TH-D75_V103_stock_plaintext.KEX
   ```

   The log must identify `canonical plaintext external KEX`, print the stock
   SHA-256 above twice (input and canonical render), identify the audited stock
   artifact, and resolve all seven segments without opening a serial device.
3. Hold `[PTT] + [1]` while powering on to enter firmware programming mode.
4. Use only the pinned artifact and hardware-qualified native cleartext USB-C
   profile:

   ```bash
   thd75-flash recovery/TH-D75_V103_stock_plaintext.KEX \
     --port /dev/cu.usbmodemXXXX \
     --cleartext --cleartext-baud 576000 --chunk-size 256 \
     --reference-transport
   ```

   Real KEX writes select the reference transport automatically; the explicit
   flag documents the locked control profile and is harmlessly redundant.

5. To qualify the native implementation itself on an already-current stock
   radio, use the separately gated selective rewrite and a new private trace:

   ```bash
   thd75-flash recovery/TH-D75_V103_stock_plaintext.KEX \
     --port /dev/cu.usbmodemXXXX \
     --cleartext --cleartext-baud 576000 --chunk-size 256 \
     --reference-transport \
     --qualification-rewrite-stock-image-data \
     --wire-trace recovery/native-qualification.trace
   python -m thd75_fw.flash.qualification \
     recovery/native-qualification.trace
   ```

   The flag is exact-stock-only and forces only segment 1 `IMAGE_DATA`. The
   loader also requests segment 3 `DATA_0160` on every run, because its stock
   descriptor carries no version bytes, so the stock plan rewrites it
   unchanged. Qualification passes only when segments `[1,3,5,6]` are written:
   42,370 chunks and 10,846,242 bytes. The trace records local paths and short
   firmware-byte samples, so keep it private and never reuse or overwrite its
   path.
6. If any step fails, record the exact verb, response bytes, display state, and
   timestamps. Power-cycle and diagnose before considering another write; do not
   blindly retry a transient-looking failure.
7. After a successful stock update, power off, disconnect USB, hold `[F]` while
   powering on, select `Full Reset`, press `[A/B]`, and press `[A/B]` again.

## Generate a display theme

`thd75-theme` derives a patch that re-skins menu 906's "White" option. It reads
the stock FIRMWARE and IMAGE_DATA sections (from the updater or extracted
files), recolours the White palette set, the White text palette and the
white-scheme icon twins to one theme colour on black, inverts the two
per-scheme digit palettes in place, relabels the option "Orange", and bumps the
IMAGE_DATA header version to 1.00.02.01 so the loader's SETUP check writes the
section instead of reporting it current.

```bash
thd75-theme orange-on-black.toml --exe TH-D75_V103_e.exe
thd75-theme amber.toml --exe TH-D75_V103_e.exe --rgb 255,191,0 --name amber-on-black
thd75-theme out.toml --firmware FIRMWARE_0x00200000.bin --image-data IMAGE_DATA_0x00600000.bin
```

The catalog entry `orange-on-black` is this tool's output for deep orange
(255,140,0). It pins IMAGE_DATA but not the whole FIRMWARE image, so it
applies to stock V1.03 and, stacked, to the normal-GM family firmware. MCP-D75
keeps labelling the option "White".

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
