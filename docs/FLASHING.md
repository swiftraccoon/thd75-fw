# Flashing and recovery

`thd75-flash` validates a plaintext `.KEX` and can write the exact admitted
TH-D75 V1.03 artifacts over USB serial. Start with an offline dry-run and
retain a verified stock recovery artifact before using a patched image.
Reflashing carries inherent risk; use a fully charged radio.

For artifact construction, use the [patch catalog](../src/thd75_fw/patches/README.md).
For extraction and other commands, see [Usage](USAGE.md).

## Supported artifacts

The flasher logs both the input-file hash and the canonical rendered
plaintext hash. Hardware admission uses the latter and requires one of these
exact artifacts; a compatible patch name or version string is insufficient.

| Resulting artifact | Canonical plaintext KEX SHA-256 |
|---|---|
| Official V1.03 stock | `e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e` |
| `service-9r-nor-read` | `fa95a673156c2d47b06a85fd6038682bbe1adfcbd1b7bdfdb7529ecfc1ca9541` |
| `normal-gm-ddr-read` | `38d435f655d1d999802efba6d116a7aedc41bc2ffdaa662eac7473a37fe7b077` |
| `normal-gm-nor-read` | `f619fbb6b6fd91ad5bcdaf85bcc3bcd31483564fc5a5643aad73ce5915f5f30e` |
| `normal-gm-nor-read-usb-recover` V18 | `257a93cbefb843c61676e5ca61e03ce4bc72b071658c936757f89477f1fa792a` |
| Azimuth (`V1.03.AZM`) | `6566a986c612204c7c248895d4719af569a9566db1f72dc0d086a021bb1a152d` |
| Azimuth plus `orange-on-black` | `c9a42fabbb5accd6da0a459e0238b4e79ce13ce1126127d738e9c317f4487ce2` |

Other structurally valid KEX files, including `pf-screen-capture`, are
dry-run-only. Admission is separate from hardware qualification: consult the
[catalog status](../src/thd75_fw/patches/README.md#choose-a-patch) for each
artifact's evidence and limitations.

An external KEX contains literal `:` Intel HEX records with opaque metadata;
the metadata need not be UTF-8. The encrypted resource embedded in an updater
is a different representation. Renaming that resource `.KEX` does not decrypt
it. Use the uppercase `.KEX` extension expected by the CLI.

## Offline inspection

```bash
thd75-flash --dry-run IMAGE.KEX
thd75-flash --dry-run IMAGE.KEX --force-all-segments
```

Dry-run validates the input and resolved descriptors without opening a serial
device. Check the audited artifact label, canonical hash, source-segment
indices, verification ranges, and any host omission. `--force-all-segments`
is an offline comparison option and is rejected for a real write.

Raw payloads are also dry-run-only:

```bash
thd75-flash --dry-run --raw payload.bin \
  --flash-addr 0x00200000 --complete-code 0x1DB0
```

Raw inspection is limited to the main-firmware slot at `0x00200000`.
Do not pass `--flash-addr 0x00000000`: raw bootloader writes are not supported.
The retained experimental Rust dumper emits through physical
UART0 and has no admitted USB-C/Bluetooth return path; see
[firmware status](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/README.md).

## Hardware writes

1. Retain the verified [stock recovery artifact](#stock-recovery), and complete
   the prerequisites for the intended patch below.
2. Run the offline dry-run and check it against [supported artifacts](#supported-artifacts).
3. Close other serial/CAT/MCP clients. Power the fully charged radio off, then
   hold `[PTT] + [1]` while powering on to enter Firmware Programming Mode.
4. Connect a direct USB data cable and select its currently enumerated
   TH-D75 USB endpoint explicitly with `--port`.
5. Run the write with the required artifact-specific acknowledgement, then
   power-cycle and complete that artifact's required first post-flash check.

Every hardware mode requires a currently enumerated TH-D75 VID:PID
`2166:9023` port. Bluetooth and unrelated serial devices are rejected. This
USB identity occurs in both normal CAT and programming states, so it does
not replace the front-panel programming-mode check.

For example, after satisfying the Azimuth prerequisites below, the artifact
built by the [catalog recipe](../src/thd75_fw/patches/README.md#build-an-artifact-offline)
uses:

```bash
thd75-flash azimuth-orange.KEX \
  --port /dev/cu.usbmodemXXXX \
  --cleartext --cleartext-baud 576000 --chunk-size 256 \
  --reference-transport --acknowledge-gm-nor-read-write
```

Replace the example port with the enumerated endpoint for your platform.
`--yes` skips the ordinary confirmation only; it never substitutes for a
patch-specific acknowledgement. Omit acknowledgement flags during dry-run.

| Artifact | Required write acknowledgement | Prerequisites and first post-flash operation |
|---|---|---|
| Stock | None | Use the recovery procedure below. |
| Service `9R` | `--acknowledge-service-9r-write` | In order: untouched-stock USB-C baseline, positive SETUP controls, full power cycle, exact mismatch/repeat SETUP result `(1,0)`, another full power cycle, verified stock restore retained. After flashing, `9r-patched-check` must be the first service operation. |
| Normal-GM DDR | `--acknowledge-gm-ddr-read-write` | Prove programming-mode entry on stock, retain the verified stock restore, and fully charge the radio. First run the escalating read probe and an out-of-bounds request that is rejected. |
| Normal-GM NOR | `--acknowledge-gm-nor-read-write` | Retain stock restore and audit the one-byte read-base delta from the qualified DDR reader. After power-cycling, `gm-nor-check` must be the first GM operation. |
| V18 USB recovery | `--acknowledge-gm-nor-read-write` | Retain stock restore; audit the base NOR patch's one-byte delta and the pinned V18 chain. First run the external `usb_apply_trigger attest-trigger`, then its one-shot `qualify` action after USB storage re-enumerates. |
| Either Azimuth artifact | `--acknowledge-gm-nor-read-write` | Retain stock restore; audit the base NOR patch's one-byte delta and the pinned Azimuth chain. First run the ABI-3 byte-exact qualifier, then the missing-snapshot, changed-context, command-4 zero-prefix, and atomic-991 canaries before any audit key. |

The shipped [capture toolkit](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/CAPTURE.md) documents the service
and base-NOR checks. The standalone DDR probe, V18 `usb_apply_trigger` host,
and Azimuth live qualification runner are maintainer prerequisites whose
implementations and installation instructions are **not shipped here**.
The Azimuth [acceptance specification](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/RADIO_AUTOMATION.md#live-acceptance-specification)
defines the required behavior; its offline build/emulation checks do not
replace that live runner. Do not treat these write examples as a complete
hardware procedure without access to the required qualifier.

### Transport and segment policy

Real writes are locked to the proven D75 transport: direct-open 576000 baud,
cleartext `FPROMOD`, `12 01`, 256-byte packets with an ACK after each, BEGIN
for every written segment (including `$EL=0` overlays), `$CT/$ET` plus a
30-second base reply margin, one END_TRANSFER per segment, and little-endian
u32 completion. `--reference-transport` is selected automatically for real
KEX writes; the explicit flag in examples records that choice. Real writes
leave pyserial's `exclusive` option unset to preserve the proven transport.
Probe and default SETUP transports open the endpoint exclusively; SETUP
calibration can also select the reference profile, which leaves it unset.

The exact DDR reader and four NOR-family artifacts use a fast plan. Before
serial I/O, the host verifies source segment 3's entire `DATA_0160` descriptor
and transmitted payload against stock pins, then omits that unchanged 10 MiB
voice database. Its `$VL=0` descriptor otherwise requests a rewrite on every
run. Dry-run and trace output preserve the retained source indices
`[0,1,2,4,5,6]`; the internal six-entry plan has its own contiguous indices.
The themed artifact still writes changed IMAGE_DATA. Stock recovery always
retains all seven segments so it can repair the voice database.

## Stock recovery

This procedure restores the stock main firmware and data when the FLDM
loader is intact. It does not repair a damaged bootloader.

Generate a canonical recovery KEX from the official V1.03 updater. This
offline script verifies both source and output before writing; adjust the
source path to your local copy. Run it with Python in an environment where
`thd75-fw` is installed (or `uv run python` in a checkout):

```python
from hashlib import sha256
from pathlib import Path
from thd75_fw import kex, resource

source = Path("TH-D75_V103_e.exe")
output = Path("recovery/TH-D75_V103_stock_plaintext.KEX")
source_expected = "a76f0c80525c942c983bd62494109e15270380a6b5964d6c2a6b4726331f60ad"
result_expected = "e62da10cfb0bb42e1b68f077858d0c64cf26e52818f05ba9d39efa6f9107259e"

if sha256(source.read_bytes()).hexdigest() != source_expected:
    raise SystemExit("official updater SHA-256 mismatch")
plaintext = kex.render(kex.parse_encrypted_resource(resource.load(source)))
if sha256(plaintext).hexdigest() != result_expected:
    raise SystemExit("rendered stock plaintext KEX SHA-256 mismatch")
output.parent.mkdir(parents=True, exist_ok=True)
with output.open("xb") as destination:
    destination.write(plaintext)
print(f"{result_expected}  {output}")
```

The 43,137,429-byte result contains Kenwood firmware; keep it out of version
control. The script refuses to overwrite an existing recovery file.

1. Disconnect USB and external power. If the radio state appears stuck,
   remove the battery, then restore power.
2. Validate the recovery file offline:

   ```bash
   thd75-flash --dry-run recovery/TH-D75_V103_stock_plaintext.KEX
   ```

   Expect the stock hash for both input and canonical render, the audited
   stock label, and all seven source segments.
3. Enter Firmware Programming Mode with `[PTT] + [1]`, connect USB, and write:

   ```bash
   thd75-flash recovery/TH-D75_V103_stock_plaintext.KEX \
     --port /dev/cu.usbmodemXXXX \
     --cleartext --cleartext-baud 576000 --chunk-size 256 \
     --reference-transport
   ```

4. After success, power off and disconnect USB. Hold `[F]` while powering on,
   select `Full Reset`, press `[A/B]`, then press `[A/B]` again.

If any step fails, record the exact operation, response bytes, display state,
and timestamps. Disconnect and fully power-cycle before diagnosis; do not
blindly retry a failed write.

## Qualification

Native-flasher qualification is a separate stock-only operation on an
already-current stock radio. It deliberately forces `IMAGE_DATA` to exercise
the write path; it is not a routine force-write option. Prepare the recovery
artifact and follow the same programming-mode and USB prerequisites first.

```bash
thd75-flash recovery/TH-D75_V103_stock_plaintext.KEX \
  --port /dev/cu.usbmodemXXXX \
  --cleartext --cleartext-baud 576000 --chunk-size 256 \
  --reference-transport \
  --qualification-rewrite-stock-image-data \
  --wire-trace recovery/native-qualification.trace
python -m thd75_fw.flash.qualification recovery/native-qualification.trace
```

The gate admits only the exact stock KEX and retained IMAGE_DATA payload and
requires a new trace path. It forces source segment 1; the loader also requests
unchanged source segment 3 `DATA_0160` because its descriptor has no version
bytes. A valid trace reports only segments `[1,3,5,6]` written: 42,370 chunks
and 10,846,242 bytes, including the two stock overlays. Other body segments
must report current. Qualification retains the ordinary confirmation unless
`--yes` is supplied.

Wire traces contain local paths and short firmware-byte samples. Keep them
private, use a new filename for each run, and preserve the corresponding
artifact and logs. The stock trace validator does not qualify a patched
artifact or replace its required post-flash checks.

## Diagnostics and troubleshooting

- A rejected artifact, encrypted-resource error, or wrong packet-size error
  occurs before serial I/O. Rebuild from the required source, inspect the
  dry-run hashes, and use the admitted profile.
- A port rejection means the endpoint is not currently enumerated as the
  expected TH-D75 USB device. An explicit unrelated port cannot bypass this
  check; reconnect the radio and confirm its front-panel state.
- `--probe-only` performs the unlock probe; `--probe-target` additionally
  enters the loader and reads target identity. Neither sends a NOR-write
  verb, but both change loader state. Disconnect USB and fully power-cycle
  afterward. SETUP calibration modes are specialist preflight operations,
  documented with the [capture workflow](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/CAPTURE.md).
- The CLI's Full Reset reminder is for successful updates. Follow the
  artifact-specific first-operation requirements before attempting any
  capture or automation, and retain failure evidence before another write.

For protocol fields and file layout, see [Format reference](FORMAT.md).
Historical timings and hardware receipts belong in [CHANGELOG.md](../CHANGELOG.md)
and the relevant specialist reference.
