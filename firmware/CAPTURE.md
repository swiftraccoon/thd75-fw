# Host capture of low NOR

[Firmware tools](README.md) · [Patch catalog](../src/thd75_fw/patches/README.md) ·
[Flashing and recovery](../docs/FLASHING.md)

[`capture_dump.py`](capture_dump.py) checks bounded reads and captures the low
2 MiB NOR region through supported main-firmware handlers. It is a checkout
tool, separate from the installable package's `thd75-flash` command and from the
[unqualified Rust dumper](README.md#hardware-status-no-go). It implements no
service `9E` command and authorizes no firmware write.

| Mode | Required firmware | Result |
| --- | --- | --- |
| `gm-nor-check` | Exact `normal-gm-nor-read` artifact | Attests live patch bytes and checks bounded normal-CAT reads. |
| `gm-nor-dump` | Exact `normal-gm-nor-read` artifact | Repeats the check, then publishes two matching 2 MiB passes. |
| `9r-baseline` | Freshly restored official stock V1.03 | Fixed service-read consistency check; no output file. |
| `9r-patched-check` | Separately audited service-9R artifact | Checks small reads and both bounds after flashing. |
| `9r-dump` | Separately audited service-9R artifact | Repeats the patched check, then requires two matching capture passes. |
| `d75d` | Retained custom payload | Legacy stream receiver; no cleared USB-C/Bluetooth payload transport. |

The GM modes apply only to the base `normal-gm-nor-read` artifact. V18 USB
recovery and Azimuth retarget ordinary GM reads to DDR and require different
live qualifiers. Those qualifier implementations are external to this
repository; see the [catalog](../src/thd75_fw/patches/README.md) and
[Azimuth acceptance specification](RADIO_AUTOMATION.md#live-acceptance-specification).

## Setup

Use a repository checkout and Python 3.10 or newer. From the repository root,
install the package into your Python environment to obtain `pyserial`, then
inspect the capture tool's options:

```bash
python3 -m pip install -e .
python3 firmware/capture_dump.py --help
```

The following commands run from the repository root. Retain a verified
[stock recovery artifact](../docs/FLASHING.md#stock-recovery) before any
modified-firmware experiment. Firmware selection and write prerequisites live
in the [flashing guide](../docs/FLASHING.md), including its
[qualification procedures](../docs/FLASHING.md#qualification).

## CAT preflight

Every audited capture mode runs in the normally powered ordinary UI. Do not
enter `[PTT] + [1]` firmware programming mode for capture.

Before acknowledging the preflight:

1. Use a direct USB-C data cable without a hub.
2. Record Menu 980 as COM + AF/IF Output. Set Menu 405 GPS PC Output and
   Menu 590 APRS PC Output Off.
3. Make KISS and DV/DR inactive. Record DV Gateway state/interface, with the
   selected CAT interface free.
4. Close every other CAT/MCP client and disconnect the unused transport.

Pass `--acknowledge-cat-preflight` only after completing these checks. The
receiver discovers and exclusively opens a TH-D75 USB endpoint with VID:PID
`2166:9023`; an explicit `--port` cannot bypass that identity check. VID:PID
identifies the endpoint, while the front-panel preflight and exact CAT replies
establish operating state. The Python receiver rejects Bluetooth for these
audited modes on every platform.

## Normal-GM NOR capture

This route requires the exact base `normal-gm-nor-read` artifact from the
[catalog](../src/thd75_fw/patches/README.md), followed by a full power cycle into
normal mode. The acknowledgement attests that prerequisite; the receiver still
verifies live patch bytes. After [CAT preflight](#cat-preflight), make the
dedicated check the first GM operation:

```bash
python3 firmware/capture_dump.py --mode gm-nor-check \
  --acknowledge-cat-preflight --acknowledge-gm-nor-read \
  --transport usb --verbose
```

The check reads the exact live base byte and complete patch windows, then
validates 1/16/64/256-byte prefix agreement at low-NOR offset zero and one byte
at `0x1FFFFF`. Capture repeats that gate before any full reads:

```bash
python3 firmware/capture_dump.py --mode gm-nor-dump \
  --acknowledge-cat-preflight --acknowledge-gm-nor-read \
  --transport usb --output thd75-low-nor.bin --verbose
```

The tool reads exactly `0x000000..0x1FFFFF` twice, compares every chunk and both
SHA-256 digests, and publishes only a match. No arbitrary address argument is
exposed. Apart from the exact base probe and four flashed-main attestations,
the host rejects requests outside the 2 MiB window before sending serial bytes.

## Service-9R baseline

The experimental service-9R route starts with untouched stock. Before considering
its modified-main handler, complete the stock USB-C baseline, fixed SETUP
positive controls, and the exact mismatch/repeat control in a separately
power-cycled session with expected result `(1,0)`. Retain a verified stock
restore artifact. See [qualification](../docs/FLASHING.md#qualification) for
the flasher-side controls.

The baseline additionally requires official stock V1.03 to have been freshly
restored and power-cycled, with no modified main firmware written since. `FV`
confirms version, not byte identity. After [CAT preflight](#cat-preflight):

```bash
python3 firmware/capture_dump.py --mode 9r-baseline \
  --acknowledge-cat-preflight \
  --acknowledge-stock-v103-restored \
  --transport usb --verbose
```

The receiver requires exact read-only `ID\r` → `ID TH-D75\r` and
`FV\r` → `FV 1.03\r`, followed by a silent service transition. The normal and
service tables share those identity handlers, so identity replies alone do not
prove normal state. Exact `0G\r` on entry means the session was already dirty
and requires cleanup plus a full power cycle. Any pre-entry proof failure also
requires disconnect and a full power cycle.

The fixed baseline performs duplicate one-byte reads and one 256-byte read,
checks exact service exit, and proves normal CAT return. It writes no dump file.

## Patched service-9R

After the separately audited modified-main write, `9r-patched-check` must be the
first service operation. This mode requires `--allow-patched-9r` and the same
CAT-preflight acknowledgement. It checks 1/16/256-byte reads and both bounds,
then proves exact service exit and normal-CAT return.

`9r-dump` requires the same acknowledgements and repeats that complete check
before its first full-read request. It enters a fresh service session for the
capture and requires two identical passes. The baseline and post-write checks
are separate prerequisites; acknowledging the write never claims the latter has
already succeeded.

## Capture evidence

The base normal-GM NOR route was hardware-qualified on 2026-07-26. Its native
fast flash completed in 41.7 seconds, `gm-nor-check` passed after a full power
cycle, and two matching passes produced a 2,097,152-byte image with SHA-256
`daaf1dbc4750fc200ee8cd33ae57b5c5923e0ea7c01697470efbf751aab47734`.

The captured D75 code establishes the Boot Program slot at NOR offsets
`0x000000..0x01FFFF` (128 KiB) and the FLDM loader slot at
`0x020000..0x05FFFF` (256 KiB). Exact boot validation, copy length, and entry
semantics remain unresolved. The evidence ledger and raw hardware-session
artifacts are retained outside this repository.
