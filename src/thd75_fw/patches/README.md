# Patch catalog

These seven TOML patches target Kenwood TH-D75 V1.03. They contain byte
expectations, compatibility checks, and the detailed rationale for each change.
List their descriptions with `thd75-list-patches`; see
[Patch format](../../../docs/PATCH_FORMAT.md) to write your own.

Catalog membership does not authorize a native flash. `thd75-flash` admits
seven exact **resulting artifacts**, including stock and one themed stack;
see [supported artifacts](../../../docs/FLASHING.md#supported-artifacts) for
the complete hash list and [flashing procedures](../../../docs/FLASHING.md).

## Choose a patch

| Patch | Purpose | Required base / stack order | Native flashing and evidence |
|---|---|---|---|
| [`pf-screen-capture`](pf-screen-capture.toml) | Enable Screen Capture assignments on front-panel PF1/PF2. | Stock V1.03. | Native dry-run only. Front PF1 capture was verified using a repacked Windows updater. |
| [`service-9r-nor-read`](service-9r-nor-read.toml) | Experimental bounded low-NOR reader through service `9R`. | Exact stock V1.03. | Exact artifact admitted with the service-specific gate; complete the ordered baseline, SETUP controls, and post-flash checks. |
| [`normal-gm-ddr-read`](normal-gm-ddr-read.toml) | Replace normal CAT `GM` with a bounded DDR reader. | Exact stock V1.03; alternative to the NOR reader. | Exact artifact admitted with the DDR gate; reader hardware-qualified on V1.03. |
| [`normal-gm-nor-read`](normal-gm-nor-read.toml) | Replace normal CAT `GM` with a bounded low-NOR reader. | Exact stock V1.03; first stage of the V18/Azimuth chain. | Exact artifact admitted with the NOR-family gate; bounded check and duplicate 2 MiB capture hardware-qualified. |
| [`normal-gm-nor-read-usb-recover`](normal-gm-nor-read-usb-recover.toml) | V18 USB-storage recovery and corrected SD capacity; retarget diagnostic `GM` to DDR. | Exact `normal-gm-nor-read` output. | Exact artifact admitted with the NOR-family gate; USB storage qualified on the tested TH-D75A/card/macOS setup. |
| [`normal-gm-nor-read-usb-recover-azimuth`](normal-gm-nor-read-usb-recover-azimuth.toml) | Azimuth ABI-3 key input and coherent LCD capture, preserving V18 recovery. | Exact V18 output. | Exact artifact admitted with the NOR-family gate. See the artifact-specific qualification status below. |
| [`orange-on-black`](orange-on-black.toml) | Re-skin menu 906's White option as deep orange on black. | Stock display tables and IMAGE_DATA; apply last after a compatible normal-GM stack. | Only the exact Azimuth-plus-orange stack is admitted. Its flash and Orange rendering were verified on 2026-09-24. |

The normal-GM patches replace the original `GM` GPS-mode command; V18 and
Azimuth also change `GW` behavior. Restoring the original behavior requires
a stock reflash. V18 and Azimuth use DDR diagnostics despite the inherited
`normal-gm-nor-read` name; the base NOR capture procedure does not apply to them.

Azimuth is the only shipped automation overlay. Its unchanged ABI-3 runtime
and hooks passed live qualification in the predecessor package on 2026-07-31.
That result does not establish separate qualification of the renamed bare
Azimuth artifact. The themed Azimuth artifact has a later verified flash and
display result, which likewise does not replace the required ABI-3 qualifier.
See [Azimuth status and protocol](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/RADIO_AUTOMATION.md#status) and
the [release history](../../../CHANGELOG.md) for the evidence and limits.

## Build an artifact offline

Both commands read an updater `.exe`. `thd75-patch` produces plaintext `.KEX`;
`thd75-repack` produces a modified Windows updater. Neither contacts a radio.

```bash
thd75-patch TH-D75_V103_e.exe screen-capture.KEX --patch pf-screen-capture
thd75-repack TH-D75_V103_e.exe screen-capture.exe --patch pf-screen-capture
thd75-flash --dry-run screen-capture.KEX
```

For V18, apply the required stages in order directly from the stock updater:

```bash
thd75-patch TH-D75_V103_e.exe usb-recovery-v18.KEX \
  --patch normal-gm-nor-read \
  --patch normal-gm-nor-read-usb-recover
thd75-flash --dry-run usb-recovery-v18.KEX
```

For Azimuth with the orange theme, this complete recipe also starts at stock:

```bash
thd75-patch TH-D75_V103_e.exe azimuth-orange.KEX \
  --patch normal-gm-nor-read \
  --patch normal-gm-nor-read-usb-recover \
  --patch normal-gm-nor-read-usb-recover-azimuth \
  --patch orange-on-black
thd75-flash --dry-run azimuth-orange.KEX
```

Omit the final `--patch orange-on-black` to build bare Azimuth. To generate
an updater instead, use `thd75-repack` with the same ordered flags and an
`.exe` output path. A `.KEX` output is never an input to either patch command.

Each stage verifies its declared section hashes, contexts, byte expectations,
and plaintext-KEX result pin. Repacking also verifies each stage's encrypted
resource result pin. A combined stack checks only the first source-updater
hash and skips single-patch result-updater hashes; skipped updater checks are
reported. To verify each intermediate updater, run successive `thd75-repack`
commands and feed each produced `.exe` into the next stage. See
[stacking semantics](../../../docs/PATCH_FORMAT.md#stacking-patches) for the distinction.

The theme changes data in both FIRMWARE and IMAGE_DATA and bumps the latter's
version so it will be written. It does not change code. MCP-D75 continues to
label the option White. Other generated themes and combinations can be
built and inspected, but do not inherit native flashing admission.

## Related procedures

- [Hardware writes, recovery, and qualification](../../../docs/FLASHING.md)
- [Capture toolkit and its prerequisites](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/CAPTURE.md)
- [Azimuth ABI, rebuild, and acceptance requirements](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/RADIO_AUTOMATION.md)
- [Theme generation and other CLI examples](../../../docs/USAGE.md)
