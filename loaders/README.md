# IDA Pro and Ghidra setup scripts

[Project](../README.md) · [Extraction usage](../docs/USAGE.md#extract-firmware-from-updater) ·
[Firmware format](../docs/FORMAT.md)

Drop-in scripts that configure your reverse-engineering tool of choice
for binaries produced by `thd75-extract`. They eliminate the manual
processor / segment / vector setup that's otherwise required for raw
ARM .bin files with no header.

## IDA Pro — `ida_thd75.py`

### Recommended workflow

Open the binary with the ARM processor selected up-front:

```bash
ida -A -pARM FIRMWARE_0x00200000.bin
```

Then in IDA: `File > Script File...` → select
[`ida_thd75.py`](ida_thd75.py). The script:

1. Verifies the processor is `arm` (offers recovery instructions if not).
2. Sets the segment to RWX, 32-bit (IDA refuses code creation otherwise).
3. **Maps the main image at runtime DDR `0xC0000000`**. Thus flat-image
   offset `N` is address `0xC0000000 + N`, and the image's `0xC0xxxxxx`
   pointers resolve to handler bodies in the same extracted blob. Other
   sections map to CPU-visible NOR (`0x60000000 + filename offset`). Set
   `REBASE_TO_ANALYSIS_ADDRESS = False` to keep file-offset zero.
4. For `FIRMWARE`: marks the 7 active ARM exception vector slots as code
   (slot `0x14` is reserved on ARMv5+ and decoded as data), names them
   (`reset_vector`, `irq_vector`, etc.), labels the literal pool as 8
   dword handler addresses, and runs cascade auto-analysis. On V1.03
   this typically yields 15,000+ functions.
5. For data sections (DATA_0160, IMAGE_DATA, FONT_DATA, DATA_00E0): reports
   that the section is data and points you at the right `thd75-fw` CLI.

### If you opened without `-pARM`

IDA only allows changing the processor on a fresh database. If your
existing IDB is x86-64, the script will print recovery steps:

1. Quit IDA without saving.
2. Delete the `.i64` file next to the `.bin`.
3. Reopen with `ida -A -pARM <file.bin>`.

## Ghidra — `ghidra_thd75.py`

### Recommended workflow

Place [`ghidra_thd75.py`](ghidra_thd75.py) in your `~/ghidra_scripts/` directory
(or any location configured under
**Window > Script Manager > Manage Script Directories**).

Then:

1. **File > Import File...** → select `FIRMWARE_0x00200000.bin`.
2. At the import dialog, set:
   - Format: **Raw Binary**
   - Language: **ARM:LE:32:v5t** (the OMAP-L138's ARM926EJ-S supports v5te)
   - Block name: `ROM` (or whatever you prefer)
   - Base Address: `0x00000000` (the script will rebase automatically)
3. Let auto-analysis finish.
4. **Window > Script Manager** → run `ghidra_thd75.py`.

The script applies the same analysis mapping as the IDA script: main
firmware at runtime DDR `0xC0000000`, and standalone data sections at
their CPU-visible NOR addresses. It then names and disassembles the ARM
vectors. Set `REBASE_TO_ANALYSIS_ADDRESS = False` to skip the rebase.

## What these scripts deliberately don't do

- Create a second alias of the main blob at its NOR source address
  `0x60200000`. The default DDR mapping is deliberate: the flat bytes
  themselves contain the handler bodies addressed as
  `0xC0000000 + flat_offset`. The stock updater establishes the NOR source,
  while the D75 low bootloader's exact copy, validation, and entry mechanics
  remain unresolved despite the separate low-NOR capture.
- Name functions in the body of the firmware. Auto-analysis will find
  them via cross-references; manual reverse-engineering is still your
  job.
- Identify particular features (APRS handler, GPS parser, menu
  navigator, etc.). That's the analysis work `thd75-fw` deliberately
  doesn't do for you.

## Analysis address mapping

See the [OMAP-L138 memory map](../docs/FORMAT.md#omap-l138-memory-map) for the
general hardware regions. These scripts choose the address space that makes
the extracted image's pointers resolve:

Section addresses in filenames (e.g., `FIRMWARE` at `0x00200000`) are
offsets relative to NOR base `0x60000000`; the main image's stock source
is therefore `0x60200000`. The updater's `$SA=` carries that CPU-visible
NOR address. This source address is provenance, not the correct code
analysis base.

For the main flat image, runtime address and file offset have the direct
relationship `runtime = 0xC0000000 + flat_offset`. For example, the D75
service table at flat offset `0x0006F284` is runtime address `0xC006F284`,
and its `9R` Thumb pointer `0xC006F827` resolves to handler bytes at flat
offset `0x0006F826`. Loading the blob at a flash offset makes valid
runtime pointers look external and prevents these xrefs from resolving.

The official service manual states that the main MPU copies its program from
flash to DDR. The byte mapping above is directly testable in the extracted
image. The [low-NOR capture](https://github.com/swiftraccoon/thd75-fw/blob/main/firmware/CAPTURE.md#capture-evidence) establishes
Boot Program and FLDM slot boundaries; exact validation, copy length, and entry
semantics remain unresolved.
