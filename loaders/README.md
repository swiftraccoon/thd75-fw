# IDA Pro and Ghidra setup scripts

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

Then in IDA: `File > Script File...` → select `ida_thd75.py`. The script:

1. Verifies the processor is `arm` (offers recovery instructions if not).
2. Sets the segment to RWX, 32-bit (IDA refuses code creation otherwise).
3. **Auto-rebases the segment to the flash address parsed from the
   filename** (e.g., `FIRMWARE_0x00200000.bin` → segment starts at
   `0x00200000`), so addresses in IDA match the README's section table
   and the documented OMAP-L138 flash layout. Set
   `REBASE_TO_FLASH_ADDRESS = False` at the top of the script to skip
   this and keep the segment at file offset 0.
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

Place this file in your `~/ghidra_scripts/` directory (or any location
configured under **Window > Script Manager > Manage Script Directories**).

Then:

1. **File > Import File...** → select `FIRMWARE_0x00200000.bin`.
2. At the import dialog, set:
   - Format: **Raw Binary**
   - Language: **ARM:LE:32:v5t** (the OMAP-L138's ARM926EJ-S supports v5te)
   - Block name: `ROM` (or whatever you prefer)
   - Base Address: `0x00000000` (the script will rebase automatically)
3. Let auto-analysis finish.
4. **Window > Script Manager** → run `ghidra_thd75.py`.

The script auto-rebases the image to the flash address parsed from the
filename (matching IDA's behavior), names the ARM vectors, and
disassembles them. Set `REBASE_TO_FLASH_ADDRESS = False` at the top of
the script to skip the rebase.

## What these scripts deliberately don't do

- Define a DDR segment at `0xC0000000` for unresolved handler addresses.
  The handlers (`0xC0180B8C` etc.) live in DDR memory after the
  bootloader copies the runtime image. That copy logic isn't in the
  flash blob, so the handler bodies aren't reachable from this segment
  alone — they live in a different blob at runtime.
- Name functions in the body of the firmware. Auto-analysis will find
  them via cross-references; manual reverse-engineering is still your
  job.
- Identify particular features (APRS handler, GPS parser, menu
  navigator, etc.). That's the analysis work `thd75-fw` deliberately
  doesn't do for you.

## Memory map reference

The TH-D75's main SoC is the TI OMAP-L138 (ARM926EJ-S + C674x DSP). Key
regions for reverse-engineering this firmware:

| Region | Address | Size | Purpose |
|--------|---------|------|---------|
| ARM Internal RAM | `0x80000000` | 128 KB | Boot, fast-access |
| DSP Internal RAM | `0x11800000` | varies | DSP-side code/data |
| External Flash (NOR) | `0x60000000` | 32 MB | Where the updater writes — section addresses are FROM 0x60000000 |
| External DDR | `0xC0000000` | 64 MB max | Where most code runs after boot |

Section addresses in this project (e.g., `FIRMWARE` at `0x00200000`)
are flash offsets *relative to the SoC's NOR flash base of `0x60000000`*.
The full physical address is `0x60200000`. The updater stores `$SA=`
metadata as the full physical address; `_extract_flash_address` in
`cli.py` subtracts the flash base (`0x60000000`, exposed as
`thd75_fw.sections.FLASH_BASE`) to derive the relative offset used in
filenames. The DDR base (`0xC0000000`) is unrelated — it's where the
runtime image lives after the bootloader copies code from flash.

This is why the literal pool in `FIRMWARE`'s exception vectors
references `0xC0xxxxxx` addresses — the handlers are copied to DDR at
runtime, not stored in flash where the vectors themselves live.
