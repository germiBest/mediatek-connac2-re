# Xtensa-MTK: a Ghidra processor extension for MediaTek connac2 Wi-Fi-MCU firmware

A self-contained Ghidra processor extension that adds a new language,
`Xtensa:LE:32:MTK`, for disassembling and decompiling the MediaTek *connac2*
Wi-Fi-MCU ("WM" / "neptune") firmware found on MT7961 / MT7921 / MT7922 /
MT7915-family chips. The blobs run on a Tensilica Xtensa LX core (little-endian, 32-bit) paired with
a vendor custom-TIE coprocessor, and stock tools cannot decode them: capstone and LLVM
mis-model op0=E/F as 4-byte ESP32-S3 `ee.*` ops, which is wrong for MediaTek, and
the vendor TIE config was never published.

The extension installs alongside Ghidra's stock Xtensa (distinct language id and
slafile), so nothing about the built-in Xtensa changes.

## What it does

`xtensa-mtk.sinc` adds opaque constructors (`define pcodeop mtk_tie_*`) that are
length-correct and never fail to decode, covering MediaTek's custom Tensilica opcodes:
op0=0xE/0xF (3-byte), op0=0x4 (3-byte, repurposed MAC16 slot), QRST CUST0/CUST1
(op1=6/7), narrow ST3 density (op0=0xD), and the residual QRST/RRI8 lanes. The verified
length rule: op0 in {8..0xD} = 2 bytes, otherwise 3 bytes (no FLIX, no 4-byte).
Every custom major emits an opaque `CALLOTHER`, which keeps the decompiler tracking control flow
and function boundaries rather than aborting. The base ISA constructors stay
strictly more specific and always win, so ~73% of the image keeps real Ghidra
mnemonics. The custom ops carry no sub-opcode field and the vendor TIE
overlay was never published, so length-correct opaque decoding is as far as this can go.

## Install

Built and verified on Ghidra 12.1 (build 20260518). Pick ONE:

### A. Install Extensions GUI (recommended)
1. Ghidra → `File ▸ Install Extensions` → `+` (Add) → select
   `dist/Xtensa-MTK-ghidra_12.1.zip`.
2. Restart Ghidra.

### B. Drop-in to the user settings dir (no GUI)
Extract the module so it lands at
`<USER_SETTINGS>/Extensions/Xtensa-MTK/` where `<USER_SETTINGS>` is the
`ghidra_<ver>_<rev>` directory Ghidra prints at startup (typically
`~/.config/ghidra/ghidra_12.1_DEV` on Linux):

```
unzip dist/Xtensa-MTK-ghidra_12.1.zip -d ~/.config/ghidra/ghidra_12.1_DEV/Extensions/
```
Restart Ghidra.

### C. Drop-in to the Ghidra installation (all users)
```
unzip dist/Xtensa-MTK-ghidra_12.1.zip -d $GHIDRA_INSTALL_DIR/Ghidra/Extensions/
```
Restart Ghidra.

## Use

Import a connac2 region image as Raw Binary, then set:
* Language: `Xtensa:LE:32:MTK`  (Processor=Xtensa, Variant=MTK)
* Base address: the region's load address (e.g. region0 code = `0x915000` on MT7961)

Or use the bundled `LoadConnac2Firmware` script (Script Manager ▸ search
"connac2", under category MTK.Connac2) from the companion loader work: import the
raw `.bin` with `Xtensa:LE:32:MTK` and run the script. It parses the connac2
container, maps every region, adds ROM/DRAM stubs, sets the entry point, and seeds
disassembly automatically.

Then run normal auto-analysis. For the full MT7961 layout, map the other regions
(rodata `0x02015c00`, `0x404400`, IRAM `0xe0270000`, `0x0`) as additional blocks;
see the `AddBlocks.java` / `SeedCode.java` helper scripts in the firmware-RE tree.

## Verified result (this build)

Headless import of `region0.bin` @ `0x915000` with `Xtensa:LE:32:MTK`, then
AddBlocks + SeedCode + deeper pointer seeding (inbound call/jump refs) +
auto-analysis:

```
Using Language/Compiler: Xtensa:LE:32:MTK:default
METRIC instructions_in_code_range=91078
METRIC bad_instructions=0
METRIC undefined_bytes_in_code_range=113335 / 363536
METRIC functions_total=4471
0  "Unable to resolve constructor" errors
```

Plain AddBlocks + SeedCode on region0 (465 code-pointer seeds, no deeper seeding)
recovers ~2,173 functions; the 4,471 above adds seeding from inbound call/jump
refs (see FINDINGS.md §6). Either way every opcode resolves, with zero bad or
unresolved instructions. By comparison, stock Ghidra Xtensa on the same blob recovers only a
handful of functions and floods the listing with bad and unresolved instructions.

## Rebuild from source

```
export GHIDRA_INSTALL_DIR=/opt/ghidra
./build.sh            # recompiles the .sla and repacks dist/Xtensa-MTK-ghidra_12.1.zip
```
`build.sh` runs `$GHIDRA_INSTALL_DIR/support/sleigh` on the slaspec and zips the
module. SLEIGH compiles clean apart from the two pre-existing stock Xtensa warnings
("2 NOP constructors", "1 unnecessary extension/truncation → copy"); the MTK
additions introduce no new warnings, and the resulting `.sla` is byte-identical
to a stock+mtk build.

## Layout

```
Xtensa-MTK/
  extension.properties          name/version (12.1) metadata
  Module.manifest               marks this dir as a Ghidra module (empty = valid)
  ghidra_scripts/               LoadConnac2Firmware.java (one-click container loader)
  LICENSE  NOTICE                Apache-2.0 + attribution for the copied Ghidra files
  build.gradle                  optional: `gradle` builds the redistributable zip
  data/
    sleighArgs.txt
    buildLanguage.xml           ant target to (re)compile the .sla
    languages/
      xtensa-mtk.ldefs          declares Xtensa:LE:32:MTK
      xtensa_mtk_le.slaspec     base ISA + xtensa-mtk.sinc (drops flix/cust)
      xtensa_mtk_le.sla         precompiled
      xtensa-mtk.sinc           THE decoder (custom-TIE constructors)
      xtensaArch/Main/Instructions.sinc   stock Ghidra Xtensa base (Apache-2.0)
      xtensa.cspec / .pspec / .dwarf      stock Ghidra Xtensa specs (Apache-2.0)
```

## License

Apache-2.0. Includes unmodified base SLEIGH files from the Ghidra project
(NSA, Apache-2.0), see `Xtensa-MTK/NOTICE`.
