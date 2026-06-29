# MediaTek connac2 Wi-Fi firmware reverse engineering

Tooling and notes for reverse engineering the firmware of MediaTek "connac2"
Wi-Fi MCUs: the MT7921 / MT7922 / MT7961 / MT7915 family (the chips the upstream
`mt76` driver loads `WIFI_RAM_CODE_*` blobs into).

Three findings drove this work:

- The connac2 Wi-Fi MCU runs Tensilica Xtensa (LX, little-endian, 32-bit)
  with vendor custom TIE opcodes.
- The connac2 RAM firmware is plaintext, not encrypted. Integrity is a plain
  `zlib.crc32(file[:-4])` stored in a trailer at the end of the file.
- Stock Ghidra recovers only about 4 usable functions from an MT7961 image: it
  seeds ~509 function stubs from pointer analysis but abandons each at the first
  unknown opcode, so almost none decode. With the processor extension in this repo
  it recovers ~3,800 to 4,500 functions with zero unresolved instructions.

## What's in here

| Path | Contents |
|------|----------|
| `ghidra_extension/` | A Ghidra processor extension that adds the language `Xtensa:LE:32:MTK`. It decodes the custom TIE ops as length-correct opaque instructions so the disassembler stays in sync and functions decompile instead of aborting. Prebuilt zip in `dist/`. |
| `kaitai/` | Kaitai Struct parsers for the firmware container and for the in-image command / TLV dispatch tables, plus `COMMAND-MAP.md`, the full host-command surface of the MT7961 image. |
| `FINDINGS.md` | The technical writeup: the Xtensa + TIE identification, the container format, the opcode/length notes, and the firmware architecture (command dispatch, CNM channel grant, MCC scheduler). |
| `DEEP-FINDINGS.md` | Named firmware structures via the mt76 driver as a Rosetta Stone (the RLM channel TLV field-by-field, the dispatch tables, ~30 handlers), the SDK source availability, and the ROM subsystems (eFuse, HIF, boot). |
| `ROM-DUMP.md` | How the WM mask ROM at `0x800000` was read off a live adapter over USB with no JTAG, what it contains, and what loading it into Ghidra recovered (4471 to 6511 functions). |
| `TIE-BOUNDARY.md` | Why the MCC scheduler cannot be rendered (the vendor TIE, confirmed five ways including by emulation), what stays recoverable, and the untouched areas that do not hit this boundary. |
| `CAPSTONE-FIX.md` | A capstone Xtensa decoding bug found via this RE (non-ESP32-S3 configs mis-decoded as 4-byte ee.* ops), and the upstream fix. |
| `examples/` | A headless loader script and a function-count helper. |

## Install the Ghidra extension

Built and verified on Ghidra 12.1.

GUI: `File > Install Extensions`, click `+`, select
`dist/Xtensa-MTK-ghidra_12.1.zip`, restart Ghidra.

Command line drop-in:

```
unzip dist/Xtensa-MTK-ghidra_12.1.zip -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

The extension ships a precompiled `.sla` for Ghidra 12.1. On a different Ghidra
version Ghidra recompiles it from the bundled `.slaspec` / `.sinc` on first use
(slower first load, still works); bump `extension.properties` and run
`ghidra_extension/build.sh` to rebuild.

## Use it

Import a connac2 code image as Raw Binary, set the language to
`Xtensa:LE:32:MTK` and the base address to the region load address (the code
region on MT7961 loads at `0x915000`), then run auto-analysis.

For a full layout in one step, run the bundled Script Manager script
`LoadConnac2Firmware` (category MTK.Connac2). It parses the container, maps every region
at its load address, adds the ROM and DRAM stub blocks so the decompiler does
not chase unmapped memory, sets the entry point, and seeds disassembly.

Verified result, full `WIFI_RAM_CODE_MT7961_1.bin` loaded via that script then
auto-analyzed:

```
language:           Xtensa:LE:32:MTK
container:          mt76_connac2_fw_trailer, CRC matches
entry:              0x915000  (j 0x917405)
functions:          3848
bad instructions:   0
unresolved opcodes: 0
```

## Kaitai parsers

`kaitai/mediatek_connac2_wifi_firmware.ksy` parses the container (trailer plus
`n_region` region headers, with the `FW_FEATURE_*` bit decode).
`kaitai/mediatek_connac2_fw_tables.ksy` parses the in-image dispatch tables;
`kaitai/COMMAND-MAP.md` is the dumped result, every host command id and BSS TLV
tag mapped to its handler address and cross-referenced against the `mt76` enums.

Compile and run with `kaitai-struct-compiler` 0.11 and the Python runtime.

## What it can't do

- The custom TIE ops stay opaque. They show as `mtk_tie_*()` CALLOTHER with no
  modeled semantics, because MediaTek never published the Tensilica TIE config.
  About 73% of the image is base Xtensa with real mnemonics; the rest is the
  vendor coprocessor. Function boundaries, control flow, and the call graph all
  survive, so the firmware stays navigable.
- The mask ROM at `0x800000-0x900000` is not part of the downloadable blob, so
  the leaf helper routines that reside there cannot be read.
- The DBGLOG numeric-id to format-string database is host-side only. There is no
  in-firmware string-pointer table, so log strings cannot be cross-referenced
  from code.
- The opaque-fallback coverage was proven by an opcode census of MT7961 region0.
  The 2-byte custom lane only has an opaque catch-all for `op0=0xD` (narrow ST3);
  narrow majors `op0=8/9/A/B/C` rely on the stock density constructors. On another
  connac2 image a vendor narrow op in one of those majors would decode as a stock
  density op rather than an opaque `mtk_tie_*`, so re-check the census per image.

## Verified vs likely

MT7961 is verified end to end. MT7921, MT7922, and MT7915 share the connac2
container and the same Xtensa core family, so the parsers and the extension
should apply, but they are not byte-verified here.

## Related work

MediaTek firmware RE splits across processors. This repo covers the connac2
Wi-Fi MCU; related projects handle the neighbouring cores:

- [`cyrozap/mediatek-wifi-re`](https://github.com/cyrozap/mediatek-wifi-re):
  earlier work on the older-generation MediaTek Wi-Fi cores (MT76x7 and similar),
  sometimes encrypted, with ILM/DLM, `MTKW`/`MTKE`, and `.ALPS` patch containers.
  A different core and container from connac2; the two do not overlap.
- [`nccgroup/ghidra-nanomips`](https://github.com/nccgroup/ghidra-nanomips) plus
  [`nccgroup/mtk_bp`](https://github.com/nccgroup/mtk_bp): the MediaTek 5G
  baseband / modem (`md1rom`), which is nanoMIPS, not Xtensa, and ships with a
  `DbgInfo` symbol file. Same toolset shape as this repo (a Ghidra processor
  module plus Kaitai container unpackers), different processor.

On a MediaTek device the modem is nanoMIPS and the connac2 Wi-Fi is the Xtensa
core handled here. Unlike the baseband, connac2 Wi-Fi
firmware is stripped and uses host-side ID logging, so there are no symbols to
import.

## Credits and license

The Ghidra extension forks Ghidra's Apache-2.0 Xtensa processor (base ISA SLEIGH,
compiler and processor specs); see `NOTICE`. The repo is Apache-2.0. The Kaitai
definitions are CC0.
