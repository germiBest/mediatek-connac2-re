# Kaitai Struct definitions for connac2 Wi-Fi firmware

Declarative parsers for the structured parts of MediaTek connac2 Wi-Fi MCU
firmware (MT7921 / MT7922 / MT7961 / MT7915). Kaitai handles containers and
tables; the Xtensa code is decoded separately by the Ghidra extension in this
repo, and the custom TIE ops have no public semantics.

## Files

- `mediatek_connac2_wifi_firmware.ksy` parses the firmware container: the 36-byte
  trailer at EOF, the `n_region` 40-byte region headers before it, and the
  `FW_FEATURE_*` bit decode. Generic across the connac2 family.
- `mediatek_connac2_fw_tables.ksy` parses the in-image dispatch tables out of the
  rodata region (load addr `0x02015c00` on MT7961): the legacy EXT and UNI command
  tables (`{u32 handler, u32 id}`) and the BSS_INFO_UPDATE TLV table
  (`{u32 handler, u32 tag}`). The table layout is MT7961-specific.
- `COMMAND-MAP.md` is the dumped result of the tables parser, every command id and
  TLV tag mapped to its handler address and cross-referenced against the `mt76`
  driver enums.

These files are the connac2 counterpart to the older-format `.ksy` files in
[`mediatek-wifi-re`](https://github.com/cyrozap/mediatek-wifi-re), which covers the
older-generation ILM/DLM, `MTKW`/`MTKE`, and `.ALPS` patch containers.

## Build and run

Needs `kaitai-struct-compiler` 0.11 and the Kaitai Python runtime
(`pip install kaitaistruct`).

```
kaitai-struct-compiler -t python mediatek_connac2_wifi_firmware.ksy
python3 -c "from mediatek_connac2_wifi_firmware import *; \
            f=MediatekConnac2WifiFirmware.from_file('WIFI_RAM_CODE_MT7961_1.bin'); \
            print(f.trailer.n_region, hex(f.region_headers[0].addr))"
```

The tables parser takes the rodata region as input; see the header comment in
`mediatek_connac2_fw_tables.ksy` for the table base offsets.
