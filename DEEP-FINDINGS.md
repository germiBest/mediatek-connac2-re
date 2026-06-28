# MT7961 (connac2) Wi-Fi MCU Firmware: Consolidated RE Findings

Target: MediaTek connac2 MT7961 Wi-Fi MCU, Tensilica Xtensa LX core with custom vendor TIE (op0 = 0x4 / 0xE / 0xF). Artifacts: `region0.bin` RAM code @ `0x915000`, `region1.bin` rodata @ `0x02015c00`, `WIFI_ROM_MT7961_full.bin` 1 MB mask ROM @ `0x800000`. Driver cross-reference: the upstream `mt76` driver.

Method. The Ghidra Xtensa decoder and capstone both desync on TIE opcodes, and the decompiler times out on every non-trivial handler, so byte-level field reads from the middle of a handler are not reliable. Three things are treated as ground truth: (a) the dispatch tables are data in `region1.bin`, read byte-exact; (b) `mt76` driver structs are the wire layout the firmware parses, by definition; (c) a handful of clean base-ISA ops (immediate loads, range-compare gates, verified jump/call displacements) survive TIE desync and anchor specific layouts to specific firmware addresses. Each claim below is tagged [proven] (read from data/clean-ISA at a cited address) or [inferred] (driver layout or connac2-family cross-reference, not read out of this firmware byte-by-byte).

---

## 1. Named firmware structures via the mt76 Rosetta Stone

### 1.1 Command dispatch: one combined EXT+UNI table

There is a single dispatch table; the UNI portion is the physical continuation of the EXT portion. [proven, data]

- EXT part @ `0x02022ce0` (entries 0..32), UNI part @ `0x02022de8` (= `0x02022ce0 + 33*8`). Each slot = `{u32 handler, u32 cid}`.
- Enums: `MCU_EXT_CMD_*` (`mt76_connac_mcu.h:1224-1275`; `EFUSE_ACCESS=0x01` @:1225, `CHANNEL_SWITCH=0x08` @:1230), `MCU_UNI_CMD_*` (`mt76_connac_mcu.h:1277-1324`; `DEV_INFO_UPDATE=0x01` @:1278, `BSS_INFO_UPDATE=0x02` @:1279, `EFUSE_CTRL=0x2d` @:1305).

Distinct firmware entry points mapped to mt76 command names (handler addresses [proven, data]; semantic names [inferred] from the cid enums):

| Firmware addr | cids served | mt76 name |
|---|---|---|
| `0x009182ae` | UNI 0x02 / 0x03 / 0x04 / 0x23 | shared TLV-container dispatcher: BSS_INFO_UPDATE, STA_REC_UPDATE, EDCA_UPDATE, GET_STAT_INFO |
| `0x00918340` | UNI 0x01 / 0x2f | DEV_INFO_UPDATE, RA |
| `0x009175b4` | UNI 0x27 / 0x2c / 0x2d / 0x30 | ROC, SET_POWER_LIMIT, EFUSE_CTRL, (0x30) |
| `0x0091837e` | EXT 0x01 | EFUSE_ACCESS |
| `0x0094fea2` | EXT 0x2a | DEV_INFO_UPDATE (EXT) |
| `0x00917006` | EXT 0x13 (+0x06/0x14/0x15) | FW_LOG_2_HOST |
| `0x00916f8a` | EXT 0x07 / 0x08 (+0x09..0x0d/0x2e) | PM_STATE_CTRL, CHANNEL_SWITCH |
| `0x00916fc6` | EXT 0x05 / 0x11 (+0x0f/0x10) | RADIO_ON_OFF_CTRL, SET_TX_POWER_CTRL |

47 table slots (33 EXT + 14 UNI) resolve to ~20 distinct entry points; ~16 cids carry an mt76 name.

### 1.2 BSS_INFO TLV dispatch table @ `0x02018120`

18 entries `{u32 handler, u32 tag}` [proven, data]; the table ends exactly where the `cnm_open.c` assert strings begin, which is how the 18-entry count is bounded. Tag enum `UNI_BSS_INFO_*` (`mt76_connac_mcu.h:1374-1399`; `BASIC=0` @:1375, `RA=1` @:1376, `RLM=2` @:1377). Handler addresses [proven], struct/name attribution [inferred] from the driver:

| tag | name | handler | driver struct (`mt76_connac_mcu.h`) |
|---|---|---|---|
| 0x00 | BASIC | inline in `0x009182ae` (no table slot) | `struct mt76_connac_bss_basic_tlv` (:1466) |
| 0x01 | RA | `0x0091ca32` | |
| 0x02 | RLM | `0x0091bfb4` | `struct rlm_tlv` (the channel TLV; see 1.3) |
| 0x03 | PROTECT_INFO | `0xe0271bd6` (IRAM) | |
| 0x04 | BSS_COLOR | `0x0091c21c` | `bss_info_uni_bss_color` (:1655) |
| 0x05 | HE_BASIC | `0x0091c160` | `bss_info_uni_he` (:1663) |
| 0x06 | 11V_MBSSID | `0x0091c1a2` | `bss_info_uni_mbssid` (:1673) |
| 0x07 | BCN_CONTENT | `0x0091c384` | |
| 0x0b | RATE | `0x0091c022` | |
| 0x0f | QBSS | `0x0091bff4` | `mt76_connac_bss_qos_tlv` (:1496) |
| 0x10 | SEC | `0x0091bfdc` | |
| 0x13 | UAPSD | `0x00919704` | |
| 0x15 | PS | `0x0091c092` | |
| 0x16 | BCNFT | `0x0091bf8c` | |
| 0x0c/0d/0e/14 | fw-internal (12/13/14/20) | `0x0091c5f8`/`0x0091c00a`/`0x0091c124`/`0x0091c0c6` | not exposed by mt76 |

14 tags named (13 in-table + BASIC inline); 5 remain firmware-internal.

### 1.3 RLM channel TLV: fully field-named, anchored to firmware

The RLM TLV (`tag 0x02`, handler `FUN_0091bfb4`) is the channel-grant input, and its layout is byte-identical to the firmware's internal channel struct because the handler `memcpy`s the body verbatim.

Clean-ISA anchors inside `FUN_0091bfb4` [proven]:
- `0x0091bfbf  movi.n a15,0xc` -> copy length = 12 = exactly the rlm_tlv body (bytes after tag/len: `control_channel..pad` = 0x0c).
- `0x0091bfc1  call0 0x00990a24` -> shared memcpy (displacement `0x0091bfc1 + 0x74a64` verified); copies the 12-byte body into the internal channel-config struct.
- `0x0091bfc6  blti a5,7` -> validates bw against 7 = cardinality of `CMD_CBW_*` (indices 0..6), confirming the `+0x03` byte is the bandwidth selector.
- `0x0091bfc9  j 0x009241dd` -> tail-call into RLM apply (`0x0091bfc9 + 0x8214` verified).
- `FUN_009241dd`: `l32r a10,0x008f8420` @ `0x009241f4` loads the channel-manager global; `l32i a12,a5,0x3c` reads `ctx+0x3c`; `j 0x00924e03` @ `0x00924206` (deep channel apply; `0x924206 + 0xbfd` verified).

Driver builder: `mt76_connac_mcu_uni_set_chctx()` @ `mt76_connac_mcu.c:1476`; `struct rlm_tlv` defined inline at `mt76_connac_mcu.c:1488-1502`; sent as `MCU_UNI_CMD(BSS_INFO_UPDATE)` / `UNI_BSS_INFO_RLM` at `:1529` (verified live: tag/len at `:1508-1509`, send at the function tail `:1553`). `CMD_CBW_*` enum at `mt76_connac.h:51-59` (note: live tree has `CMD_CBW_320MHZ` at :59, so the firmware `blti a5,7` admits indices 0..6 and rejects 320 MHz, consistent with an MT7961 that has no 320 MHz path).

Fully-named `struct rlm_tlv` (TLV-relative offset / internal-struct offset / field) [layout proven by the verbatim-copy argument; field semantics from driver `:1488-1551`]:

```
TLV+0x04 / +0x00  control_channel  u8   primary/control channel (chandef->chan->hw_value)
TLV+0x05 / +0x01  center_chan      u8   seg0 center (freq1 -> chan)
TLV+0x06 / +0x02  center_chan2     u8   seg1 center (freq2, 80+80)
TLV+0x07 / +0x03  bw               u8   CMD_CBW_*  (blti a5,7 gate)
TLV+0x08 / +0x04  tx_streams       u8   hweight8(antenna_mask)
TLV+0x09 / +0x05  rx_streams       u8   chainmask
TLV+0x0a / +0x06  short_st         u8   short slot/preamble (=1)
TLV+0x0b / +0x07  ht_op_info       u8   4 = 40M allowed, 0 for 20M
TLV+0x0c / +0x08  sco              u8   secondary offset: 1=SCA(above), 3=SCB(below)
TLV+0x0d / +0x09  band             u8   nl80211 band (0=2G, 1=5G)
TLV+0x0e / +0x0a  pad[2]
```

`sco` derivation `mt76_connac_mcu.c:1548-1551`; bw map `:1521-1546`. The channel-manager global is `0x008f8420`; `FUN_009241dd` dereferences `ctx+0x3c` before the deep apply at `0x00924e03`.

### 1.4 Driver-layout field tables (parsed by firmware, offsets from driver)

These offsets are the wire layout the firmware consumes [inferred from driver structs, not read from firmware ops]:

- `mt76_connac_bss_basic_tlv` (tag0 BASIC, `:1466`): `+0x04 active`, `+0x05 omac_idx`, `+0x06 hw_bss_idx`, `+0x07 band_idx`, `+0x08 conn_type le32`, `+0x0c conn_state`, `+0x0d wmm_idx`, `+0x0e bssid[6]`, `+0x14 bmc_tx_wlan_idx le16`, `+0x16 bcn_interval le16`, `+0x18 dtim_period`, `+0x19 phymode`, `+0x1a sta_idx le16`, `+0x1c nonht_basic_phy le16`, `+0x1e phymode_ext`, `+0x1f link_idx`.
- `bss_info_uni_bss_color` (tag4): `+0x04 enable`, `+0x05 bss_color`, `+0x06 rsv[2]`.
- `bss_info_uni_he` (tag5): `+0x04 he_rts_thres le16`, `+0x06 he_pe_duration`, `+0x07 su_disable`, `+0x08 max_nss_mcs[]`.
- `mt76_connac_bss_qos_tlv` (tag15 QBSS): `+0x04 qos`, `+0x05 pad[3]`.

---

## 2. SDK / source availability

The firmware source itself is not publicly indexed; the surrounding host-driver context partly is.

The MCU scheduler source (`cnm_open.c` / `getMinimumQuotaTime` / the `ENUM_CNM_QUOTA_CHINFO` role switch) is confirmed closed. Every firmware-unique symbol returns 0 hits on GitHub code search and web search [proven by negative search]:

- Log strings `"Check CNM minimum quota time"`, `"STA/GC min quota time"` -> 0.
- Symbols `getMinimumQuotaTime`, `ENUM_CNM_QUOTA_CHINFO_NUM`, `ucWorkingNetNum`, `MccStaQuotaTimeInUs`, `MccP2pGoQuotaTimeInUs`, `CnmAbsenceMarginInUs`, `EnCnmSmartBrake`, `EnCnmSyncTBTT`, `fgCnmForceEarlyAbortCH`, `prMigrationChInfo` -> all 0.
- Tree paths `wifi/open_core/wificore/mlm/cnm_open.c`, `wifi/core/wificore/mlm/cnm.c`, `cnm_radio.c`, `coex/common/coex_chinfo.c` -> 0. The `open_core` vs `core` split is MediaTek-internal and never published.

These paths and symbols are present as strings in `region1.bin` / `WIFI_RAM_CODE_MT7961_1.bin`, so the source files exist; they are simply not on any public index.

### Firmware-only enums/structs (from strings, in no public header)

- `enum ENUM_CNM_QUOTA_CHINFO { ENUM_CNM_QUOTA_CHINFO_STA, ..., _NUM }`, role axis starts at STA (no AP role), per assert @ `0x0201821c`.
- `enum ENUM_CNM_QUOTA_CONDITION { ENUM_CNM_QUOTA_CONDITION_DEFAULT, ..., _NUM }`.
- `getMinimumQuotaTime()` (str @ region1 `0x02023a0c`); logs `"Check CNM minimum quota time:"`, `"STA/GC min quota time: %d us"`.
- `struct prMsgChReq { ucBssIndex (<5), ucPrimaryChannel (>0) }`; `struct prChInfo { eBand, ucWorkingNetNum, eSysProtectMode }`; `prMigrationChInfo`, `prHeadChInfo`.
- wifi.cfg/registry knobs: `MccStaQuotaTimeInUs` (@ `0x020254f0`), `MccP2pGoQuotaTimeInUs`, `MccP2pGcQuotaTimeInUs`, `CnmAbsenceMarginInUs`, `CnmGOAbsenceMarginInUs`, `CnmFastChReqQuotaInUs`, `EnCnmSmartBrake`, `EnCnmSyncTBTT`, `EnCnmDoubleWFDCHtime`, `fgCnmForceEarlyAbortCH`, `ScnMissThreshold`.

### Recoverable public proxies (GPL gen4m host driver, same lineage, not the firmware)

1. Host channel-manager header, gen4m `include/mgmt/cnm.h`: `MSG_CH_REQ` / `MSG_CH_GRANT` / `MSG_CH_ABORT`, `CNM_INFO{fgChGranted,ucBssIndex,ucTokenID}`, enums `ENUM_CH_SWITCH_TYPE` / `ENUM_CNM_DBDC_MODE` / `ENUM_CNM_DBDC_SWITCH_MECHANISM`, funcs `cnmChMngrRequestPrivilege` / `AbortPrivilege` / `HandleChEvent`. Fetch-confirmed it does not contain `getMinimumQuotaTime` / `ENUM_CNM_QUOTA_CHINFO`.
   - https://github.com/EndCredits/android_kernel_oppo_mt6893 (`.../wlan/core/gen4m/include/mgmt/cnm.h`, also `mgmt/cnm.c`)
   - https://github.com/realme-kernel-opensource/realmeC12_realmeC15_AndroidR-kernel-source
2. Host-side MCC quota config (closest proxy to the quota knobs), gen4m `mgmt/ais_fsm.c` parses `MccDualStaAIS0QuotaTimeInUs` / `MccDualStaAIS1QuotaTimeInUs`, the dual-STA analogue of the firmware's per-role STA/GO/GC quota. Confirms a host-pushed MCC quota-config interface, but not the scheduler (which runs on-MCU).
   - https://github.com/xiaomi-mediatek-devs/android_kernel_xiaomi_mt6877 , https://github.com/Rohail33/Realking_xiaomi_xaga , https://github.com/NothingOSS/android_kernel_modules_nothing_mt6886 , https://github.com/LineageOS/android_kernel_xiaomi_mt6785 , https://github.com/cyberknight777/dragonheart_kernel_motorola_cancunf (all `.../gen4m/mgmt/ais_fsm.c`)
3. Newest connac host tree (mt6639 / mt7927-class), has `MID_MNY_CNM_CH_REQ`: https://github.com/zouyonghao/mt7927 (`mt6639/mgmt/`).
4. Shipped wifi.cfg proving the tokens are a wifi.cfg/registry namespace: `ScnMissThreshold 8` present; the `Mcc*`/`Cnm*` quota knobs are not in the public cfgs (compiled defaults). https://github.com/lenovo-mt6765/proprietary_vendor_lenovo_mt6765-common , https://github.com/who53/rom-dump-lenovo-akita , https://github.com/J6idot/vendor_device_x606x
5. RE reference (no source, encryption-focused): https://github.com/cyrozap/mediatek-wifi-re

Use gen4m `cnm.h` to name the channel-privilege protocol and the `Mcc*QuotaTimeInUs` config surface, then read the quota scheduler itself in Ghidra (region0 grant cluster ~`0x0094e4fa..0x0094fc04`, `getMinimumQuotaTime` consumer). It cannot be sourced.

---

## 3. ROM subsystems (eFuse, HIF, boot)

ROM file-path strings (real pointers only for `sys_cache.c`; all others ID-logged): `sys_efuse.c` @ `0x00817a8c`, `hif.c` @ `0x00817af0`, `hif_drv.c` @ `0x00817ad0`, `usb3.c` @ `0x00817b8c`, `usb3_drv.c` @ `0x00817e44`, `ccif.c` @ `0x00818070`, `axi_dma.c` @ `0x008180ec`, `wdt.c` @ `0x00818088`, `sys_cache.c` @ `0x80b6e4`, `top_pos.c` ("@mcu/project/7961/conn_infra/src/top_pos.c").

### 3.1 eFuse

Command path [proven, data/strings]:
- `MCU_EXT_CMD_EFUSE_ACCESS` cid=0x01 -> `FUN_0091837e`.
- `MCU_UNI_CMD_EFUSE_CTRL` cid=0x2d -> `FUN_009175b4`.
- Reads are 16-byte blocks (strings `"eFuse block:0x%x read succeed!"` @ `0x02022038`, `"...FAILED!"` @ `0x02022058`, `"Invalid eFuse access cmd!(%x)"` @ `0x02022078`, file `wsys_efuse_info.c` @ `0x02022098`). 16 B/block = AIN masked to ~0xf + 4 RDATA words = the standard connac efuse macro.
- Buffer-mode shadow: `EXT_CMD_EFUSE_BUFFER_MODE` uploads the whole efuse image into a RAM shadow; firmware then reads config from the shadow, not the controller. Strings `"rlmCmdEfuseBufferModeRead"` @ `0x02021788`, `"Buffer mode content length too large %d (> %d)"` @ `0x020215e0`, radio config parse `"Efuse: ucIso %d"` @ `0x0201f6b0`, `"EfuseOrWfCfg: BwcMode %d, TddMode %d"` @ `0x02020444`.

Controller register model [inferred, connac2-family cross-ref; not read from ROM ops]: conn_infra efuse = `conn_infra+0x020` (host `0x18001020`; MCU view based at `MT_INFRA_MCU_START=0x7c000000`). TOP path = `TOP+0x1cc` (host `0x180601cc`). `EFUSE_CTRL = base+0x008`: AIN = `GENMASK(25,16)` (addr & ~0xf), MODE = `GENMASK(7,6)`, VALID = `BIT(29)`, KICK = `BIT(30)`, AOUT = `GENMASK(5,0)`; RDATA[0..3] = `base+0x010` (16 B/block). Note [proven, negative]: a literal-pool census found no co-located KICK/VALID/AIN signature next to an MMIO base, i.e. the WM ROM does not do a classic kick/poll in a clean literal pool, consistent with reads going through the buffer-mode RAM shadow and/or conn_infra auto-load, the controller only being touched on the explicit `EFUSE_ACCESS` command.

eFuse data layout (LE byte offsets) [inferred, MT7961 == mt7921 connac2 map, from driver]: `0x000` CHIP_ID (=0x7961), `0x002` VERSION, `0x004` MAC_ADDR[6], `0x00a` MAC_ADDR2[6] (band1), `0x050` DDIE_FT_VERSION, `0x062` DO_PRE_CAL, `0x07c` WIFI_CONF (CONF0: TX_PATH `G(2,0)`, RX_PATH `G(5,3)`, BAND_SEL `G(7,6)`), `0x252`/`0x29d` RATE_DELTA_2G/5G (val `G(5,0)`, sign `BIT6`, en `BIT7`), `0x2fc`/`0x34b` TX0_POWER_2G/5G, `0x55b` HW_TYPE (adie variant), `0x9a0` ADIE_FT_VERSION, `0x9ff` `__MT_EE_MAX`. WIFI_CAL flags: GROUP `BIT0`, DPD_5G `BIT1`, DPD_2G `BIT2`, DPD_6G `BIT3`. Regulatory note: no dedicated efuse region field on this part, country comes from host CLC; efuse carries only band capability + the BWC/TDD/ISO flags logged above.

### 3.2 HIF transport

MT7961 has ROM drivers for two transports (MT7961U = USB).

CR blocks driven [proven, literal-pool census; meanings cross-ref'd to driver]:
- WFDMA0 @ `0x18000000`. Ring descriptors @ `0x18000300 + 0x10*ring`: BASE(+0x0)/CNT(+0x4)/CIDX(+0x8)/DIDX(+0xc). Touched: `0x18000300/304/314/350`, `0x18001300`, `0x18002304/310`. `FUN_00818654` is a ring-programming routine (uses `0x18000314`). HOST_INT block @ `0x18000200` (`HOST_INT_ENA = +0x204`). WFDMA1/PDA @ `0x18080000`/`0x18082000`.
- USB device controller @ `0xe0000000` + `0xe0270000` (region3 IRAM). USB-side command handler in IRAM: EXT cid 0x16 -> `0xe027074e`. Endpoint strings "USB Wi-Fi"/"USB WFSYS"/"USB_UDMA_WFSYS" @ `0x8172c0`/`0x817e60`/`0x817e6c`.
- CCIF mailbox (conn_infra cross-core doorbell): `"Get mailbox r/w ack timeout!!"` @ `0x02017214`.
- MCU PC/boot ctrl @ `0x7c060000` (`MT_WM_MCU_PC=0x7c060204`, `MT_WA_MCU_PC=0x7c06020c`).

Command-receive path [inferred, reconstructed from CR usage + dispatch tables + driver structs; address-level verified]: Host builds HW TXD + cmd header (`struct mt76_connac2_mcu_txd`: `txd[8]`, then len/pq_id/cid/pkt_type/set_query/seq/ext_cid/s2d_index/ext_cid_ack; UNI form `mt76_connac2_mcu_uni_txd` is pkt_type=0xa0 long-format, 16-bit cid + option byte). PCIe: write packet to MCU cmd WFDMA TX ring, fill descriptor @ `0x18000300+`, bump CIDX. USB: send on MCU cmd bulk-OUT, UDMA receives into MCU RAM. Completion IRQ -> HIF ISR (`WIFI_Process_HIF_Intr` sym @ `0x02017238`) reads DIDX vs CIDX, dequeues, copies. Parser checks pkt_type then indexes the EXT/UNI dispatch tables by cid. Replies/events return as `struct mt76_connac2_mcu_rxd` via RX ring / USB IN ("HIF TX CMD"/"HIF TX PKT" @ `0x02022978`/`84`). A RAM WFDMA diagnostic dumper names probe regs (`CONN_HIF_BUSY_STATUS`, `WFDMA_HIF_MISC`, `WFDMA_AXI0_R2A_*` @ `0x0201cbb5..0x0201cd75`).

### 3.3 Boot / reset

Vector table @ `0x800000` (Xtensa relocatable VECBASE) [proven, structural]: first block `0x800000-0x80003f` is register-window spill/fill (`l32e`/`s32e` @ `0x80007f`/`0x80009b`, which the sleigh renders as "tie/ill"). Standard relocatable vector group (WindowOverflow/Underflow 4/8/12 at 0x40 spacing, then Kernel/User/Double + leveled-interrupt vectors), ROM bootloader code follows at ~`0x800040+`.
- Panic stub `FUN_00803090` = `do { ill(); } while(true)`, the fatal-exception target.
- Central assert/log printf(file-ptr, line) @ `0x00800598` (mirror `0x00880598`); `FUN_0082625c` is a `sys_cache.c` routine that l32r-loads the filename @ `0x80b6e4` and `call4 0x00880598`.
- Early reset/init cluster: `FUN_800070` (-> panic stub), `FUN_800903`, `FUN_801607`, `FUN_801f3d`, `FUN_802483`. Boot-file functions sit around `0x80c000-0x80f000` (sys_cache/sys_irq/Eint/top_pos) and `0x817000-0x819000` (hif/usb/ccif/axi_dma).

Sequence [inferred, mask-ROM bootloader role]: 1 MB image is mirrored twice and byte-identical (`0x800000-0x87ffff == 0x880000-0x8fffff`, verified) so `call4` into `0x88xxxx` is the same code via the high mirror. On reset: VECBASE boot -> window/exception vector setup -> cache init (`sys_cache.c`) -> IRQ controller (`sys_irq.c`) + EINT (`Eint.c`, "EINT handler" @ `0x80cb44`) -> conn_infra power/position (`top_pos.c`) -> HIF/USB bring-up. Then it receives the WM firmware over HIF (FW_SCATTER per region + FW_START, no signature/CRC gate observed) and releases the MCU to the RAM image: WM entry `region0 @ 0x00915000` is `j 0x917405`; release controlled via `MT_WM_MCU_PC=0x7c060204`. Chip identity at TOP/conn_cfg: host `0x70010200 = 0x7961`, HW_BOUND `BIT(5)` @ `0x70010020` = DBDC-capable.

### 3.4 Reliability caveats

- TIE pollution dominates: of 1919 ROM functions in `0x800000-0x85ffff`, only ~106 decompile cleanly (<=15% TIE); the hardware-driver functions (efuse poke, WFDMA/USB ring engine, cache/irq init) are exactly the TIE-dense 25-66% ones and are not byte-accurately recoverable. They were verified structurally (VECBASE layout, resolved call edges, literal-pool CR census, rodata dispatch tables, the one real filename pointer, the command/efuse/ring structs).
- The clean 106 functions are pure logic (parsers/list/heap/math) and contain no CR constants, all register access is concentrated in the TIE functions.
- eFuse data offsets and controller bit-fields are mt76/connac2-family cross-references, authoritative for the part but not read byte-by-byte from this ROM; the command path, 16 B block size, buffer mode, and handler addresses are firmware-verified.

Decompiling the RLM handlers fails with `process: timeout`; that failure is itself the evidence for the TIE limitation.

## 4. Rosetta Stone part 2: STA_REC, DEV_INFO, remaining BSS TLVs

Extends section 1 (RLM) with the per-station record and the rest of the command structures, same
method: dispatch tables read as data, mt76 driver structs as the wire layout, clean base-ISA anchors.

### 4.1 STA_REC_UPDATE is a two-pass TLV dispatch

STA_REC_UPDATE (UNI cid 0x03) shares the container dispatcher FUN_009182ae but uses two
`{u32 handler, u32 tag}` tables sitting directly above the BSS_INFO table in region1 rodata; both carry
STA_REC-specific tags (HE_V2=0x19, PHY=0x15, HE_6G=0x17, BFEE=0x14). Table bytes [proven-data];
struct attribution [inferred from the mt76 enum order].

Pass-2 / primary table `@0x02017f80` (19 entries, the only table holding tag0 BASIC):

| tag | name | handler | driver struct (`mt76_connac_mcu.h`) |
|---|---|---|---|
| 0x00 | STA_REC_BASIC | 0x00919e16 | `sta_rec_basic` (:289) |
| 0x01 | STA_REC_RA | 0x0091b868 | `sta_rec_ra` (:572) |
| 0x02 | STA_REC_RA_CMM_INFO | 0x0091b968 | `sta_rec_ra_info` (:398) |
| 0x04 | STA_REC_BF | 0x0091ba1a | `sta_rec_bf` (:450) |
| 0x05 | STA_REC_AMSDU | 0x0091ba74 | `sta_rec_amsdu` (:376) |
| 0x06 | STA_REC_BA | 0x0091bad0 | `sta_rec_ba` (:331) |
| 0x07 | STA_REC_STATE | 0x0091bafa | `sta_rec_state` (:385) |
| 0x09 | STA_REC_HT | 0x0091bc76 | `sta_rec_ht` (:302) |
| 0x0a | STA_REC_VHT | 0x0091bd18 | `sta_rec_vht` (:309) |
| 0x0c | STA_REC_KEY | 0x0091bd62 | `sta_rec_sec` (:432) |
| 0x0e | STA_REC_HE | 0x0091bd8e | `sta_rec_he` (:342) |
| 0x11 | STA_REC_KEY_V2 | 0x0091bde4 | `sta_rec_sec` v2 (:440) |
| 0x12 | STA_REC_MURU | 0x0091be0e | `sta_rec_muru` (:507) |

Pass-1 / PHY-and-capability table `@0x02017ef0` (18 entries, no tag0; adds the rate/PHY-control tags
the primary table lacks: BFEE 0x14, PHY 0x15 (handler in mask ROM `0xe027a9e8`), HE_6G 0x17, HE_V2 0x19;
NULL handlers for AMSDU/BA = processed only in pass-2). Interpretation [inferred]: pass-2 is the main
STA_REC parser, pass-1 is a second sweep that programs PHY/capability/rate-control state.

### 4.2 sta_rec_basic, fully field-named

tag 0x00, handler 0x00919e16 [proven-data]. The handler's first clean op `addi.n a2, a11, 0xc` pins
+0x0c = peer_addr [proven]. Layout [inferred from `struct sta_rec_basic`, `mt76_connac_mcu.h:289`,
built by `mt76_connac_mcu_sta_basic_tlv()` `mt76_connac_mcu.c:371`]:

```
+0x00 le16  tag         = 0x0000
+0x02 le16  len         = 0x0014 (20)
+0x04 le32  conn_type   STA_TYPE(low) | NETWORK(bit16+):
                          INFRA_AP =0x00010002  INFRA_STA=0x00010001
                          P2P_GO   =0x00020002  P2P_GC   =0x00020001
                          IBSS     =0x00040004  INFRA_BC =0x00010020
+0x08 u8    conn_state  0=DISCONNECT 1=CONNECT 2=PORT_SECURE
+0x09 u8    qos
+0x0a le16  aid
+0x0c u8[6] peer_addr   <- addi.n a2,a11,0xc anchor [proven]
+0x12 le16  extra_info  VER=BIT0, NEW=BIT1
```

The `conn_type` values are the link to the scheduler finding: the firmware distinguishes AP / STA /
P2P-GO / P2P-GC here, and the MCC quota roles cover STA, GO, GC but not AP, which is why a second
infra-AP gets no concurrent channel.

### 4.3 DEV_INFO_UPDATE

UNI cid 0x01 -> dispatcher 0x00918340. One TLV, DEV_INFO_ACTIVE (=0); built by
`mt76_connac_mcu_uni_add_dev()` `mt76_connac_mcu.c:1147` [inferred wire layout]: hdr {omac_idx,
band_idx, pad}, then req_tlv {tag=0, len=0xc, active, link_idx, omac_addr[6]}. (No `tx_radio` struct
on MT7961; that is connac3.)

### 4.4 Remaining BSS_INFO TLVs

Resolved against the driver [tag->handler proven, struct inferred]:

| tag | name | handler | driver struct |
|---|---|---|---|
| 0x07 | BCN_CONTENT | 0x0091c384 | `bcn_content_tlv` (`mt7921/mcu.c:1243`): tim/csa/bcc ie pos, enable, type, pkt_len, pkt[512] |
| 0x0b | RATE | 0x0091c022 | `bss_rate_tlv`: bc/mc trans, short_preamble, bc/mc fixed_rate |
| 0x13 | UAPSD | 0x00919704 | BSS-level U-APSD enable (fw-side params; per-STA is `sta_rec_uapsd`) |
| 0x15 | PS | 0x0091c092 | `ps_tlv` (`mt7921/mcu.c:946`): ps_state {0 awake,1 static,2 dynamic,3 enter TWT,4 leave TWT} |
| 0x16 | BCNFT | 0x0091bf8c | `bcnft_tlv` (`mt7921/mcu.c:985`): bcn_interval, dtim_period |
