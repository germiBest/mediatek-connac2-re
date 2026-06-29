# MT7961 WM firmware: host command and TLV dispatch map

Parsed from region1 rodata using `mediatek_connac2_fw_tables.ksy`. The id column
gives the cid/tag the host (mt76) sends. The two command tables sit adjacent in
memory: legacy EXT first, then UNI.

## EXT command table (@0x02022ce0)

| cid | handler | mt76 name |
|---|---|---|
| 0x01 | 0x0091837e | MCU_EXT_CMD_EFUSE_ACCESS |
| 0x24 | 0x0091839c |  |
| 0x16 | 0xe027074e |  |
| 0x17 | 0x009170f6 |  |
| 0x18 | 0x009170f6 |  |
| 0x19 | 0x009170f6 |  |
| 0x28 | 0x009170f6 |  |
| 0x2b | 0x00917384 |  |
| 0x0e | 0x00917384 |  |
| 0x0f | 0x00916fc6 |  |
| 0x10 | 0x00916fc6 |  |
| 0x11 | 0x00916fc6 | MCU_EXT_CMD_SET_TX_POWER_CTRL |
| 0x05 | 0x00916fc6 | MCU_EXT_CMD_ID_RADIO_ON_OFF_CTRL |
| 0x2a | 0x0094fea2 | MCU_EXT_CMD_DEV_INFO_UPDATE |
| 0x00 | 0x0094feaa |  |
| 0x29 | 0x00917060 |  |
| 0x1a | 0x00917062 |  |
| 0x1b | 0x00916f8c |  |
| 0x1c | 0x00916f8c |  |
| 0x1d | 0x00916f8c |  |
| 0x12 | 0x00916f8c |  |
| 0x13 | 0x00917006 | MCU_EXT_CMD_FW_LOG_2_HOST |
| 0x14 | 0x00917006 |  |
| 0x15 | 0x00917006 |  |
| 0x06 | 0x00917006 |  |
| 0x07 | 0x00916f8a | MCU_EXT_CMD_PM_STATE_CTRL |
| 0x08 | 0x00916f8a | MCU_EXT_CMD_CHANNEL_SWITCH |
| 0x09 | 0x00916f8a |  |
| 0x0a | 0x00916f8a |  |
| 0x0b | 0x00916f8a |  |
| 0x0c | 0x00916f8a |  |
| 0x0d | 0x00916f8a |  |
| 0x2e | 0x00916f8a |  |

## UNI command table (@0x02022de8)

| cid | handler | mt76 name |
|---|---|---|
| 0x2f | 0x00918340 | MCU_UNI_CMD_RA |
| 0x01 | 0x00918340 | MCU_UNI_CMD_DEV_INFO_UPDATE |
| 0x02 | 0x009182ae | MCU_UNI_CMD_BSS_INFO_UPDATE |
| 0x03 | 0x009182ae | MCU_UNI_CMD_STA_REC_UPDATE |
| 0x04 | 0x009182ae | MCU_UNI_CMD_EDCA_UPDATE |
| 0x23 | 0x009182ae | MCU_UNI_CMD_GET_STAT_INFO |
| 0x25 | 0x00916fc4 | MCU_UNI_CMD_SR |
| 0x26 | 0x0092a55e |  |
| 0x27 | 0x009175b4 | MCU_UNI_CMD_ROC |
| 0x2c | 0x009175b4 | MCU_UNI_CMD_SET_POWER_LIMIT |
| 0x2d | 0x009175b4 | MCU_UNI_CMD_EFUSE_CTRL |
| 0x30 | 0x009175b4 |  |
| 0x01 | 0x00917004 | MCU_UNI_CMD_DEV_INFO_UPDATE |
| 0x00 | 0x0092b718 |  |

## BSS_INFO_UPDATE TLV handlers (@0x02018120)

| tag | handler | mt76 tag |
|---|---|---|
| 0x01 | 0x0091ca32 |  |
| 0x03 | 0xe0271bd6 |  |
| 0x04 | 0x0091c21c |  |
| 0x05 | 0x0091c160 |  |
| 0x06 | 0x0091c1a2 |  |
| 0x0b | 0x0091c022 |  |
| 0x0c | 0x0091c5f8 |  |
| 0x0d | 0x0091c00a |  |
| 0x0e | 0x0091c124 |  |
| 0x0f | 0x0091bff4 |  |
| 0x10 | 0x0091bfdc |  |
| 0x02 | 0x0091bfb4 |  |
| 0x07 | 0x0091c384 |  |
| 0x13 | 0x00919704 |  |
| 0x14 | 0x0091c0c6 |  |
| 0x16 | 0x0091bf8c |  |
| 0x15 | 0x0091c092 |  |
| 0x18 | 0x0091c080 |  |

## Live-captured command map

These 24 commands were captured live on an MT7961 (Alfa AWUS036AXML): a print in the driver MCU send path logged every `(cmd, payload)` during scan, associate, disconnect, power-save, regulatory-set, and tx-power operations. Each is decoded against the mt76 builder that produced it and checked against the static dispatch map.

| cmd_id | name | type | purpose | handler / builder | confidence |
|---|---|---|---|---|---|
| 0x1 | MCU_CMD_TARGET_ADDRESS_LEN_REQ | MCU_CMD (bare, id=0x01) | FW-download handshake: declares target RAM addr+len+mode for next FW_SCATTER region (non-patch) | builder `mt76_connac_mcu_init_download` (mt76_connac_mcu.c:54-79) | proven |
| 0x2 | MCU_CMD_FW_START_REQ | MCU_CMD (bare, id=0x02) | Boots downloaded FW: entry point + start option (FW_START_OVERRIDE -> 0x00915000) | builder `mt76_connac_mcu_start_firmware` (mt76_connac_mcu.c:9-21) | proven |
| 0xee | MCU_CMD_FW_SCATTER | MCU_CMD (bare, id=0xee) | Bulk FW/data DMA chunk into addr declared by TARGET_ADDRESS_LEN_REQ; handled by ROM loader DMA, not the cid dispatch table | builder `__mt76_mcu_send_firmware` / `mt76_mcu_send_firmware` (mt76_connac_mcu.c:3026,3196) | proven |
| 0x21ed | MCU_EXT_CMD_EFUSE_BUFFER_MODE | MCU_EXT_CMD (extid=0x21 on EXT_CID 0xed) | Loads eFuse/EEPROM into FW RAM shadow (EE_MODE_EFUSE, EE_FORMAT_WHOLE) | builder `mt7921_mcu_set_eeprom` (mt7921/mcu.c:937-953); handler not in captured EXT table | proven |
| 0x3eed | MCU_EXT_CMD_PROTECT_CTRL | MCU_EXT_CMD (extid=0x3e on EXT_CID 0xed) | Sets RTS/CTS protection threshold (len_thresh=2347, pkt_thresh=2) | builder `mt76_connac_mcu_set_rts_thresh` (mt76_connac_mcu.c:213-228); handler not in captured EXT table | proven |
| 0x46ed | MCU_EXT_CMD_MAC_INIT_CTRL | MCU_EXT_CMD (extid=0x46 on EXT_CID 0xed) | Enables/disables MAC per band, toggles RX header translation during bring-up | builder `mt76_connac_mcu_set_mac_enable` (mt76_connac_mcu.c:172-187); handler not in captured EXT table | proven |
| 0x4eed | MCU_EXT_CMD_SET_RX_PATH | MCU_EXT_CMD (extid=0x4e on EXT_CID 0xed) | Programs channel/RX-path: control+center chan, BW, Tx/Rx streams, band (shared struct with CHANNEL_SWITCH) | builder `mt7921_mcu_set_chan_info` (mt7921/mcu.c:880-918, call mt7921/main.c:239); handler not in captured EXT table | proven |
| 0x20001 | MCU_UNI_CMD_DEV_INFO_UPDATE | UNI (bit17, cid=0x01), S2D_H2N, ACK/WM | Activate/deactivate a device-level OMAC (assign radio MAC to omac index) on vif up | builder `mt76_connac_mcu_uni_add_dev` dev_req (mt76_connac_mcu.c:1147); handler 0x00918340 | proven |
| 0x20002 | MCU_UNI_CMD_BSS_INFO_UPDATE | UNI (cid=0x02), TLV container | Program/teardown per-BSS context: BASIC params, RLM channel, QoS/QBSS, beacon-filter timing | builders `..._uni_add_dev` basic_req (mt76_connac_mcu.c:1182), `..._uni_add_bss` (~:1560), `..._uni_set_chctx` RLM (:1476); handler 0x009182ae | proven |
| 0x20003 | MCU_UNI_CMD_STA_REC_UPDATE | UNI (cid=0x03), nested-TLV container | Create/update peer station record (WTBL + rate/PHY/HE/BA/state) across auth->assoc for connected AP | builder `__mt76_connac_mcu_alloc_sta_req` (mt76_connac_mcu.c:276) + sta_basic/sta/ba_tlv; driven by `mt7921_mcu_sta_update` (mt7921/mcu.c:1077); handler 0x009182ae | proven |
| 0x20006 | MCU_UNI_CMD_OFFLOAD | UNI (cid=0x06), TLV container | Host-offload for WoWLAN/PS: ARP IPv4 responder, IPv6 ND list, GTK rekey material | builders `..._update_arp_filter` (:2298), `mt7921_mcu_set_ipv6_ns_filter` (mt7921/main.c:~1230), `..._update_gtk_rekey` (:2406) | proven |
| 0x20027 | MCU_UNI_CMD_ROC | UNI (cid=0x27), TLV container | Remain-on-channel: acquire temporary channel grant or abort in-progress one | builders `mt7921_mcu_set_roc` (:784) / `mt7921_mcu_abort_roc` (:852); handler 0x009175b4 | proven |
| 0x40003 | MCU_CE_CMD_START_HW_SCAN | CE (bit18), cid=0x03, set | Kick off FW-offloaded HW scan over a specified channel list | builder `mt76_connac_mcu_hw_scan` (mt76_connac_mcu.c:1750, send :1847) | proven |
| 0x4000a | MCU_CE_CMD_SET_RX_FILTER | CE, cid=0x0a, set | Program MAC Rx frame filter (FIF_* mask + RFCR bitmap) | builder `mt7921_mcu_set_rxfilter` (mt7921/mcu.c:1472) | proven |
| 0x4000f | MCU_CE_CMD_SET_CHAN_DOMAIN | CE, cid=0x0f, set | Push regulatory channel domain (per-band BW caps + enabled-channel table) | builder `mt76_connac_mcu_set_channel_domain` (mt76_connac_mcu.c:80) | proven |
| 0x40017 | MCU_CE_CMD_SET_BSS_ABORT | CE, cid=0x17, set | Abort/reset BSS-level PS context for a bss_idx (first step of bss-PM enable) | builder `mt7921_mcu_set_bss_pm` abort hdr (mt7921/mcu.c:1029, send :1058) | proven |
| 0x4001b | MCU_CE_CMD_CANCEL_HW_SCAN | CE, cid=0x1b, set | Cancel in-progress HW scan by sequence number | builder `mt76_connac_mcu_cancel_hw_scan` (mt76_connac_mcu.c:1856) | proven |
| 0x4001d | MCU_CE_CMD_SET_EDCA_PARMS | CE, cid=0x1d, set | Set per-AC EDCA/WMM contention parameters for a BSS | builder `mt7921_mcu_set_tx` / struct mt7921_mcu_tx (mt7921/mcu.c:701) | proven |
| 0x4005d | MCU_CE_CMD_SET_RATE_TX_POWER | CE, cid=0x5d, set | Download per-channel/per-rate SKU TX-power limit table for one band | builder `mt76_connac_mcu_rate_txpower_band` (mt76_connac_mcu.c:2133) | proven |
| 0x400a1 | MCU_CE_CMD_RSSI_MONITOR | CE, cid=0xa1, set | Arm FW connection-quality RSSI threshold monitoring (CQM low/high) | builder `mt7921_mcu_set_rssimonitor` (mt7921/mcu.c:1494) | proven |
| 0x400c5 | MCU_CE_CMD_FWLOG_2_HOST | CE, cid=0xc5, set | Enable/disable streaming FW debug log to host | builder `mt7921_mcu_fw_log_2_host` (mt7921/mcu.c:624) | proven |
| 0x400ca | MCU_CE_CMD_CHIP_CONFIG | CE, cid=0xca, set | Generic string-keyed chip config; here "KeepFullPwr 1" toggles deep-sleep off | builder `mt76_connac_mcu_set_deep_sleep` (:2001); shared by `..._chip_config` (:1988) | proven |
| 0x400d0 | MCU_CE_CMD_GET_TXPWR | CE, cid=0xd0, get (send-and-get-msg) | Query FW current TX-power table (user/eeprom/mac rate entries) per DBDC idx | builder `mt7921_get_txpwr_info` (mt7921/mcu.c:1126) | proven |
| 0x500c0 | MCU_CE_QUERY(REG_READ) (REG_READ=0xc0) | CE+QUERY (bit18 CE | bit16 query), cid=0xc0 | Read one 32-bit chip register via MCU (here MT_PSE_BASE, after each TX-power batch) | builder `mt76_connac_mcu_reg_rr` (:2677, call :2264) | proven |

### Notes

- The full 32-bit command word is confirmed on the wire: UNI = `0x20000 | cid`, CE = `0x40000 | cid`, and `0x500c0` = `CE | QUERY | cid 0xc0`. REG_READ and REG_WRITE share cid 0xc0 (h:1361-1362) and differ only by the QUERY bit, so they are separable here but not in a cid-only table.
- The `MCU_CE_CMD` space (bit18) is not in the static dispatch tables; the 12 CE commands above (0x40003..0x500c0) appear only in the capture and reach the chip through a separate command-engine path rather than the EXT cid table.
- The four EXT commands (0x21ed, 0x3eed, 0x46ed, 0x4eed) were captured but are absent from the EXT dispatch table (its cids stop at 0x2e), so their handler addresses are unknown. The EFUSE_BUFFER_MODE string at 0x02021788 is a hint, not a proven address.
- `FW_SCATTER` (0xee) carried a 320-byte chunk matching the EXT dispatch/config table at `0x02022ce0`, which anchors that table's RAM address.
- UNI handler addresses (DEV_INFO 0x00918340, BSS_INFO/STA_REC 0x009182ae, ROC 0x009175b4) match the static map.
- Observed values backing the decode: BSSID c4:b8:b4:f8:91:b8, OMAC 00:c0:ca:ba:57:59, RTS threshold 2347, WM entry 0x00915000, RAM target 0x00404400.
- All entries are `proven` from the decode except the four EXT handler addresses and the EFUSE string association.

### Method (reproducible)

Captured by adding a one-line `print_hex_dump` to the driver MCU send path
(`mt76_mcu_skb_send_and_get_msg` in mt76 `mcu.c`), reloading the stack, and
driving real STA-mode operations on the adapter (scan, associate, disconnect,
power-save, regulatory set, tx-power query). Each logged `(cmd, payload)` was
then decoded byte-for-byte against the mt76 builder that produced it. A debugfs
`mcu_inject` hook (write `<le32 cmd><payload>`, read the return code) replays or
mutates any command for response probing. Driving more operations (P2P, AP mode,
coredump) would extend the table further.
