# Findings: MediaTek connac2 Wi-Fi-MCU firmware

Technical writeup behind the `mediatek-connac2-re` extension. Everything here was derived from
the MT7961 WM image (`WIFI_RAM_CODE_MT7961_1.bin`, 792,036 bytes, from
`/lib/firmware/mediatek/`, build tag `MT7961_MT7972_E2_MAIN_ASIC_ROM_RAM_MOBILE_CCN16`,
build date `20260224110949`), the same firmware run by the Alfa AWUS036AXML (MT7921AU,
`0e8d:7961`).

Each claim is tagged with how it was established:

- [proven-bytes], exact bytes / struct match / recomputed checksum; tool-independent.
- [proven-rodata], a compiler-emitted ASSERT condition string or config-symbol name
  embedded verbatim in the firmware's rodata. These are literal C-source fragments and are
  decode-independent (no disassembler needed).
- [disasm], read from the base-ISA disassembly of specific instructions that decode cleanly.
- [inferred], a conclusion from the data model / negative search; the leaf instruction that
  would make it [disasm] is TIE-opaque or in masked ROM. Called out explicitly each time.

---

## 1. The CPU is Tensilica Xtensa

The connac2 generation (the "neptune" WM core in MT7961/7921/7922/7915) runs Tensilica
Xtensa LX, little-endian, 32-bit, with a vendor vector/DSP TIE coprocessor. Proof:

- Entry point decodes as Xtensa `J`. `[proven-bytes]` `region0` loads at `0x00915000`; its
  first three bytes are `46 00 09`. Decoded as a little-endian Xtensa CALL/J word
  `w = 0x090046`: `op0 = w[3:0] = 0x6` (the `J` major), 18-bit signed displacement
  `imm18 = w[23:6] = 9217`, target `= PC + 4 + imm18 = 0x915000 + 4 + 9217 = 0x917405`. So the
  entry is `j 0x917405`, an ordinary Xtensa unconditional jump. Other ISAs decode this as
  garbage; only `asm.arch=xtensa` yields coherent code across the region.
- `l32r` PC-relative literal pools resolve. `[disasm]` `l32r` (`op0 = 1`) loads a 32-bit
  constant from a negatively-offset, word-aligned literal pool:
  `lit = ((PC + 3) & ~3) + ((imm16 - 0x10000) << 2)`. Applying this across the image lands on
  word-aligned constants that are valid code/rodata pointers (and resolve string operands), an
  Xtensa-specific addressing mode that would not line up on any other ISA.
- Windowed-ABI prologue/epilogue and call shape. `[disasm]` The image uses `entry` / `retw` /
  `l32e` / `s32e` and `call4` / `call8` / `call12` register-window calls throughout, the Xtensa
  Windowed Register Option.
- Code-density + loop options present. `[disasm]` Narrow 16-bit forms (`mov.n`, `ret.n`,
  `add.n`, `l32i.n`, `s32i.n`, `movi.n`, `bnez.n`) appear exactly where the Xtensa length rule
  predicts them.

Conclusion: connac2 WM = Xtensa + TIE.

---

## 2. The connac2 container format

`[proven-bytes]` Parsed directly against the mt76 kernel-driver structs
(`mt76_connac_mcu.h`: `mt76_connac2_fw_trailer` and `mt76_connac2_fw_region`). The blob is, from
the start of file: all region payloads concatenated, then `n_region` region headers, then a
single trailer at EOF.

### Trailer, `struct mt76_connac2_fw_trailer`, last 36 bytes

| offset | field | type | MT7961 value |
|-------:|-------|------|--------------|
| 0x00 | `chip_id` | u8 | `0x0d` |
| 0x01 | `eco_code` | u8 | `0x01` |
| 0x02 | `n_region` | u8 | `5` |
| 0x03 | `format_ver` | u8 | `2` |
| 0x04 | `format_flag` | u8 |, |
| 0x05 | `rsv[2]` | u8×2 |, |
| 0x07 | `fw_ver` | char[10] | `"____010000"` |
| 0x11 | `build_date` | char[15] | `"20260224110949"` |
| 0x20 | `crc` | __le32 | `0x5775a48a` |

Total 36 bytes.

### Region header, `struct mt76_connac2_fw_region`, 40 bytes (0x28) each

| offset | field | type | note |
|-------:|-------|------|------|
| 0x00 | `decomp_crc` | __le32 | CRC of decompressed payload (unused here) |
| 0x04 | `decomp_len` | __le32 | `0` on every region ⇒ payload is RAW, not compressed |
| 0x08 | `decomp_blk_sz` | __le32 | decompression block size (unused) |
| 0x0c | `rsv[4]` | u8×4 |, |
| 0x10 | `addr` | __le32 | load virtual address |
| 0x14 | `len` | __le32 | payload length |
| 0x18 | `feature_set` | u8 | bitfield (see patchability) |
| 0x19 | `type` | u8 | region type |
| 0x1a | `rsv[14]` | u8×14 |, |

Total 40 bytes. The `n_region` headers sit immediately before the trailer, i.e. header `i`
is at `file_end - (n_region - i)*40 - 36`.

### MT7961 region map `[proven-bytes]`

| region | file offset | load VA | size | role |
|--------|------------:|---------|-----:|------|
| region0 | `0x000000` | `0x00915000` | `0x058c10` (363 KB) | WM CODE (entry `0x915000` → `j 0x917405`) |
| region1 | `0x058c10` | `0x02015c00` | `0x042810` (272 KB) | rodata, strings, dispatch/TLV tables, config-symbol DB |
| region2 | `0x09b420` | `0x00404400` | `0x003c10` | data |
| region3 | `0x09f030` | `0xe0270000` | `0x00cad0` | IRAM / peripheral |
| region4 | `0x0abb00` | `0x00000000` | `0x015960` | data / overlay |

Entry point = override address `0x915000` (region0). The download protocol is per-region
`FW_SCATTER` + `FW_START(override=0x915000)`, no scatter-list compression, no signature step.

A second blob, `WIFI_MT7961_patch_mcu_1_2_hdr.bin` (the ROM patch, "neptune" platform
`ALPS`), loads at ~`0x900000` *before* the RAM code; in the analysis project it is mapped at
`0x00900000` (capped to `0x15000` so it abuts region0).

### Integrity / patchability `[proven-bytes]`

- Plaintext. region0 `feature_set = 0x20 = FW_FEATURE_OVERRIDE_ADDR` (bit 5); the
  `FW_FEATURE_SET_ENCRYPT` (bit 0) is not set, so `gen_dl_mode()` does not add
  `DL_MODE_ENCRYPT`, region0 downloads as cleartext (which is why it disassembles).
- Unsigned. The image ends in the 36-byte trailer; there is no RSA/hash block, and
  `mt76_connac_mcu_send_ram_firmware()` performs only `init_download` + raw `FW_SCATTER` +
  `start_firmware`. No signature exists in the protocol.
- CRC-32 only, recomputable. The trailer `crc = 0x5775a48a` equals `zlib.crc32(blob[:-4])`
  exactly, and the driver sends `check_crc = 0`. A patched blob is re-stamped trivially.

The blob is patchable in principle, though §7 shows the dual-AP limitation is not a
single-byte flag.

---

## 3. The instruction-length rule, and the capstone/LLVM ESP32-S3 mis-model

Xtensa instruction length is fixed by `op0` (the low nibble of byte 0). The rule that holds
across the entire MT7961 image:

```
op0 in {8, 9, A, B, C, D}      -> 2 bytes   (Code-Density / narrow forms)
op0 in {0..7, E, F}            -> 3 bytes   (24-bit words, incl. the custom-TIE majors)
```

There are no 4-byte and no FLIX/VLIW (8/16-byte) instructions in this firmware. The key
correction is:

> `op0 = 0xE` and `op0 = 0xF` are 3-byte (24-bit), not 4-byte.

### Why capstone/LLVM get it wrong

`[proven-bytes]` capstone-6's `CS_ARCH_XTENSA` (and LLVM's Xtensa backend) bundle Espressif's
ESP32-S3 vector extension, which defines `op0 = 14/15` (`0xE`/`0xF`) as 4-byte `ee.*`
instructions. That is a *different CPU* that merely reuses the same opcode slots. capstone's
count of size-4 instructions exactly equals its count of `op0 = 0xE`+`0xF` ops, i.e. it is a
model assumption, not a measurement of this firmware. Reading E/F as 4 bytes desyncs the
stream by one byte at every E/F op (~11,400 sites in region0) and cascades into hallucinated
FP/MAC mnemonics (`un.s`, `mula.da`, `round.s`, `lsi`, `ee.ldf.64.xp`).

### Proof that E/F are 3 bytes (four independent methods)

1. Next-op0 distribution (`lentest_nextop.py`). After a correctly-sized instruction, the
   *next* byte's `op0` follows the global instruction-start `op0` histogram; after a wrongly-sized
   one it is an interior byte with a different distribution. chi2/n vs a reference boundary
   histogram: `op0=E` -> 11.8 at len=3 vs 62.3 at len=4; `op0=F` -> 11.1 at len=3 vs 78.2
   at len=4 (lower = better). And the fraction "next op0 == E" is 3% under len=3
   (matching the true ~4.3% rate at which E *starts* an instruction) but 9% under len=4, a
   4-byte step keeps landing mid-instruction on another E byte.
2. The 4th byte IS the next instruction (`opcodes_analyze.py`). Reading E ops as 4 bytes, the
   low nibble of `byte[off+3]` is distributed `0:22% 4:11% 8:11% c:10% 1:6% ...`, an almost exact
   match to the global instruction-start `op0` histogram (`0:24.9 4:11.1 8:6.9 c:7.3 1:8.2 ...`).
   If E were 4-byte, that byte would be a fixed opcode/operand field, not a copy of the
   start-distribution.
3. Branch-target landing (`lentest_branch.py`). Forward local branches whose span crosses an
   E/F op land on a sweep boundary 36.8% of the time under len=3 vs 32.1% under len=4 (weak but
   consistent).
4. Ghidra A/B (§6). End-to-end function recovery, E/F = 3 vs 4 bytes, everything else
   identical: 3-byte wins on every metric.

---

## 4. The custom-TIE opcode space

`[proven-bytes]` 24-bit little-endian field layout (`w = b0 | b1<<8 | b2<<16`):
`op0=w[3:0]  at=w[7:4]  as=w[11:8]  ar=w[15:12]  op1=w[19:16]  op2=w[23:20]`.
16-bit narrow: `n_op0=w[3:0]  n_at=w[7:4]  n_as=w[11:8]  n_ar=w[15:12]`. (`at/as/ar` are the
SLEIGH names for the Tensilica t/s/r register nibbles.)

Census from a linear sweep of region0 under the verified length rule:

| group / encoding | match (LE) | len | count | % of instrs |
|------------------|-----------|----:|------:|------------:|
| `op0 = 0x4` (MAC16 slot, repurposed) | `b0[3:0]==4` | 3 | 13,774 | 10.28% |
| `op0 = 0xE` | `b0[3:0]==E` | 3 | 5,765 | 4.30% |
| `op0 = 0xF` | `b0[3:0]==F` | 3 | 5,671 | 4.23% |
| NARROW ST3 (`op0=D, r=1..14`) | `b0[3:0]==D & w[15:12] in 1..14` | 2 | 4,804 | 3.59% |
| QRST CUST0 (designer-reserved) | `op0==0 & op1==6` | 3 | 1,469 | 1.10% |
| QRST `op1=0xC` (reserved RST) | `op0==0 & op1==C` | 3 | 1,356 | 1.01% |
| QRST `op1=0xD` | `op0==0 & op1==D` | 3 | 1,173 | 0.88% |
| QRST `op1=0xE` | `op0==0 & op1==E` | 3 | 1,102 | 0.82% |
| QRST `op1=0xF` | `op0==0 & op1==F` | 3 | 910 | 0.68% |
| QRST CUST1 (designer-reserved) | `op0==0 & op1==7` | 3 | 651 | 0.49% |
| QRST ST0 `op2=0x7` (reserved) | `op0==0 & op1==0 & op2==7` | 3 | 81 | 0.06% |
| SI BI1 reserved (`op0=6,n=3,m=1,r not in {0,1,8,9,10}`) | `b0==0x76 & ar not in {...}` | 3 | 66 | 0.05% |
| TOTAL custom | | | ~36,800 | ~27.5% |

So ~27% of all instructions are vendor TIE, dominated by `op0 = 4/E/F`. The remainder is
the QRST designer-reserved (CUST0/CUST1) and reserved-RST majors (`op1 = C..F`), the reserved
narrow ST3 lane, and a tiny BI1 reserved branch-ish lane.

### There is no sub-opcode field (why the ops cannot be named)

`[proven-bytes]` Per-bit `P(bit=1)` over each group's 24-bit words (denoised against the
`l32r` literal pools) shows that for `op0 = E/F/4` only `op0` is constant, all ~19-20
remaining bits are operand-like (entropy 3.0-3.9 of a 4.0 max per nibble). Unlike the base QRST
format (where `op1`/`op2` cleanly select the operation), here `op1` and `op2` are as uniform as
the register nibbles; the joint `op2|op1` yields 250-256 distinct values spread across the space,
not a small concentrated selector. For CUST0/CUST1, `op0`+`op1` are constant and the rest is
operands. A data-flow probe (do the `at/as/ar` nibbles of a custom op match a source register of
the next base instruction?) matches only 18-33% of the time, no field is a clear >=60% "written
register", so even dest/src register *roles* cannot be assigned.

Conclusion: a handful of opaque MAJORS, each effectively one TIE-instruction class with
~16-20 operand bits. Individual operations are not recoverable from the static image;
naming them needs MediaTek's Xtensa config/TDK overlay, which is not public (confirmed absent
from LinkIt / OpenWrt / Filogic SDKs and all publicly documented RE efforts).

---

## 5. The SLEIGH decoder (`xtensa-mtk.sinc`)

`xtensa-mtk.sinc` adds, behind the stock Xtensa constructors (which stay strictly more specific
and continue to win), one length-correct, never-fail, opaque constructor per custom major.
Each emits a `define pcodeop` `CALLOTHER` that takes no operands, so the disassembler stays in
sync and the decompiler renders an opaque intrinsic instead of aborting, without fabricating
data flow (the real operands are unknown).

| constructor | matches | len | pcodeop |
|-------------|---------|----:|---------|
| `tie.e` | `op0=0xE` | 3B | `mtk_tie_e` |
| `tie.f` | `op0=0xF` | 3B | `mtk_tie_f` |
| `tie.4` | `op0=0x4` | 3B | `mtk_tie_4` (repurposed MAC16) |
| `cust0` | `op0=0 & op1=6` | 3B | `mtk_cust0` |
| `cust1` | `op0=0 & op1=7` | 3B | `mtk_cust1` |
| `tie.q` | `op0=0` (catch-all) | 3B | `mtk_tie_q` (covers `op1=C..F`, `op2=7`) |
| `tie.2` | `op0=0x2` | 3B | `mtk_tie_2` |
| `tie.3` | `op0=0x3` | 3B | `mtk_tie_3` |
| `tie.d` | `n_op0=0xD` | 2B | `mtk_tie_d` (narrow ST3 `r=1..14`) |
| `tie.6` | `op0=6, n=3, m=1` | 3B | `mtk_tie_6` (SI BI1 reserved `r`) |

Implementation notes:

- The 3-byte ops reference the stock 24-bit `insn` token fields (`op0/op1/op2/ar/as/at`), so
  they are exactly 3 bytes and live in the same SLEIGH decision tree as the base ISA. They fix
  only `op0` (CUST0/1 also fix `op1`), so the much more specific stock constructors (e.g. the 54
  MAC16 `mul*`/`mula*` ops at `op0=4`) match first; the catch-all is the guaranteed fallback that
  always consumes the bytes.
- An earlier version modeled `op0=E/F` as 4-byte via a 32-bit `mtkinsn` token (`xtensa-mtk.4byte.sinc`,
  kept for the A/B comparison). That was wrong, see §3, and is superseded by the 3-byte file.
- The register nibbles are surfaced in the disassembly display only.
- This file replaces Ghidra's stub `flix.sinc` (which matched `op0=0xE` as a 3-byte
  no-semantics op and never handled `op0=0xF`) and `cust.sinc` (CUST0/CUST1), both are dropped
  from the `xtensa_le.slaspec` include list.

---

## 6. Ghidra A/B validation

`[proven-bytes]` Ghidra 12.1 headless, identical harness (AddBlocks + SeedCode + quality check,
465 code-pointer seeds), `Xtensa:LE:32` @ `0x915000`, over the 363,536-byte code range:

| variant | instructions | byte coverage | functions | undefined bytes |
|---------|-------------:|--------------:|----------:|----------------:|
| STOCK (no MTK patch) | 1,880 | 1.33% | 509 stubs (4 clean) | 358,302 (98.6%) |
| patched, E/F = 4 bytes | 83,321 | 64.05% | 2,076 | 126,534 |
| patched, E/F = 3 bytes | 87,621 | 65.16% | 2,173 | 122,528 |

Reading:

- STOCK -> patched is the function-recovery fix. Stock decodes 1,880 instructions (1.3%);
  each seeded function aborts after ~3 instructions at its first custom opcode (509 function
  stubs, only 4 of them clean, abandoned at the first unknown opcode; first failure is
  `0x91740a = dd5d`, a narrow ST3 custom op). Adding length-correct catch-alls jumps instruction recovery 46x and byte
  coverage 49x, because every encoding now *resolves*, Ghidra stops marking bad-data and
  abandoning functions.
- 3-byte vs 4-byte is the correctness refinement. Both patched variants resolve every opcode
  and Ghidra re-syncs at control-flow targets, so the wrong 4-byte length only mis-decodes ~1
  instruction after each E/F op instead of aborting, the headline gap looks modest, but the
  analytically correct 3-byte length recovers +4,300 instructions, +97 functions, -4,006
  undefined bytes, and the bytes after every E/F op decode correctly instead of as garbage.
- With deeper seeding (also seeding the WM ROM-patch from inbound call/jump refs), region0
  function recovery reaches 4,471. The remaining ~35% undefined is mostly genuine inline data
  (`l32r` literal pools, the region-descriptor table @ `0x96dac8`, jump tables) plus code not
  reached by pointer seeding.

---

## 7. Firmware architecture

What the decoder unlocked: the host-command -> BSS-setup -> channel-grant -> scheduler chain, and
the concrete reason a single-RF MT7961 cannot run two simultaneous APs.

### 7.1 Command dispatch (EXT + UNI)

`[proven-rodata + driver]` Two adjacent command tables in region1 rodata, preceded by a
module descriptor @ `0x02022cbc` `{group_fn=0x00916478, MAGIC=0x1818cdef}`. See
`kaitai/COMMAND-MAP.md` for the full dump:

- The EXT command table @ `0x02022ce0`: small cids matching `enum mcu_ext_cmd` (e.g. cid
  `0x01` = `EFUSE_ACCESS`).
- The UNI command table @ `0x02022de8`: cids `0x01..0x30` match `enum mcu_uni_cmd`. All four
  of `BSS_INFO_UPDATE` (cid `0x02`), `STA_REC_UPDATE` (`0x03`), `EDCA_UPDATE` (`0x04`),
  `GET_STAT_INFO` (`0x23`) dispatch to one shared generic UNI TLV handler `FUN_009182ae`, the
  usual connac pattern. (Driver confirms `MCU_UNI_CMD_BSS_INFO_UPDATE = 0x02`.)

A separate legacy MCU_EXT/CE table @ `0x02025cd0` has sparse large ids (`0x8d, 0x8f, 0xc8,
...`); its id-2 entry -> `0x0091f616` is an *unrelated* EXT command, not the UNI BSS handler.

### 7.2 BSS_INFO / RLM (channel into the per-BSS context)

`[proven-rodata]` `FUN_009182ae` walks the BSS TLV table @ `0x02018120` (stride-8
`{handler, tag}`; first entry `{0x0091ca32, tag=1 (RA)}`; the string `bssUniCmdBssInfoBasic`
sits at `0x02018104`). The BASIC TLV sets `eNetworkType` / `eConnOpType`; AP is recognised by
`(((prBssInfo)->eConnOpType) == OP_MODE_ACCESS_POINT)` `[rodata @0x02017893]`. Both infra-APs
decode to the same `NETWORK_INFRA` + `OP_MODE_ACCESS_POINT`, there is no distinct "second-AP"
role.

`[disasm]` The RLM/chanctx TLV is `tag=2 -> handler 0x0091bfb4`:
```
0091bfbf  movi.n a15, 0xc
0091bfc1  call0  0x00990a24
0091bfc9  j      0x009241dd            ; tail-call -> RLM processor
```
`FUN_009241dd` stores the channel params into the per-BSS chanctx, then branches into the RLM
body:
```
009241ec  s32i.n a12, a4, 0x0          ; store into BSS ctx
00924204  l32i.n a12, a5, 0x3c
00924206  j      0x00924e03            ; -> FUN_00924dfb (RLM body)
0092421a  j      0x00925226            ; -> FUN_009251d1 (RLM body)
```
The RLM leaf just *copies* the control channel / center-freq / bandwidth / band into the BSS
context; it requests and schedules nothing. The grant happens later in CNM when the BSS is
activated.

### 7.3 CNM channel-grant, the single-RF authority

`[in-image + rodata]` The CNM cluster (`cnm.c` / `cnm_radio.c` / `cnm_open.c`) lives in
region0 (~`0x0094e4fa..0x0094fc04`, plus the RLM bodies `FUN_00924dfb` / `FUN_009251d1`),
not in masked ROM; only certain leaf helpers like `bssGetBssInfoByBssIdx` are in the
`0x008xxxxx` ROM stub. The grant logic is
present but TIE-decode-blocked for clean C. Its data model `[rodata]`:
```
prHeadChInfo && (eDBDCBand >= ENUM_BAND_0) && (eDBDCBand < 2)            @0x0201e3ac
(i < prChInfo->ucWorkingNetNum) && (eDBDCBand < 2) && (eDBDCBand >= 0)   @0x020184a7
prMsgHeadGrantAllChReq                                                   @0x0201e504  (grant queue head)
prMigrationChInfo / (eTargetDBDCBand < 2)                               @0x0201e47c / 0x0201e441
IndBssEarlyAbs,Bss[%u] not in HeadOPCH                                  @0x0201832c  (off-channel/absence)
```
CNM grants the single RF; `prChInfo[band].ucWorkingNetNum` is the set of nets time-sharing one
channel. A 2nd channel needs either band-1 (a 2nd PHY) or an MCC migration.

### 7.4 The MCC time-share scheduler, and the missing AP quota role

`[proven-rodata]` The per-net quota lookup is keyed by role (`eChInfoType`), gated by
this literal ASSERT condition string `@0x0201821c`:
```
(eCondition  >= ENUM_CNM_QUOTA_CONDITION_DEFAULT) && (eCondition  < ENUM_CNM_QUOTA_CONDITION_NUM) &&
(eChInfoType >= ENUM_CNM_QUOTA_CHINFO_STA)        && (eChInfoType < ENUM_CNM_QUOTA_CHINFO_NUM)
```
The role axis begins at `_STA`; the helper is `getMinimumQuotaTime` `@str 0x02023a0c`; the
min-quota log is literally `"STA/GC min quota time: %d us"` `@0x02018510`. The only quota /
absence knobs in the entire image (verified across all regions) are:
```
MccStaQuotaTimeInUs    @0x020254f0   (CHINFO_STA)
MccP2pGoQuotaTimeInUs  @0x02025488   (CHINFO_P2P_GO)
MccP2pGcQuotaTimeInUs  @0x020254bc   (CHINFO_P2P_GC)
CnmAbsenceMarginInUs   @0x02025524   (STA)
CnmGOAbsenceMarginInUs @0x02025558   (P2P-GO only)
```
Negative result, re-run over every region:
`grep ApQuota|SapQuota|MccAp|MccSap|MccSoftAp|ApAbsence|CHINFO_AP|CHINFO_SAP` -> 0 hits.
Notice-of-Absence (the mechanism that vacates the RF for the other net) is P2P-GO-only:
`pmP2pGONetwork*`, `arTimerPrdNoa[i].u4NextStartTimeUs`, gated on
`((prBssInfo)->eNetworkType) == NETWORK_TYPE_P2P` `@0x02019648`. There is no `pmApNetwork*`
absence path.

`[proven-rodata]` SAP *is* a real role for beaconing/link-detect/CSA (`pm_sap.c`,
`bss_sap_beacon.c`, `linkdt_sap.c`; `LinkDtSapCheckIntervalPureAp`, `GO_SAP[%d] IN_PROGRESS`), so
the firmware fully supports one AP. It simply has no MCC quota / absence role to
time-share the single RF with a *second* concurrent BSS on another channel.

### 7.5 The single-RF / DBDC gate

`[proven-rodata]` The "2" in every band assert is `RAM_BAND_NUM` (PHY-band count), e.g.
`eDbdcIdx(%d) >= RAM_BAND_NUM` `@0x0201f814`, and `DBDC band :%d not support in MT7961`
`@0x02021e9c`. The BSS ceiling, by contrast, is 4:
`(((prStaRec)->prBssInfo)->ucBssIndex) < ((4)+(1-1)+0+0)` `@0x020193b5` and ChReq
`ucBssIndex < (4)+1` `@0x020183e0`. So the firmware supports 4 BSS, "no dual-AP" is *not* a
BSS-count limit. (The DBDC string itself is an ID-based DBGLOG token with zero code pointers
to it in the image, it is host-side logging, not a flippable gate.)

### 7.6 Why the 2nd AP gets nothing `[inferred, see caveat below]`

A 2nd infra-AP BSS on a different channel needs one of two things; both are closed:

1. A 2nd PHY band (real DBDC): refused, MT7961 is single-RF; band-1 is rejected
   (`DBDC band :%d not support in MT7961`), and the coex op-mode array is per-DBDC-band. (The
   live silicon advertises DBDC-capable, `0x70010020 = 0x20`, `MT_HW_BOUND` BIT(5), so the gate
   is a firmware/SKU policy, not the radio.)
2. A time-share slot on the one RF (MCC): refused, the quota lookup (`getMinimumQuotaTime`,
   keyed `ENUM_CNM_QUOTA_CHINFO_STA..NUM`) and the absence/NoA machinery have arms only for
   STA / P2P-GO / P2P-GC. An `OP_MODE_ACCESS_POINT` BSS maps to no CHINFO quota type and has no
   absence path, so CNM cannot enter it into a concurrent schedule.

In summary: the 2nd AP either collapses onto the first AP's `prChInfo` (same channel/working-net) or
gets no grant; only the first AP, holding the CNM grant on the single band-0 channel, beacons.
This is a policy/role-table limitation (missing AP quota role + single usable band), not
a BSS-count ceiling and not a host-driver limit.

### Caveat: proven vs inferred for §7.6

- Proven (decode-independent rodata): the quota enum starts at `ENUM_CNM_QUOTA_CHINFO_STA`;
  exactly three `Mcc{Sta,P2pGo,P2pGc}QuotaTimeInUs` knobs exist; NoA/absence is GO-only; the
  negative grep for any AP/SAP quota/absence symbol is empty across all regions; the BSS ceiling
  is 4 and the band ceiling is `RAM_BAND_NUM`; band-1 is refused on MT7961; both infra-APs decode
  to the same `NETWORK_INFRA`/`OP_MODE_ACCESS_POINT`.
- Inferred (not yet read as instructions): the leaf `switch(eChInfoType)` role-mapper
  itself, the code that, given a BSS, selects (or fails to select) a CHINFO quota type, is
  TIE-opaque / partly mask-ROM and was not recovered as C. The conclusion rests on the
  rodata data model + the negative search, which are decode-independent, but the exact branch
  instruction that drops an AP BSS with no quota type is the one piece still blocked. Giving the
  custom-TIE ops real semantics (the unpublished MediaTek config), or marking the `0x008xxxxx`
  ROM callees no-return so the decompiler stops chasing uninitialized memory, would turn this
  last step from [inferred] into [disasm].

---

## 8. Source artifacts

The raw analysis backing every number above (carved regions, `decode.py`, the length-proof
scripts `lentest_nextop.py` / `opcodes_analyze.py` / `lentest_branch.py` / `bit_entropy.py`, the
Ghidra A/B harness, and the per-subsystem walker reports `SCHEDULER.md` / `mcc-scheduler.md` /
`bss-network-type-map.md`) lives in a separate analysis tree (`firmware-re/` and
`firmware-re/ghidra-work/`), not included in this repo. The opcode census and length proofs are
written up in `ghidra-work/opcodes.md`; the firmware-architecture synthesis is
`ghidra-work/walk/SCHEDULER.md`.
