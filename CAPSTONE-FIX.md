# A capstone Xtensa decoding bug found via this RE, and the fix

While building the decoder for MT7961 firmware, I found that capstone 6.0 (`CS_ARCH_XTENSA`)
mis-decodes this chip's instructions. The bug reaches well beyond MediaTek; it hits every
non-ESP32-S3 Xtensa target.

## The bug

Any instruction with op0 `0xE`/`0xF` decodes as a 4-byte ESP32-S3 SIMD/AI `ee.*` op, even
in base or esp32/esp32s2/esp8266 mode. On MediaTek connac2 those bytes encode 3-byte vendor
TIE ops, so capstone reads one byte too many and the rest of the linear sweep desyncs.

```
cstool esp32 9e3e0940  ->  ee.vmulas.u16.accx.ld.ip.qup ...  (size 4)   # wrong: should not decode
```

(`9e3e0940` and `3e194548` are real bytes from `WIFI_RAM_CODE_MT7961_1.bin`.)

## Root cause

capstone's Xtensa support is auto-translated from LLVM, and the translator left the
subtarget feature gates stubbed to always return true, in `arch/Xtensa/XtensaDisassembler.c`:

- `Xtensa_getFeatureBits()` was `// we support everything; return true;`
- `hasDensity()` / `hasESP32S3Ops()` / `hasHIFI3()` were hardcoded `return true;`

So the ESP32-S3 instruction tables stay enabled for every target regardless of mode. LLVM
itself gets this right: it gates these ops behind a real subtarget feature and only decodes
them for an esp32s3 target. This is a concrete instance of capstone issue #1992 (features
enabled by default produce wrong disassembly). Don't bother bisecting for a regression.
Xtensa is new in capstone 6 and has never decoded a non-S3 config correctly.

## The fix

The fix follows the in-tree SystemZ pattern. `Xtensa_getFeatureBits(mode, feature)` now maps
the mode to a feature set, `MI->csh->mode` threads into the three `has*Ops` gates, and a new
opt-in `CS_MODE_XTENSA_ESP32S3` selects the S3 tables. With that in place, base and
esp32/esp32s2/esp8266 modes no longer emit ESP32-S3 ops, while `CS_MODE_XTENSA_ESP32S3`
keeps them.

```
cstool esp32   9e3e0940  ->  invalid assembly code               # base config, correct
cstool esp32s3 9e3e0940  ->  ee.vmulas.u16.accx.ld.ip.qup ...     # preserved when asked for
```

Base and density ops still decode in every mode. I also updated the `suite/auto-sync` saved
patch hashes so the fix survives the next LLVM re-sync; auto-sync had been re-introducing the
stubs, which is why this regressed silently. There's a new `tests/MC/Xtensa/esp32s3.s.yaml`,
and the full Xtensa MC suite passes 105/105.

The fix covers everyone using capstone, including rizin, which now decodes Xtensa entirely
through capstone.

## Status

Submitted to `capstone-engine/capstone` (branch `next`).
