# A capstone Xtensa decoding bug found via this RE, and the fix

While building the decoder for MT7961 firmware, capstone 6.0 (`CS_ARCH_XTENSA`) turned
out to mis-decode this chip's instructions, and the bug is not specific to MediaTek: it
affects every non-ESP32-S3 Xtensa target.

## The bug

Any instruction with op0 `0xE`/`0xF` is decoded as a 4-byte ESP32-S3 SIMD/AI `ee.*` op,
even in base or esp32/esp32s2/esp8266 mode. On MediaTek connac2 those bytes are 3-byte
vendor TIE ops, so capstone over-reads by one byte and the whole linear sweep desyncs.

```
cstool esp32 9e3e0940  ->  ee.vmulas.u16.accx.ld.ip.qup ...  (size 4)   # wrong: should not decode
```

(`9e3e0940` and `3e194548` are real bytes from `WIFI_RAM_CODE_MT7961_1.bin`.)

## Root cause

capstone's Xtensa support is auto-translated from LLVM, and the translator stubbed the
subtarget feature gates to always return true, in `arch/Xtensa/XtensaDisassembler.c`:

- `Xtensa_getFeatureBits()` was `// we support everything; return true;`
- `hasDensity()` / `hasESP32S3Ops()` / `hasHIFI3()` were hardcoded `return true;`

So the ESP32-S3 instruction tables are enabled for every target regardless of mode. LLVM
itself is correct: it gates these ops behind a real subtarget feature and only decodes
them for an esp32s3 target. This is a concrete instance of capstone issue #1992 (features
enabled by default produce wrong disassembly). It is not a regression to bisect: Xtensa is
new in capstone 6 and has never decoded a non-S3 config correctly.

## The fix

Mirror the in-tree SystemZ pattern: make `Xtensa_getFeatureBits(mode, feature)` map the
mode to a feature set, thread `MI->csh->mode` into the three `has*Ops` gates, and add an
opt-in `CS_MODE_XTENSA_ESP32S3`. After the fix, base and esp32/esp32s2/esp8266 modes stop
emitting ESP32-S3 ops, while `CS_MODE_XTENSA_ESP32S3` preserves them.

```
cstool esp32   9e3e0940  ->  invalid assembly code               # base config, correct
cstool esp32s3 9e3e0940  ->  ee.vmulas.u16.accx.ld.ip.qup ...     # preserved when asked for
```

Base and density ops still decode in every mode. The `suite/auto-sync` saved patch hashes
are updated so the fix survives the next LLVM re-sync (the stubs had been re-introduced by
auto-sync, which is why it regressed silently). New `tests/MC/Xtensa/esp32s3.s.yaml`; the
full Xtensa MC suite passes 105/105.

This fixes Xtensa decoding for everyone using capstone, and for rizin, which decodes
Xtensa entirely through capstone now.

## Status

Submitted to `capstone-engine/capstone` (branch `next`): <PR link to be added>.
