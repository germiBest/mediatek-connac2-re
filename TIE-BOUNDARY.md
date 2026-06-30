# The TIE boundary: rendering and running the MCC scheduler

Most of the MT7961 firmware can be read. The MCC quota role-switch
(`getMinimumQuotaTime`, the `eChInfoType` decision that grants channel time to
STA/P2P-GO/P2P-GC but not to a second AP) is the piece that stays sealed against a
faithful render: its arithmetic lives in the vendor TIE ops (op0=0xE/0xF), which
have no published semantics. The scheduler can be navigated statically and even
executed in emulation, but the exact role-to-quota arithmetic cannot be recovered.
None of that affects the no-AP conclusion, which is proven from the firmware's own
assert strings (`ENUM_CNM_QUOTA_CHINFO_STA`, the three `Mcc*QuotaTimeInUs` knobs,
and a zero image-wide grep for any AP quota), not from rendering the code.

## Where the boundary actually is

The genuine wall is the op0=0xE/0xF vendor TIE coprocessor. An earlier version of
this note also listed op0=0x4 as vendor TIE; that was wrong. op0=0x4 is the
documented Xtensa MAC16 option (`mula.da.hl.ldinc` and the rest), not a custom op,
and modeling it changes the picture (see "Running the scheduler" below).

| approach | result on the scheduler |
|---|---|
| Ghidra decompiler | times out on the TIE-dense functions (`process: timeout`) |
| static disassembly | desyncs at each vendor-TIE opcode (op0 = 0xE / 0xF) |
| the mask ROM dump | the role-switch is not in the ROM (it is in TIE-sealed RAM) |
| emulation | runs once op0=0x4 (MAC16) is modeled and the runtime DRAM is seeded; only op0=0xE/0xF stay opaque (below) |

The op0=0xE/0xF ops have no published semantics and no localized sub-opcode field,
so no public tool decodes them. `TIE-SEMANTICS.md` characterizes what they are.

## Emulation: the op0=0x4 correction

The first emulator (pypcode lifting the Ghidra `Xtensa:LE:32:default` SLEIGH, a
~500-line interpreter, and the only runnable Xtensa path here since Unicorn,
qemu-xtensa, radare2-ESIL, and angr all lack Xtensa execution) treated op0 in
{0x4, 0xE, 0xF} as opaque and no-op'd them. On `FUN_0094e4fa` it fell into an
infinite loop at `0x94df4c`: the exit tested `a2 = extui(a9, 4, 11)`, and `a9` was
never updated by a base-ISA instruction in the loop body.

The cause was the no-op of op0=0x4, not the vendor TIE. op0=0x4 is documented
MAC16, and `a9` was fed by a MAC16 accumulator read the emulator had been
discarding. Implementing MAC16 for real breaks the loop. Only op0=0xE/0xF, and the
custom ops MediaTek placed in op0=0x4 reserved cells, stay genuinely opaque.

## The coredump supplies the runtime DRAM state

The scheduler operates on data in WM DRAM (`0x80000000`), which the host cannot
read directly. The firmware dumps it on assert:

- Trigger: the `chip_config "assert"` command (the `chip_reset` debugfs path).
- Recovery: a USB `authorized` toggle (`echo 0` then `1` on the device node)
  resets the adapter with no physical replug.
- Format: a 1.3 MB dump, beginning with a text exception summary (the assert line,
  a 32-entry PC log, and an LR log) followed by a memory image of
  `[<addr LE32>,<value LE32>]` records (`[`=0x5b, `,`=0x2c, `]`=0x5d) in labeled
  sections (CMD, RA, PF, WTBL, ...).

Parsed, that is 115,108 live memory words: the full data RAM
(`0x02000000-0x0205xxxx`, where the scheduler's globals live), sparse WM-DRAM
structures (`0x8xxxxxxx`), and the station table (WTBL).

## Running the scheduler

Wiring the `Xtensa:LE:32:MTK` decoder into the emulator (so the custom ops get
correct lengths instead of desyncing), keeping the MAC16 lift on, seeding the
coredump words, mapping the real `0x9xxxxx` worker code dumped off the live chip,
and advancing past the firmware's `ill` traps, `FUN_0094e4fa` executes 312 distinct
instructions loop-free across `0x94047a-0x9bf7e8`, deep into the real workers. It
went from stuck at 10 PCs (a jump to zero) to 312 instructions of real logic on
real data. The vendor TIE no longer blocks execution of the scheduler: MAC16 is
computed for real, and the genuine op0=0xE/0xF ops are opaque but length-correct.

## What still cannot be watched

Two things keep the exact quota decision out of reach, neither of them the TIE:

- Data coverage. The run still has 178 unmapped reads, from host-invisible workers
  and unseeded addresses.
- Invocation context. The scheduler is reached by an indirect `callx` from an ops
  table (runtime `0x0201ea68`, slot +0x24, state id `0xa`) with `a7`=context
  pointer, `a6`=role record, `a4`=state, and it is called cold here. Its early
  branches (`bnez.n a0`, `bgei a4,2`) are register-driven, so without the real
  `a7`/`a6`/`a4` it takes the default path however well the data RAM is seeded. A
  live read of connected-state data RAM and a re-run produced an identical trace
  (312 instructions, 178 unmapped reads, same PC range), which confirms the path is
  fixed by the entry registers, not the globals. Those registers come from a
  snapshot taken mid-scheduling, which needs an assert that hard-wedges the adapter.
  And `getMinimumQuotaTime` itself sits in the TIE-dense CNM cluster, so the
  role-to-quota arithmetic is opaque even once reached.

Verbose firmware logging does not get past it either. The lever is `FW_DBG_CTRL`
(EXT cmd 0x95), present in the firmware (dispatch slot `0x02025ea8`, a real
~423-byte handler). Porting `mt7915_mcu_fw_dbg_ctrl` into mt7921 as a debugfs hook
and setting every log module to level 7, the command is accepted but the firmware
emits nothing to the host through a full association (verified with a handler
patched to surface every message). The logs, if generated, stay in the chip's
internal ring buffer.

## The no-AP result stands on the static anchor

The no-dual-AP conclusion rests on the firmware's own static code, not on watching
the scheduler run:

- `getMinimumQuotaTime` (`cnm_open.c`) is guarded by the assert at `0x0201821c`:
  `(eChInfoType >= ENUM_CNM_QUOTA_CHINFO_STA) && (eChInfoType < ENUM_CNM_QUOTA_CHINFO_NUM)`.
- The role axis has exactly three members: `ENUM_CNM_QUOTA_CHINFO_STA`(0),
  `_P2P_GO`(1), `_P2P_GC`(2), `_NUM`=3, matched one-to-one by `MccStaQuotaTimeInUs`,
  `MccP2pGoQuotaTimeInUs`, and `MccP2pGcQuotaTimeInUs`.
- A grep across all nine firmware images (region0-4, ROM, RAM_CODE, the WM patch,
  and the live worker dump) for `ApQuota|SapQuota|MccAp|MccSap|CHINFO_AP|CHINFO_SAP`
  returns nothing.

A second AP has no quota role to schedule.

## What is recoverable, and what is untouched

- About 73% of the image is base Xtensa with real mnemonics, fully readable.
- The command and TLV interface is mapped and named (see `DEEP-FINDINGS.md`): the
  dispatch tables, the RLM channel TLV, the STA_REC two-pass dispatch, `sta_rec_basic`.
- The mask ROM (boot, ConnSys OS core, HIF, eFuse) is dumped and largely readable
  (see `ROM-DUMP.md`).
- The emulator runs the base-ISA and MAC16 logic, including the scheduler's control
  flow.
- The vendor TIE limits the Wi-Fi MAC scheduler's quota arithmetic specifically, not
  the rest of the firmware. The combo chip's Bluetooth firmware (`BT_RAM_CODE_MT7961`)
  is a separate connac2 blob that the same tools parse, the host-controlled TLV
  parsers are named and auditable, and the same extension applies to the MT7922 and
  MT7915 family blobs.
