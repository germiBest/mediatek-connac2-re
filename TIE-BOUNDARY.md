# The TIE boundary: why the MCC scheduler cannot be rendered, and what can

The MT7961 firmware answers most questions, but one stays sealed: the literal MCC
quota role-switch (`getMinimumQuotaTime`, the `eChInfoType` decision that grants channel
time to STA/P2P-GO/P2P-GC but not to a second AP). This documents exactly where the
boundary is, why it holds, and what is recoverable on either side of it. The conclusion
about the scheduler (no AP quota role) does not depend on rendering this code; it is
proven from the firmware's own compiled-in assert strings (`ENUM_CNM_QUOTA_CHINFO_STA`,
the three `Mcc*QuotaTimeInUs` knobs, a zero image-wide grep for any AP quota). What
follows is why every attempt to *read the switch itself* fails.

## The wall, confirmed five independent ways

| approach | result on the scheduler |
|---|---|
| Ghidra decompiler | times out on the TIE-dense functions (`process: timeout`) |
| static disassembly | desyncs at each vendor-TIE opcode (op0 = 0x4 / 0xE / 0xF) |
| the mask ROM dump | the role-switch is not in the ROM (it is in TIE-sealed RAM) |
| the live chip | WM-CPU DRAM is not host-readable; the firmware log channel is silent |
| emulation | the TIE ops feed the control flow and cannot be no-op'd (below) |

All five fail for the same root cause: MediaTek's custom Tensilica TIE coprocessor. The
ops have no published semantics and no localized sub-opcode field, so no public tool
decodes them.

## Emulation: proof by execution that the logic is inside the TIE

We built a p-code emulator (pypcode lifting the Ghidra `Xtensa:LE:32:default` SLEIGH, a
~500-line interpreter; the only runnable Xtensa path here, since Unicorn, qemu-xtensa,
radare2-ESIL and angr all lack Xtensa execution). It lifts each instruction, runs the
base ISA, and treats every vendor-TIE op as a length-correct no-op. The hypothesis was
that the control-flow branches do not depend on the TIE ops, so stubbing them would still
let the scheduler's logic run.

That hypothesis is false, and the emulator proves it:

- On base-ISA code the emulator steps and computes faithfully (verified on a synthetic
  function and on ROM functions).
- On the scheduler `FUN_0094e4fa` it falls into an infinite loop at `0x94df4c`. The loop
  exit tests `a2 = extui(a9, 4, 11)`, and `a9` is never modified by any base-ISA
  instruction in the loop body. The only ops touching the loop state are the `cust0` /
  `cust1` vendor-TIE ops, which we are forced to no-op.
- Over 200 steps of the scheduler, about 31% of executed instructions are opaque
  TIE/`cust` ops, and the control flow depends on them.

So the scheduler's decision logic is partly *implemented in the custom ops*. They are not
DSP payload the branches ignore; they compute the values the branches test. Stubbing them
yields garbage and loops. This is the static decompiler timeout seen at runtime: the same
wall, reached by execution instead of analysis.

The harness still has value: it faithfully executes the base-ISA majority of the firmware
(boot, HIF, command handlers), where it is a usable tool. It just cannot run TIE-bound
logic, by construction.

## Dynamic attempts, and why they did not get past the wall

- Verbose firmware logging. The lever is `FW_DBG_CTRL` (EXT cmd 0x95), confirmed
  present in the firmware (dispatch slot `0x02025ea8`, a real ~423-byte handler). We
  ported `mt7915_mcu_fw_dbg_ctrl` into mt7921 as a debugfs hook and set every log module
  to level 7. The command is accepted with no error, but the firmware emits nothing to the
  host through a full association, verified with a handler patched to surface every
  message of any type. The logs, if generated, stay in the chip's internal ring buffer and
  are never pushed out.
- Live chip memory. Reads of the CR-bus regions (ROM at 0x800000, SRAM at 0x400000,
  registers) work and are safe, which is how the ROM was dumped. But the scheduler's state
  lives in WM-CPU DRAM (0x80000000), which is the core's local virtual space, not on the
  host bus; reading it destabilizes the chip. The coredump that would snapshot it requires
  forcing an assert, which hard-wedges the device.

## What is recoverable, on the near side of the wall

- About 73% of the image is base Xtensa with real mnemonics, fully readable.
- The command and TLV interface is mapped and named (see `DEEP-FINDINGS.md`): the
  dispatch tables, the RLM channel TLV, the STA_REC two-pass dispatch, `sta_rec_basic`.
- The mask ROM (boot, ConnSys OS core, HIF, eFuse) is dumped and largely readable (see
  `ROM-DUMP.md`).
- The emulator runs the base-ISA logic.
- The scheduler conclusion stands from the asserts.

## Untouched areas that do not hit this wall

The vendor TIE caps the Wi-Fi MAC scheduler specifically. It does not cap everything. The
combo chip's Bluetooth firmware (`BT_RAM_CODE_MT7961`) is a separate connac2 blob the same
tools parse, the host-controlled TLV parsers are named and auditable, and the same
extension applies to the MT7922 and MT7915 family blobs. Those are open ground.
