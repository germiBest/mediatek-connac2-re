# The vendor TIE coprocessor (op0=0xE/0xF): encoding and semantic classes

`TIE-BOUNDARY.md` established that the vendor TIE walls the Wi-Fi internals. This
note characterizes that coprocessor: what the ops are, how they encode, and which
ones gate control flow. It rests on a bit-field census of all firmware images and
a dataflow analysis over a verified reachable-code corpus (949 instructions taken
to a fixpoint from the WM entry, rejecting any out-of-range branch, call, or l32r).

## A structured, bespoke scalar DSP (proven)

The ops are 3-byte RRR-format scalar instructions. The field layout is `op0[3:0]`
= major (E or F), `{op2,op1,t}` = a distributed sub-opcode of roughly 8 to 12
effective bits, and `{ar,as,at}` = up to three 4-bit register operands (dest `ar`
from `as`, `at`). There are no wide immediates and no FLIX/VLIW bundles.

A census finds about 100 distinct op-shapes that recur with at least three
different operand combinations, against up to ~800 plausible sub-opcode keys. That
is a rich opcode space, not a handful of wide macro-ops.

MediaTek placed the bulk coprocessor in the Tensilica-reserved E/F majors (RM
Table 7-192) and uses the sanctioned CUST0/CUST1 designer space (op0=0, op1=6/7)
separately, which is the usual move when CUST0/1 is too small.

## Probably not a stock Cadence HiFi/ConnX package (inferred)

Every documented HiFi 2/3/4/5 and ConnX BBE16/32/64 package gets its throughput
from 48/64/88-bit FLIX/VLIW bundles. This firmware has no wide instructions: the
byte following each E/F op matches the global op0 start histogram, which a FLIX
slot field could not do. A shipped HiFi/ConnX config would be bundle-dominated, so
its absence argues against a stock audio/baseband DSP. The `mula.da`/MAC16 lineage
shows only a MAC-family Xtensa LX config (MAC16 is a stock option), not HiFi.

The question is partly moot in any case. Cadence publishes mnemonics and semantics
but no fixed binary opcode map; encodings are generated per-config by the TIE
compiler. A documented-package lookup could not yield the encodings even for a
genuine HiFi instance.

## Semantic classes (inferred from the corpus)

Grouped by op2 high nibble, from the register read/write context of the base-ISA
neighbors at each TIE site:

- `op2~0x4`: MAC/DSP datapath sharing the MAC16 40-bit accumulator (M0-M3), with
  load-with-pointer-increment streaming (`ldinc`, `mula.da`, `umul.aa`).
- `op2~0x8`: scaled-index / strided address generation.
- `op2~0xa`: pointer/handle validate-transform-dereference.
- `op2~0xe/0xf`: compare and reduce-to-flag (writes the boolean predicate file b0-b15).

## The control-flow-gating ops

Five verified sites where a `tie.e/f` destination is tested directly by the next
branch. The gating (the op's output steers a branch) is proven; the role name is
inferred:

| `{op2,op1}` | branch | inferred role |
|---|---|---|
| `{0xa,0x3}` | bnez | handle/pointer-validity predicate (after call4) |
| `{0x4,0x1}` | bnez | call-status check (after call12) |
| `{0xf,0x6}` | beq  | equality / select |
| `{0xf,0xc}` | bnez | reduce-to-flag |
| `{0x0,0x1}` | bbsi/ball | status-extract then bit-test |

Naming these by role lets the surrounding control flow be read while the DSP
arithmetic stays opaque. So `op2` in `{0x0,0x4,0xa,0xf}` carries the
extract-and-branch ops that gate scheduler decisions.

## Routes to full per-op semantics

- Documented-package lookup is a dead end. No public binary opcode map exists for
  any HiFi/ConnX config (encodings are per-config generated), and the package is
  bespoke regardless.
- A MediaTek Xtensa config or TIE-source leak is the only route to complete,
  certain semantics, but nothing is indexed publicly. Highest payoff, near-zero
  current availability.
- Behavioral inference by live single-step (JTAG) can pin each op by diffing
  architectural state (GPRs, M0-M3, b0-b15, user regs) across one step with
  controlled inputs. Of the routes that need only hardware debug access, this is
  the one most likely to yield proven semantics.
- Static usage-inference is the only route that delivers now. It classifies and
  names-by-role the operationally important ops above, but cannot pin the exact
  per-opcode arithmetic.

## Decoder fidelity

The permissive SLEIGH model makes instruction length a pure function of the op0
nibble, so about 8% of all bytes decode spuriously as `tie.e/f` (0x00 and 0xFF
padding dominate a naive linear census). Real ops have to be isolated by
recurrence and operand diversity over a reachable-code corpus rather than a linear
sweep. Tightening the decoder's length and validity handling for the custom majors
would improve every static pass.
