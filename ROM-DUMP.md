# Dumping the MT7961 mask ROM over USB, and what is in it

The downloadable `WIFI_RAM_CODE_MT7961_1.bin` firmware is only the RAM image. The
WM CPU also runs a mask ROM at internal-bus address `0x800000` that the RAM
firmware calls into. That ROM is not in any redistributable file, and it was the
hard boundary for the static RE here: several scheduler leaf functions delegate
into it. This documents how the ROM was read off a live adapter with no JTAG, and
what it contains.

The ROM bytes are MediaTek's and are not redistributed here; what follows is just
the method and the findings, the same approach the related projects take.

## Why it is readable at all

On connac2 the chip's internal control bus is host addressable, and the mask ROM
is mapped on that bus at `0x800000`. The driver's own coredump table proves it:

```c
// mt7915/coredump.c, mt7916/mt798x region tables
{ .start = 0x00800000, .len = 0x0005ffff, .name = "ROM" }
```

On PCIe parts the host reaches that address through an L2 remap window. On USB it
is simpler: every register access is an `MT_VEND_READ_EXT` (0x63) control transfer
that carries the full 32-bit bus address (`___mt76u_rr`, `wValue=addr>>16`,
`wIndex=addr`), so the chip's USB engine decodes `0x800000` directly with no
remap. The driver already reads chip-physical addresses this way at probe
(`MT_HW_CHIPID=0x70010200`, `MT_WTBLON_TOP_BASE=0x820d4000`). Every transaction is
a read of read-only memory, so there is no write to the chip and no risk of a
register-poke hang.

## Method

The existing `regidx` / `regval` debugfs pair already issues that exact transfer
with no address translation, so no driver changes are required.

Identify the adapter's phy first and never touch the internal card:

```
for p in /sys/class/ieee80211/*/; do
  echo "$(basename $p) $(basename $(readlink -f $p/device/driver)) \
        $(cat $p/device/idVendor 2>/dev/null):$(cat $p/device/idProduct 2>/dev/null)"
done
# pick the phy whose driver is mt7921u and id is 0e8d:7961
D=/sys/kernel/debug/ieee80211/phyN/mt76
```

Read one word:

```
echo 0x800000 | sudo tee $D/regidx >/dev/null
sudo cat $D/regval            # -> the little-endian 32-bit word at 0x800000
```

Loop it to pull the region (one root process, reopen `regidx` per word because
debugfs files are not seekable):

```python
import struct
D='/sys/kernel/debug/ieee80211/phyN/mt76'
out=open('rom.bin','wb')
for addr in range(0x800000, 0x900000, 4):
    open(D+'/regidx','w').write(hex(addr))
    out.write(struct.pack('<I', int(open(D+'/regval').read(),16)))
```

That is about 262144 control transfers, a few minutes. A small debugfs patch that
calls `mt76_rr_copy(dev, 0x800000, buf, len)` does it as one batched blob if you
want it fast, but the loop is zero-risk and needs no rebuild.

## Layout found on this MT7961

The first read pass confirmed real content, not zeros:

```
0x800000: 48 00 03 c9 ...   a vector / dispatch table (entries end in 0x48, the
                            Xtensa narrow-load opcode)
0x830000: ...46            an Xtensa `j` opcode
0x85ffff                   end of the documented ROM region
```

The mapped memory in `0x800000-0x8fffff` is sparse: a dense main ROM at
`0x800000-0x85ffff` (about 384 KB), then smaller mapped windows higher up
(`0x880000`, and a block around `0x8c0000` that holds the scheduler leaf functions
the RAM CNM cluster calls, for example the callee at `0x8cb3e8`). The ranges in
between read back as zero.

The ROM carries plaintext source-file paths and assert strings, which the stripped
RAM firmware never had. These name the subsystems even though they are not usable
as function-naming xrefs (see Limits below):

```
mcu/system/rom/init/{sys_cache,sys_irq,Eint}.c     boot, cache, interrupt setup
mcu/system/cos/{cos_api,cos_exp}.c                  the ConnSys OS core + exception path
mcu/driver/rom/{hif,hif_drv,usb3,usb3_drv}.c        host interface and USB transport
mcu/driver/rom/{sys_efuse,sys_spi,uart_dsn}.c       eFuse, SPI, debug UART
mcu/coex/_hal/hal_conn_pta_cmm.c                    Wi-Fi / BT coexistence
mcu/driver/{axi_dma,ccif,wdt}.c                     DMA, inter-core comm, watchdog
exp_main: jump from cos_assert    CHIP_DUMP_STATE_ERR@cos_exp.c
```

## Loading it into Ghidra

Import the dump as Raw Binary, base `0x800000`, language `Xtensa:LE:32:MTK`, then
analyze it alongside the RAM image in one project (load the RAM region0 at
`0x915000` and the ROM block at `0x800000`). With the ROM present as real bytes
instead of an uninitialized stub:

```
functions before (RAM only):  4471
functions after (RAM + ROM):  6511      (+1401 in 0x800000-0x85ffff alone)
```

Much of the ROM decompiles cleanly. Sampled ROM functions, including a 1219-byte
one, decompile in well under a second; only the TIE-dense ones time out, the same
as in RAM. ROM custom-TIE density is about 32 percent, close to the RAM image.

## Limits

- The ROM uses the same ID-based logging as the RAM firmware. None of the 38
  candidate source-path strings are pointer-referenced inside the ROM, so they
  cannot anchor function names by xref. The numeric-id to string database is
  host-side, as it is for the RAM image.
- Loading the ROM did not make the RAM CNM cluster decompile. Those functions
  still time out, which confirms the cause is custom-TIE density plus unmodeled
  special-register varnodes, not the decompiler chasing into unmapped ROM. The
  literal quota role-switch stays sealed for that reason, not for lack of bytes.
- The dump captures memory as the host bus sees it. The sparse mapped windows in
  `0x860000-0x8fffff` are included; the zero ranges between them are unmapped, not
  data.

## What it changes

The mask ROM was the main boundary for the static RE: the routines the RAM
firmware called into were previously just absent bytes. With it dumped, the boot
path, the ConnSys OS core, the host interface and USB transport, the eFuse and SPI
drivers, and the coexistence code are disassembled and largely readable. The grant
leaf functions the scheduler delegates into can now be read directly, even though
the RAM cluster that calls them still does not decompile.
