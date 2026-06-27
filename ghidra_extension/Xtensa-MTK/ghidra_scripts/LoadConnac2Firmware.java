// MediaTek connac2 Wi-Fi-MCU firmware loader  (GhidraScript)
//
// Part of the mediatek-connac2-re project.  Licensed Apache-2.0.
//
// Makes a *raw* MediaTek connac2 firmware blob (MT7961/MT7921/MT7915-family
// "WM"/"neptune" Wi-Fi MCU) "just work": it parses the connac2 container,
// maps every region at its load address, adds ROM/DRAM stub blocks so the
// decompiler does not thrash on references into memory we do not have, sets
// the entry point from the FW_FEATURE_OVERRIDE_ADDR region, and seeds
// disassembly (entry + every code-pointer literal) so analysis has roots.
//
// Handles BOTH container types:
//   - WIFI_RAM_CODE_*  (WM RAM firmware): mt76_connac2_fw_trailer + N x
//     mt76_connac2_fw_region headers at END of file (little-endian); region
//     DATA concatenated from file start.
//   - WIFI_*_patch_mcu (ROM patch): mt76_connac2_patch_hdr at START of file
//     (big-endian) + N x mt76_connac2_patch_sec section descriptors; each
//     section's data lives at sec.offs in the file.
//
// NOTE: the leading comment must NOT start with a "/* ###" block - Ghidra
// reserves that for its IP-certification header and will reject the script.

//Parse a raw MediaTek connac2 (MT7961/MT7921/MT7915) Wi-Fi-MCU firmware blob:
//map all regions at their load addresses, add ROM/DRAM stubs, set the entry
//point, and seed disassembly. Run AFTER importing the raw .bin with the
//"Xtensa:LE:32:MTK" language (or stock Xtensa:LE:32:default carrying the MTK
//.sinc). Optional arg: absolute path to the firmware file (else the imported
//file's path, else a file chooser).
//@author connac2 firmware-RE project
//@category MTK.Connac2
//@keybinding
//@menupath Tools.MTK.Load connac2 firmware
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.zip.CRC32;

public class LoadConnac2Firmware extends GhidraScript {

	// NOTE: the container parsing below is intentionally duplicated with
	// src/.../Connac2FirmwareLoader.java. This script must stay self-contained so
	// it runs from a zip-only install (where src/ is never compiled); keep the two
	// parsers in sync when the container format changes.

	// ---- connac2 container constants (mt76_connac_mcu.h) ----------------
	private static final int TRAILER_SZ = 36;   // sizeof(mt76_connac2_fw_trailer)
	private static final int REGION_SZ  = 40;   // sizeof(mt76_connac2_fw_region)
	private static final int PATCH_HDR_SZ = 96; // sizeof(mt76_connac2_patch_hdr)
	private static final int PATCH_SEC_SZ = 64; // sizeof(mt76_connac2_patch_sec)

	private static final int FW_FEATURE_SET_ENCRYPT  = 0x01; // BIT(0)
	private static final int FW_FEATURE_OVERRIDE_ADDR = 0x20; // BIT(5)
	private static final int FW_FEATURE_NON_DL       = 0x40; // BIT(6)
	private static final int PATCH_SEC_TYPE_INFO     = 0x2;

	// One parsed region/section: bytes [fileOff, fileOff+len) load at vaddr.
	private static final class Region {
		String  name;
		long    vaddr;
		int     fileOff;
		int     len;
		int     feature;   // RAM feature_set (0 for patch sections)
		boolean exec;
		boolean override;  // FW_FEATURE_OVERRIDE_ADDR
	}

	@Override
	public void run() throws Exception {
		// 1. Obtain the raw firmware bytes.
		byte[] raw = readRawBytes();
		if (raw == null) {
			println("ABORT: could not obtain the raw firmware bytes.");
			return;
		}
		println(String.format("connac2 loader: %d bytes", raw.length));

		// 2. Sanity-check the program language (we only remap memory; the
		//    language must already be the MTK Xtensa one for code to decode).
		String lid = currentProgram.getLanguageID().getIdAsString();
		if (!lid.startsWith("Xtensa")) {
			println("WARNING: program language is '" + lid + "'.");
			println("         Re-import the raw .bin with 'Xtensa:LE:32:MTK'");
			println("         (or stock 'Xtensa:LE:32:default' carrying xtensa-mtk.sinc).");
		}

		// 3. Parse the container.
		boolean isPatch = looksLikePatch(raw);
		boolean isRam   = looksLikeRam(raw);
		String fname = (currentProgram.getExecutablePath() == null) ? ""
				: currentProgram.getExecutablePath().toLowerCase();
		if (isPatch && isRam) {            // both structurally plausible: use the name
			if (fname.contains("patch")) isRam = false; else isPatch = false;
		}

		List<Region> regions;
		if (isPatch) {
			println("container: ROM patch (mt76_connac2_patch_hdr, big-endian)");
			regions = parsePatch(raw);
		} else if (isRam) {
			println("container: RAM firmware (mt76_connac2_fw_trailer, little-endian)");
			regions = parseRam(raw);
			verifyRamCrc(raw);
		} else {
			println("ABORT: file is neither a connac2 RAM blob nor a ROM patch.");
			return;
		}
		if (regions.isEmpty()) {
			println("ABORT: parsed 0 regions.");
			return;
		}

		// 4. Wipe whatever the raw import created so we control the layout.
		Memory mem = currentProgram.getMemory();
		MemoryBlock[] old = mem.getBlocks();
		for (MemoryBlock b : old) {
			println("removing import block " + b.getName() + " @ " + b.getStart());
			mem.removeBlock(b, monitor);
		}

		// 5. Lay out every region at its load address.
		Region overrideR = null;
		for (Region r : regions) {
			if (r.override) overrideR = r;
		}
		// For RAM, fall back to the first region as the entry. For a patch with
		// no non-INFO section we have no reliable entry, so map only (no seed).
		boolean seedEntry = true;
		if (overrideR == null) {
			overrideR = regions.get(0);
			if (isPatch) seedEntry = false;
		}
		long codeStart = overrideR.vaddr;
		long codeEnd   = overrideR.vaddr + overrideR.len;

		println("");
		println("region map  (load VA  <- file_off  size  flags)");
		println("------------------------------------------------------------");
		for (Region r : regions) {
			if (r.len <= 0) { println("  skip " + r.name + " (len 0)"); continue; }
			try {
				Address a = toAddr(r.vaddr);
				MemoryBlock blk = mem.createInitializedBlock(
						r.name, a,
						new ByteArrayInputStream(raw, r.fileOff, r.len),
						r.len, monitor, false);
				blk.setRead(true);
				blk.setWrite(true);
				blk.setExecute(r.exec);
				println(String.format("  %-14s 0x%08x <- 0x%06x  0x%05x  %s%s%s",
						r.name, r.vaddr, r.fileOff, r.len,
						r.exec ? "X" : "-",
						(r.feature & FW_FEATURE_OVERRIDE_ADDR) != 0 ? " OVERRIDE" : "",
						(r.feature & FW_FEATURE_NON_DL) != 0 ? " NON_DL" : ""));
			} catch (Exception e) {
				println("  !! could not map " + r.name + " @ 0x"
						+ Long.toHexString(r.vaddr) + ": " + e.getMessage());
			}
		}

		// 6. ROM/DRAM stub blocks (uninitialized: no fake bytes) so references
		//    into masked ROM / runtime DRAM resolve instead of thrashing the
		//    decompiler. Each is trimmed to the gaps not already mapped.
		println("");
		println("stub blocks (uninitialized, gap-filled):");
		if (!isPatch) {
			// masked ROM + WM ROM-patch window below the code region
			if (codeStart > 0x00800000L)
				addStub("rom_below", 0x00800000L, codeStart, true);
			// scratch just above the code region (descriptor tables, etc.)
			long ac = (codeEnd + 0xf) & ~0xfL;
			addStub("above_code", ac, ac + 0x52000L, true);
		}
		// runtime DRAM / BSS globals (_DAT_80xxxxxx) and 2nd data window
		addStub("dram_bss", 0x80000000L, 0x80000000L + 0x04000000L, false);
		addStub("dram_84",  0x84000000L, 0x84000000L + 0x01000000L, false);

		// 7. Entry point + seed disassembly (folds in SeedCode.java).
		println("");
		if (seedEntry) {
			seed(codeStart, codeEnd);
		} else {
			println("patch: no entry section identified; mapped only, not seeded.");
		}

		println("");
		println("connac2 loader: done." + (seedEntry
				? " Entry = 0x" + Long.toHexString(codeStart) : " (no entry seeded)")
				+ ". Run Auto-Analyze (or it follows automatically in headless).");
	}

	// =====================================================================
	//  Raw-bytes acquisition
	// =====================================================================
	private byte[] readRawBytes() {
		// (a) explicit path argument
		String[] args = getScriptArgs();
		if (args != null && args.length >= 1 && args[0] != null && !args[0].isEmpty()) {
			byte[] b = tryRead(new File(args[0]));
			if (b != null) { println("source: arg " + args[0]); return b; }
			println("arg path not readable: " + args[0]);
		}
		// (b) the imported file's original path
		String exe = currentProgram.getExecutablePath();
		if (exe != null && !exe.isEmpty()) {
			byte[] b = tryRead(new File(exe));
			if (b != null) { println("source: imported file " + exe); return b; }
		}
		// (c) interactive chooser (GUI only)
		try {
			File f = askFile("Select raw connac2 firmware .bin", "Load");
			byte[] b = tryRead(f);
			if (b != null) { println("source: chosen " + f); return b; }
		} catch (Exception e) {
			println("no file chooser available (headless?): " + e.getMessage());
		}
		return null;
	}

	private byte[] tryRead(File f) {
		try {
			if (f != null && f.isFile())
				return Files.readAllBytes(f.toPath());
		} catch (Exception e) {
			println("read failed: " + e.getMessage());
		}
		return null;
	}

	// =====================================================================
	//  Container detection
	// =====================================================================
	private boolean looksLikeRam(byte[] raw) {
		if (raw.length < TRAILER_SZ + REGION_SZ) return false;
		int trailerOff = raw.length - TRAILER_SZ;
		int n = raw[trailerOff + 2] & 0xff;          // n_region
		if (n < 1 || n > 16) return false;
		int tableStart = trailerOff - n * REGION_SZ;
		if (tableStart < 0) return false;
		long dataOff = 0;
		for (int i = 0; i < n; i++) {
			int rh = tableStart + i * REGION_SZ;
			long len  = le32(raw, rh + 20);
			long addr = le32(raw, rh + 16);
			if (len < 0 || len > raw.length) return false;
			if (dataOff + len > tableStart) return false; // data must not run into the table
			if (addr == 0 && len == 0) return false;
			dataOff += len;
		}
		return true;
	}

	private boolean looksLikePatch(byte[] raw) {
		if (raw.length < PATCH_HDR_SZ + PATCH_SEC_SZ) return false;
		long n = be32(raw, 44);                       // desc.n_region
		if (n < 1 || n > 64) return false;
		if (PATCH_HDR_SZ + n * PATCH_SEC_SZ > raw.length) return false;
		long type0 = be32(raw, PATCH_HDR_SZ);         // section[0].type
		return (type0 & 0xffff) == PATCH_SEC_TYPE_INFO;
	}

	// =====================================================================
	//  Container parsing
	// =====================================================================
	private List<Region> parseRam(byte[] raw) {
		List<Region> out = new ArrayList<>();
		int trailerOff = raw.length - TRAILER_SZ;
		int n = raw[trailerOff + 2] & 0xff;
		int tableStart = trailerOff - n * REGION_SZ;
		println(String.format("  trailer: chip_id=0x%02x eco=0x%02x n_region=%d fmt_ver=%d",
				raw[trailerOff] & 0xff, raw[trailerOff + 1] & 0xff, n, raw[trailerOff + 3] & 0xff));
		println("  fw_ver=\"" + ascii(raw, trailerOff + 7, 10)
				+ "\" build=\"" + ascii(raw, trailerOff + 17, 15) + "\"");
		int dataOff = 0;
		for (int i = 0; i < n; i++) {
			int rh = tableStart + i * REGION_SZ;
			Region r = new Region();
			r.vaddr   = le32(raw, rh + 16);
			r.len     = (int) le32(raw, rh + 20);
			r.feature = raw[rh + 24] & 0xff;
			r.fileOff = dataOff;
			r.override = (r.feature & FW_FEATURE_OVERRIDE_ADDR) != 0;
			r.exec    = r.override || isExecVa(r.vaddr);
			r.name    = String.format("region%d_%s", i, role(r.vaddr));
			if ((r.feature & FW_FEATURE_SET_ENCRYPT) != 0)
				println("  WARNING: region" + i + " has SET_ENCRYPT; bytes may be ciphertext.");
			out.add(r);
			dataOff += r.len;   // matches driver: offset += len for every region
		}
		return out;
	}

	private List<Region> parsePatch(byte[] raw) {
		List<Region> out = new ArrayList<>();
		long n = be32(raw, 44);
		println("  patch: build=\"" + ascii(raw, 0, 16) + "\" platform=\""
				+ ascii(raw, 16, 4) + "\" hw_sw_ver=0x" + Long.toHexString(be32(raw, 20))
				+ " n_region=" + n);
		boolean entryPicked = false;
		for (int i = 0; i < n; i++) {
			int s = PATCH_HDR_SZ + i * PATCH_SEC_SZ;
			int type = (int) (be32(raw, s) & 0xffff); // sec.type (INFO sections are metadata, not the entry)
			Region r = new Region();
			r.fileOff = (int) be32(raw, s + 4);   // sec.offs
			r.vaddr   = be32(raw, s + 12);         // sec.info.addr
			r.len     = (int) be32(raw, s + 16);   // sec.info.len
			r.feature = 0;
			r.exec    = true;                      // patch sections are code/ROM
			r.override = false;
			r.name    = String.format("patch%d_%s", i, role(r.vaddr));
			if (r.fileOff < 0 || (long) r.fileOff + r.len > raw.length) {
				println("  WARNING: patch section " + i + " out of range; skipping.");
				continue;
			}
			// Entry/override is the first non-INFO (code) section, not section[0]
			// (which looksLikePatch requires to be PATCH_SEC_TYPE_INFO metadata).
			if (!entryPicked && type != PATCH_SEC_TYPE_INFO) {
				r.override = true;
				entryPicked = true;
			}
			out.add(r);
		}
		if (!entryPicked)
			println("  note: no non-INFO patch section found; mapping only, no entry seeded.");
		return out;
	}

	private void verifyRamCrc(byte[] raw) {
		CRC32 c = new CRC32();
		c.update(raw, 0, raw.length - 4);
		long calc = c.getValue();
		long stored = le32(raw, raw.length - 4);
		println(String.format("  crc32 trailer=0x%08x computed=0x%08x  %s",
				stored, calc, (calc == stored) ? "OK (plaintext, unsigned)" : "MISMATCH"));
	}

	// =====================================================================
	//  Stub blocks (uninitialized), trimmed to gaps not already mapped
	// =====================================================================
	private void addStub(String name, long start, long end, boolean exec) throws Exception {
		if (end <= start) return;
		// collect occupied [s,e) ranges of existing blocks intersecting [start,end)
		List<long[]> occ = new ArrayList<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			long bs = b.getStart().getOffset();
			long be = bs + b.getSize();
			if (be > start && bs < end) occ.add(new long[]{Math.max(bs, start), Math.min(be, end)});
		}
		occ.sort((x, y) -> Long.compareUnsigned(x[0], y[0]));
		long cursor = start;
		int part = 0;
		for (long[] o : occ) {
			if (Long.compareUnsigned(o[0], cursor) > 0) {
				part += makeUninit(name, part, cursor, o[0], exec);
			}
			if (Long.compareUnsigned(o[1], cursor) > 0) cursor = o[1];
		}
		if (Long.compareUnsigned(cursor, end) < 0)
			part += makeUninit(name, part, cursor, end, exec);
		if (part == 0) println("  " + name + ": fully covered, nothing to add");
	}

	private int makeUninit(String base, int part, long start, long end, boolean exec) throws Exception {
		long size = end - start;
		if (size <= 0) return 0;
		String nm = (part == 0) ? base : (base + "_" + part);
		MemoryBlock b = currentProgram.getMemory()
				.createUninitializedBlock(nm, toAddr(start), size, false);
		b.setRead(true); b.setWrite(true); b.setExecute(exec);
		println(String.format("  %-12s 0x%08x size 0x%x %s", nm, start, size, exec ? "X" : "-"));
		return 1;
	}

	// =====================================================================
	//  Seeding (folds in SeedCode.java): entry + code-pointer literals
	// =====================================================================
	private void seed(long codeStart, long codeEnd) throws Exception {
		Address entry = toAddr(codeStart);
		disassemble(entry);
		createFunction(entry, "fw_entry");
		// A permanent label survives even if analysis turns the 1-instruction
		// override stub (j <real_entry>) into a thunk and renames the function.
		try { createLabel(entry, "fw_entry", false); } catch (Exception e) { /* ok */ }
		currentProgram.getSymbolTable().addExternalEntryPoint(entry);
		println("entry seeded: fw_entry @ 0x" + Long.toHexString(codeStart));

		Memory mem = currentProgram.getMemory();
		TreeSet<Long> targets = new TreeSet<>();
		for (MemoryBlock blk : mem.getBlocks()) {
			if (!blk.isInitialized()) continue;
			int sz = (int) blk.getSize();
			if (sz <= 4) continue;
			byte[] buf = new byte[sz];
			try { mem.getBytes(blk.getStart(), buf); } catch (Exception e) { continue; }
			for (int i = 0; i + 4 <= sz; i += 2) {
				long v = (buf[i] & 0xffL) | ((buf[i + 1] & 0xffL) << 8)
						| ((buf[i + 2] & 0xffL) << 16) | ((buf[i + 3] & 0xffL) << 24);
				if (v >= codeStart && v < codeEnd) targets.add(v);
			}
		}
		println("code-pointer targets: " + targets.size());
		int made = 0;
		for (long t : targets) {
			try {
				Address a = toAddr(t);
				disassemble(a);
				if (createFunction(a, null) != null) made++;
			} catch (Exception e) { /* keep going */ }
		}
		println("functions seeded: " + made);
	}

	// =====================================================================
	//  Little helpers
	// =====================================================================
	private static long le32(byte[] b, int o) {
		return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8)
				| ((b[o + 2] & 0xffL) << 16) | ((b[o + 3] & 0xffL) << 24);
	}

	private static long be32(byte[] b, int o) {
		return ((b[o] & 0xffL) << 24) | ((b[o + 1] & 0xffL) << 16)
				| ((b[o + 2] & 0xffL) << 8) | (b[o + 3] & 0xffL);
	}

	private static String ascii(byte[] b, int o, int n) {
		StringBuilder sb = new StringBuilder();
		for (int i = o; i < o + n && i < b.length; i++) {
			int c = b[i] & 0xff;
			if (c == 0) break;
			sb.append((c >= 32 && c < 127) ? (char) c : '.');
		}
		return sb.toString();
	}

	// VA-range heuristics for connac2 (MT7961 verified; generalizes by range).
	private static boolean isExecVa(long a) {
		return (a >= 0x00400000L && a < 0x00500000L)   // periph/data-text
				|| (a >= 0x00800000L && a < 0x00A00000L) // ROM patch + WM code
				|| (a >= 0xE0000000L);                   // IRAM
	}

	private static String role(long a) {
		if (a >= 0x00800000L && a < 0x00A00000L) return "code";
		if (a >= 0x02000000L && a < 0x02100000L) return "rodata";
		if (a >= 0xE0000000L)                    return "iram";
		if (a >= 0x00400000L && a < 0x00500000L) return "periph";
		return "data";
	}
}
