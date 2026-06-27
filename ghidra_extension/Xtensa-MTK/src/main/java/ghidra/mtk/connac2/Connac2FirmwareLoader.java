/* Connac2FirmwareLoader - a real Ghidra Loader for MediaTek connac2 Wi-Fi-MCU
 * firmware blobs (MT7961/MT7921/MT7915-family).
 *
 * Part of the mediatek-connac2-re project.  Licensed Apache-2.0.
 *
 * This is the "advanced" path: File > Import recognises a raw connac2 RAM blob
 * (WIFI_RAM_CODE_*) or ROM patch (WIFI_*_patch_mcu) automatically, selects the
 * "Xtensa:LE:32:MTK" language, and lays out every region at its load address
 * plus ROM/DRAM stub blocks -- no manual base address, no post-import script.
 *
 * NOTE: this Loader is shipped as SOURCE only. The prebuilt
 * dist/Xtensa-MTK-ghidra_12.1.zip does NOT contain a compiled copy (build.sh
 * excludes src/ and runs no javac), so File > Import auto-recognition is active
 * only after you compile this class into the extension via gradle / GhidraDev.
 * The GhidraScript LoadConnac2Firmware.java does the same memory map + entry
 * with zero build steps and is the recommended/tested path.
 *
 * Seeding of disassembly is intentionally left to auto-analysis / the
 * companion script -- a Loader's job is the memory map + entry point.
 *
 * Built against the Ghidra 12.1 Loader API (load(Program, ImporterSettings)).
 */
package ghidra.mtk.connac2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class Connac2FirmwareLoader extends AbstractLibrarySupportLoader {

	private static final String MTK_LANG = "Xtensa:LE:32:MTK";

	// NOTE: the container parsing here is intentionally duplicated with the
	// ghidra_scripts/LoadConnac2Firmware.java script (which must stay
	// self-contained for zip-only installs). Keep the two parsers in sync when
	// the container format changes.
	private static final int TRAILER_SZ = 36;
	private static final int REGION_SZ = 40;
	private static final int PATCH_HDR_SZ = 96;
	private static final int PATCH_SEC_SZ = 64;
	private static final int FW_FEATURE_OVERRIDE_ADDR = 0x20;
	private static final int FW_FEATURE_NON_DL = 0x40;
	private static final int PATCH_SEC_TYPE_INFO = 0x2;

	private static final class Region {
		String name;
		long vaddr;
		int fileOff;
		int len;
		int feature;
		boolean exec;
		boolean override;
	}

	@Override
	public String getName() {
		return "MediaTek connac2 Wi-Fi-MCU firmware (Xtensa-MTK)";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 60; // beat the generic Raw Binary loader for these blobs
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		byte[] raw = readAll(provider);
		if (raw != null && (looksLikeRam(raw) || looksLikePatch(raw))) {
			specs.add(new LoadSpec(this, 0,
					new LanguageCompilerSpecPair(MTK_LANG, "default"), true));
		}
		return specs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws IOException {
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		byte[] raw = readAll(settings.provider());
		if (raw == null) {
			log.appendMsg("connac2: could not read firmware bytes");
			return;
		}

		boolean isPatch = looksLikePatch(raw);
		boolean isRam = looksLikeRam(raw);
		String nm = settings.importName() == null ? "" : settings.importName().toLowerCase();
		if (isPatch && isRam) {
			if (nm.contains("patch")) isRam = false; else isPatch = false;
		}

		List<Region> regions = isPatch ? parsePatch(raw, log) : parseRam(raw, log);
		if (regions.isEmpty()) {
			log.appendMsg("connac2: parsed 0 regions");
			return;
		}

		Region overrideR = null;
		for (Region r : regions) if (r.override) overrideR = r;
		// RAM falls back to the first region as entry; a patch with no non-INFO
		// section has no reliable entry, so map only (don't label fw_entry).
		boolean haveEntry = overrideR != null;
		if (overrideR == null) {
			overrideR = regions.get(0);
			if (!isPatch) haveEntry = true;
		}
		long codeStart = overrideR.vaddr;
		long codeEnd = overrideR.vaddr + overrideR.len;

		// regions at their load addresses
		for (Region r : regions) {
			if (r.len <= 0) continue;
			try {
				Address a = addr(program, r.vaddr);
				MemoryBlockUtils.createInitializedBlock(program, false, r.name, a,
						new ByteArrayInputStream(raw, r.fileOff, r.len), r.len,
						"connac2 region", "Connac2FirmwareLoader",
						true, true, r.exec, log, monitor);
			} catch (Exception e) {
				log.appendMsg("connac2: failed to map " + r.name + ": " + e.getMessage());
			}
		}

		// ROM/DRAM stub blocks (uninitialized) so refs into unmapped memory resolve
		if (!isPatch) {
			if (Long.compareUnsigned(codeStart, 0x00800000L) > 0)
				addStub(program, "rom_below", 0x00800000L, codeStart, true, log);
			long ac = (codeEnd + 0xf) & ~0xfL;
			addStub(program, "above_code", ac, ac + 0x52000L, true, log);
		}
		addStub(program, "dram_bss", 0x80000000L, 0x80000000L + 0x04000000L, false, log);
		addStub(program, "dram_84", 0x84000000L, 0x84000000L + 0x01000000L, false, log);

		// entry point (only when we identified a real one)
		if (haveEntry) {
			try {
				Address ep = addr(program, codeStart);
				program.getSymbolTable().addExternalEntryPoint(ep);
				program.getSymbolTable().createLabel(ep, "fw_entry", SourceType.IMPORTED);
			} catch (Exception e) {
				log.appendMsg("connac2: entry point: " + e.getMessage());
			}
		}
	}

	// ---- helpers --------------------------------------------------------
	private Address addr(Program program, long v) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(v);
	}

	private void addStub(Program program, String name, long start, long end,
			boolean exec, MessageLog log) {
		if (Long.compareUnsigned(end, start) <= 0) return;
		// gap-fill against existing blocks so we never overlap a real region
		List<long[]> occ = new ArrayList<>();
		for (var b : program.getMemory().getBlocks()) {
			long bs = b.getStart().getOffset();
			long be = bs + b.getSize();
			if (Long.compareUnsigned(be, start) > 0 && Long.compareUnsigned(bs, end) < 0)
				occ.add(new long[] { uMax(bs, start), uMin(be, end) });
		}
		occ.sort((x, y) -> Long.compareUnsigned(x[0], y[0]));
		long cursor = start;
		int part = 0;
		for (long[] o : occ) {
			if (Long.compareUnsigned(o[0], cursor) > 0)
				part += mkStub(program, name, part, cursor, o[0], exec, log);
			if (Long.compareUnsigned(o[1], cursor) > 0) cursor = o[1];
		}
		if (Long.compareUnsigned(cursor, end) < 0)
			part += mkStub(program, name, part, cursor, end, exec, log);
	}

	private int mkStub(Program program, String base, int part, long start, long end,
			boolean exec, MessageLog log) {
		long size = end - start;
		if (size <= 0) return 0;
		String name = (part == 0) ? base : base + "_" + part;
		try {
			MemoryBlockUtils.createUninitializedBlock(program, false, name,
					addr(program, start), size, "connac2 stub", "Connac2FirmwareLoader",
					true, true, exec, log);
			return 1;
		} catch (Exception e) {
			log.appendMsg("connac2: stub " + name + ": " + e.getMessage());
			return 0;
		}
	}

	private List<Region> parseRam(byte[] raw, MessageLog log) {
		List<Region> out = new ArrayList<>();
		int trailerOff = raw.length - TRAILER_SZ;
		int n = raw[trailerOff + 2] & 0xff;
		int tableStart = trailerOff - n * REGION_SZ;
		int dataOff = 0;
		for (int i = 0; i < n; i++) {
			int rh = tableStart + i * REGION_SZ;
			Region r = new Region();
			r.vaddr = le32(raw, rh + 16);
			r.len = (int) le32(raw, rh + 20);
			r.feature = raw[rh + 24] & 0xff;
			r.fileOff = dataOff;
			r.override = (r.feature & FW_FEATURE_OVERRIDE_ADDR) != 0;
			r.exec = r.override || isExecVa(r.vaddr);
			r.name = String.format("region%d_%s", i, role(r.vaddr));
			out.add(r);
			dataOff += r.len;
		}
		log.appendMsg("connac2: RAM firmware, " + n + " regions");
		return out;
	}

	private List<Region> parsePatch(byte[] raw, MessageLog log) {
		List<Region> out = new ArrayList<>();
		long n = be32(raw, 44);
		boolean entryPicked = false;
		for (int i = 0; i < n; i++) {
			int s = PATCH_HDR_SZ + i * PATCH_SEC_SZ;
			int type = (int) (be32(raw, s) & 0xffff); // sec.type; INFO is metadata, not the entry
			Region r = new Region();
			r.fileOff = (int) be32(raw, s + 4);
			r.vaddr = be32(raw, s + 12);
			r.len = (int) be32(raw, s + 16);
			r.exec = true;
			r.override = false;
			r.name = String.format("patch%d_%s", i, role(r.vaddr));
			if (r.fileOff < 0 || (long) r.fileOff + r.len > raw.length) continue;
			// Entry is the first non-INFO (code) section, not section[0] (which
			// looksLikePatch requires to be PATCH_SEC_TYPE_INFO metadata).
			if (!entryPicked && type != PATCH_SEC_TYPE_INFO) {
				r.override = true;
				entryPicked = true;
			}
			out.add(r);
		}
		log.appendMsg("connac2: ROM patch, " + n + " sections"
				+ (entryPicked ? "" : " (no non-INFO entry section)"));
		return out;
	}

	private boolean looksLikeRam(byte[] raw) {
		if (raw.length < TRAILER_SZ + REGION_SZ) return false;
		int trailerOff = raw.length - TRAILER_SZ;
		int n = raw[trailerOff + 2] & 0xff;
		if (n < 1 || n > 16) return false;
		int tableStart = trailerOff - n * REGION_SZ;
		if (tableStart < 0) return false;
		long dataOff = 0;
		for (int i = 0; i < n; i++) {
			int rh = tableStart + i * REGION_SZ;
			long len = le32(raw, rh + 20);
			long a = le32(raw, rh + 16);
			if (len < 0 || len > raw.length) return false;
			if (dataOff + len > tableStart) return false;
			if (a == 0 && len == 0) return false;
			dataOff += len;
		}
		return true;
	}

	private boolean looksLikePatch(byte[] raw) {
		if (raw.length < PATCH_HDR_SZ + PATCH_SEC_SZ) return false;
		long n = be32(raw, 44);
		if (n < 1 || n > 64) return false;
		if (PATCH_HDR_SZ + n * PATCH_SEC_SZ > raw.length) return false;
		return (be32(raw, PATCH_HDR_SZ) & 0xffff) == PATCH_SEC_TYPE_INFO;
	}

	private static byte[] readAll(ByteProvider p) {
		try {
			long len = p.length();
			if (len <= 0 || len > Integer.MAX_VALUE) return null;
			return p.readBytes(0, len);
		} catch (IOException e) {
			return null;
		}
	}

	private static long le32(byte[] b, int o) {
		return (b[o] & 0xffL) | ((b[o + 1] & 0xffL) << 8)
				| ((b[o + 2] & 0xffL) << 16) | ((b[o + 3] & 0xffL) << 24);
	}

	private static long be32(byte[] b, int o) {
		return ((b[o] & 0xffL) << 24) | ((b[o + 1] & 0xffL) << 16)
				| ((b[o + 2] & 0xffL) << 8) | (b[o + 3] & 0xffL);
	}

	private static long uMax(long a, long b) { return Long.compareUnsigned(a, b) >= 0 ? a : b; }
	private static long uMin(long a, long b) { return Long.compareUnsigned(a, b) <= 0 ? a : b; }

	private static boolean isExecVa(long a) {
		return (Long.compareUnsigned(a, 0x00400000L) >= 0 && Long.compareUnsigned(a, 0x00500000L) < 0)
				|| (Long.compareUnsigned(a, 0x00800000L) >= 0 && Long.compareUnsigned(a, 0x00A00000L) < 0)
				|| Long.compareUnsigned(a, 0xE0000000L) >= 0;
	}

	private static String role(long a) {
		if (Long.compareUnsigned(a, 0x00800000L) >= 0 && Long.compareUnsigned(a, 0x00A00000L) < 0) return "code";
		if (Long.compareUnsigned(a, 0x02000000L) >= 0 && Long.compareUnsigned(a, 0x02100000L) < 0) return "rodata";
		if (Long.compareUnsigned(a, 0xE0000000L) >= 0) return "iram";
		if (Long.compareUnsigned(a, 0x00400000L) >= 0 && Long.compareUnsigned(a, 0x00500000L) < 0) return "periph";
		return "data";
	}
}
