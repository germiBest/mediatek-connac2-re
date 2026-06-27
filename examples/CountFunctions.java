// Print the total number of functions and any bad instructions in the program.
// Self-contained helper for the examples/ headless walkthrough. Apache-2.0.
//@category MTK.Connac2
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class CountFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int funcs = 0;
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcs++; }

        // A failed decode does NOT become an Instruction object (it stays
        // undefined data); Ghidra records it as an Error bookmark in the
        // "Bad Instruction" category, so count those rather than scanning
        // instruction mnemonics.
        long bad = 0;
        BookmarkManager bms = currentProgram.getBookmarkManager();
        java.util.Iterator<Bookmark> bi = bms.getBookmarksIterator(BookmarkType.ERROR);
        while (bi.hasNext()) {
            if ("Bad Instruction".equals(bi.next().getCategory())) bad++;
        }
        println("METRIC functions_total=" + funcs);
        println("METRIC bad_instructions=" + bad);
    }
}
