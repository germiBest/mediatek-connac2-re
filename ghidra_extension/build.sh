#!/usr/bin/env bash
# Recompile the SLEIGH .sla and repack the installable extension zip.
# Requires GHIDRA_INSTALL_DIR (default /opt/ghidra).
set -euo pipefail
GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MOD="$HERE/Xtensa-MTK"
DIST="$(dirname "$HERE")/dist"
echo ">> compiling SLEIGH with $GHIDRA/support/sleigh"
( cd "$MOD/data/languages" && "$GHIDRA/support/sleigh" xtensa_mtk_le.slaspec )
mkdir -p "$DIST"
ZIP="$DIST/Xtensa-MTK-ghidra_12.1.zip"
rm -f "$ZIP"
( cd "$HERE" && zip -r -q "$ZIP" Xtensa-MTK \
    -x '*.DS_Store' \
    -x 'Xtensa-MTK/src/*' )

echo ">> built $ZIP"
