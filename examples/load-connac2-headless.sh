#!/usr/bin/env bash
# Headless walkthrough: import a raw MediaTek connac2 Wi-Fi-MCU blob with the
# Xtensa:LE:32:MTK language, run the bundled LoadConnac2Firmware loader, let
# auto-analysis run, and print the function count.
#
# Requires the Xtensa-MTK extension to be INSTALLED (File > Install Extensions,
# or unzip dist/Xtensa-MTK-ghidra_12.1.zip into your Ghidra Extensions dir) so
# that analyzeHeadless can find both the language and the loader script.
#
# Usage:
#   export GHIDRA_INSTALL_DIR=/opt/ghidra
#   ./load-connac2-headless.sh /lib/firmware/mediatek/WIFI_RAM_CODE_MT7961_1.bin
set -euo pipefail

GHIDRA="${GHIDRA_INSTALL_DIR:-}"
FW="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "$GHIDRA" || ! -x "$GHIDRA/support/analyzeHeadless" ]]; then
  echo "Set GHIDRA_INSTALL_DIR to your Ghidra install (got: '${GHIDRA:-unset}')." >&2
  exit 2
fi
if [[ -z "$FW" || ! -f "$FW" ]]; then
  echo "Usage: $0 <path-to-WIFI_RAM_CODE_*.bin>" >&2
  exit 2
fi

PROJ="$(mktemp -d)"
trap 'rm -rf "$PROJ"' EXIT

# Loader is found via the installed extension; CountFunctions ships here in examples/.
"$GHIDRA/support/analyzeHeadless" "$PROJ" connac2 \
  -import "$FW" \
  -loader BinaryLoader -loader-baseAddr 0x0 \
  -processor "Xtensa:LE:32:MTK" \
  -scriptPath "$HERE" \
  -preScript LoadConnac2Firmware.java \
  -postScript CountFunctions.java \
  -deleteProject 2>&1 | \
  grep -E 'METRIC|container:|region map|0x00915000|entry seeded|functions seeded|code-pointer|crc32|Using Language|Import succeeded' || true
