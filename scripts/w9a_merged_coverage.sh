#!/usr/bin/env bash
# W9a merged cross-module JaCoCo measurement (the W8d method):
# ALL exec files from ALL modules counted against ALL kotlin classes,
# because the conformance module exercises facade/engine code from another
# JVM and per-module reports UNDERCOUNT.
#
# Usage: scripts/w9a_merged_coverage.sh [module-filter]
#   module-filter: optional substring (e.g. guard-core) to restrict the
#   package listing to matching package names. Always merges everything.
set -euo pipefail
cd "$(dirname "$0")/.."

JACOCO_CLI=${JACOCO_CLI:-/tmp/jacococli-0.8.15.jar}
OUT=${1:-build/w9a-merged}
mkdir -p "$OUT"

# Collect exec files (test.exec per module).
EXEC_FILES=()
for f in */build/jacoco/*.exec; do
  [ -e "$f" ] && EXEC_FILES+=("$f")
done

# Collect kotlin class dirs.
CLASS_DIRS=()
for d in */build/classes/kotlin/main; do
  [ -d "$d" ] && CLASS_DIRS+=("$d")
done

echo "exec files: ${EXEC_FILES[*]}"
echo "class dirs: ${CLASS_DIRS[*]}"

java -jar "$JACOCO_CLI" report "${EXEC_FILES[@]}" \
  ${CLASS_DIRS[@]/#/--classfiles } \
  --xml "$OUT/merged.xml" \
  --html "$OUT/html" \
  --name merged-w9a > "$OUT/report.log" 2>&1 || { cat "$OUT/report.log"; exit 1; }

python3 - "$OUT/merged.xml" "${2:-}" <<'PY'
import sys
import xml.etree.ElementTree as ET

tree = ET.parse(sys.argv[1])
root = tree.getroot()
filt = sys.argv[2] if len(sys.argv) > 2 else ""

pkgs = {}
total_m = total_c = 0
for p in root.findall("package"):
    name = p.get("name")
    src_m = src_c = 0
    for c in p.findall("sourcefile"):
        for ctr in c.findall("counter"):
            if ctr.get("type") == "LINE":
                src_m += int(ctr.get("missed"))
                src_c += int(ctr.get("covered"))
    pkgs[name] = (src_m, src_c)
    total_m += src_m
    total_c += src_c

print(f"TOTAL: lines covered {total_c}, missed {total_m}, "
      f"total {total_m + total_c}, "
      f"coverage {100.0 * total_c / max(1, total_m + total_c):.2f}%")
print()
rows = sorted(pkgs.items(), key=lambda kv: -kv[1][0])
print(f"{'package':<55} {'missed':>7} {'covered':>8} {'pct':>7}")
for name, (m, c) in rows:
    if filt and filt not in name:
        continue
    pct = 100.0 * c / max(1, m + c)
    print(f"{name:<55} {m:>7} {c:>8} {pct:>6.2f}%")
PY
