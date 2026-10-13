#!/usr/bin/env bash
# Fail-closed 100 percent line-coverage gate (the family standard; the
# guard-core-rs enforce_line_coverage.py analog).
#
# Runs every module's test task, merges ALL exec files via jacococli against
# ALL modules' kotlin classes (per-module reports UNDERCOUNT cross-JVM
# execution: the conformance module exercises facade/engine code from another
# JVM), and fails unless the workspace total AND every module hold 100.0
# percent covered lines. On failure it prints the uncovered-line list per
# class. JaCoCo excludes in the build config are only acceptable for
# genuinely unreachable arms and must carry a written reason.
#
# Usage: scripts/enforce_line_coverage.sh [--merge-only <workdir>]
set -euo pipefail
cd "$(dirname "$0")/.."

JACOCO_VERSION=0.8.15
JACOCO_CLI=${JACOCO_CLI:-/tmp/jacococli-${JACOCO_VERSION}.jar}

# The pinned artifact: sha256 verified before use
# (org.jacoco.cli-0.8.15-nodeps.jar from repo1.maven.org).
EXPECTED_SHA256=d2b74b20b415163c1f53261e7c5ef4445b788327094208ff821e0c2baf9bc8f1

if [ ! -f "$JACOCO_CLI" ]; then
  echo "downloading jacococli ${JACOCO_VERSION} (pinned)"
  curl --fail --silent --show-error --location \
    -o "$JACOCO_CLI" \
    "https://repo1.maven.org/maven2/org/jacoco/org.jacoco.cli/${JACOCO_VERSION}/org.jacoco.cli-${JACOCO_VERSION}-nodeps.jar"
fi
# shasum is macOS-first; fall back to sha256sum on the ubuntu CI image.
ACTUAL_SHA256=$(
  (shasum -a 256 "$JACOCO_CLI" 2>/dev/null || sha256sum "$JACOCO_CLI") | awk '{print $1}'
)
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "jacococli sha256 mismatch: $ACTUAL_SHA256 != $EXPECTED_SHA256" >&2
  exit 1
fi

OUT=${1:-build/coverage-gate}
# MERGE_ONLY=1 skips the test run: the caller already executed the tests and
# only wants the merge + enforcement over the existing exec files.
if [ "${MERGE_ONLY:-0}" != "1" ]; then
  ./gradlew test --no-daemon
fi

mkdir -p "$OUT"

# Only the test task's exec files: the gate measures the unit-test surface and
# must not drift with whatever else left an exec behind (e.g. a local corpus
# run's fullCorpusGate.exec covering pipeline arms the tests do not).
EXEC_FILES=()
for f in */build/jacoco/test.exec; do
  [ -e "$f" ] && EXEC_FILES+=("$f")
done
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
  --name coverage-gate > "$OUT/report.log" 2>&1 || { cat "$OUT/report.log"; exit 1; }

python3 scripts/enforce_line_coverage.py "$OUT/merged.xml"
