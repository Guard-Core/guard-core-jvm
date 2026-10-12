#!/usr/bin/env python3
"""Fail-closed 100 percent line-coverage gate (the family standard).

The house analog of guard-core-rs's scripts/enforce_line_coverage.py. Reads
the merged cross-module JaCoCo XML produced by
scripts/enforce_line_coverage.sh (ALL exec files counted against ALL kotlin
classes, per-module reports UNDERCOUNT because the conformance module
exercises facade/engine code from another JVM), then fails unless:

  - the workspace total is at 100.0 percent covered lines, and
  - every module is at 100.0 percent covered lines.

On failure it prints the uncovered-line ranges per class, per module, so the
fix is directly actionable. A JaCoCo exclusion in the build config is only
acceptable for a genuinely unreachable arm and must carry a written reason
next to the exclude.

Usage: enforce_line_coverage.py <merged.xml> [--skip module ...]
"""
import argparse
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# module name -> the java package prefixes it owns (declared in the settings
# module layout; the engine owns com.guardcore.engine.*, the facade the
# guardcore root surface, conformance the runner harness).
MODULE_PACKAGES = {
    "guard-core-engine": "com/guardcore/engine",
    "guard-core": "com/guardcore/",
    "guard-core-conformance": "com/guardcore/conformance",
}

THRESHOLD = 100.0


def ranges(lines):
    """Collapse a sorted list of ints into inclusive ranges."""
    out = []
    for n in sorted(lines):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in out)


def uncovered_lines(sourcefile):
    missed = []
    for ln in sourcefile.findall("line"):
        if int(ln.get("mi")) > 0 and int(ln.get("ci")) == 0:
            missed.append(int(ln.get("nr")))
    return missed


def package_stats(pkg):
    covered = missed = 0
    for sf in pkg.findall("sourcefile"):
        for ctr in sf.findall("counter"):
            if ctr.get("type") == "LINE":
                covered += int(ctr.get("covered"))
                missed += int(ctr.get("missed"))
    return covered, missed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("merged_xml")
    parser.add_argument("--skip", action="append", default=[])
    args = parser.parse_args()

    root = ET.parse(args.merged_xml).getroot()

    # Workspace totals.
    total_covered = total_missed = 0
    for pkg in root.findall("package"):
        c, m = package_stats(pkg)
        total_covered += c
        total_missed += m

    # Per-module rollups: a package belongs to the LONGEST owned prefix.
    module_covered = defaultdict(int)
    module_missed = defaultdict(int)
    unattributed = defaultdict(int)
    for pkg in root.findall("package"):
        name = pkg.get("name")
        c, m = package_stats(pkg)
        owner = None
        best = -1
        for module, prefix in MODULE_PACKAGES.items():
            if name.startswith(prefix) and len(prefix) > best:
                owner = module
                best = len(prefix)
        if owner is None:
            unattributed[m] += 1
            continue
        module_covered[owner] += c
        module_missed[owner] += m

    pct = lambda c, m: 100.0 * c / max(1, c + m)

    print(
        f"workspace: covered {total_covered}, missed {total_missed}, "
        f"{pct(total_covered, total_missed):.4f}% (threshold {THRESHOLD:.2f}%)"
    )
    for module in sorted(MODULE_PACKAGES):
        c, m = module_covered[module], module_missed[module]
        print(
            f"{module}: covered {c}, missed {m}, "
            f"{pct(c, m):.4f}% (threshold {THRESHOLD:.2f}%)"
        )
    print()

    failures = []
    if pct(total_covered, total_missed) < THRESHOLD:
        failures.append(
            f"workspace line coverage {pct(total_covered, total_missed):.4f}% "
            f"is below {THRESHOLD:.2f}%"
        )
    for module in sorted(MODULE_PACKAGES):
        if module in args.skip:
            continue
        c, m = module_covered[module], module_missed[module]
        if pct(c, m) < THRESHOLD:
            failures.append(
                f"{module} line coverage {pct(c, m):.4f}% is below {THRESHOLD:.2f}%"
            )

    if not failures:
        print("OK: 100 percent line coverage holds across the workspace")
        return 0

    print("FAIL: line-coverage gate")
    for failure in failures:
        print(f"  - {failure}")
    print()
    print("Uncovered lines per class (fix these; excludes need a written reason):")

    # Attribute each package to a module for the report.
    for pkg in root.findall("package"):
        name = pkg.get("name")
        owner = None
        best = -1
        for module, prefix in MODULE_PACKAGES.items():
            if name.startswith(prefix) and len(prefix) > best:
                owner = module
                best = len(prefix)
        if owner in args.skip:
            continue
        cls_by_source = defaultdict(list)
        for g in pkg.findall("class"):
            sf = g.get("sourcefilename")
            if sf:
                cls_by_source[sf].append(g.get("name").split("/")[-1])
        for sf in pkg.findall("sourcefile"):
            missed = uncovered_lines(sf)
            if not missed:
                continue
            classes = ", ".join(cls_by_source.get(sf.get("name"), ["?"]))
            print(f"  [{owner}] {name}/{sf.get('name')} [{classes}]")
            print(f"      lines: {ranges(missed)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
