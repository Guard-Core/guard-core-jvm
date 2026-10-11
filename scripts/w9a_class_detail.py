#!/usr/bin/env python3
"""Per-class missed-line enumeration from the merged JaCoCo XML.

Usage: python3 scripts/w9a_class_detail.py <merged.xml> [package-prefix]
Prints per-sourcefile missed-line ranges sorted by missed count.
"""
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict


def ranges(lines):
    """Collapse a sorted list of ints into inclusive ranges."""
    out = []
    for n in sorted(lines):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in out)


def main():
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()
    prefix = sys.argv[2] if len(sys.argv) > 2 else "com/guardcore"
    # package/sourcefile -> missed lines; and sourcefile -> class name mapping
    for pkg in root.findall("package"):
        pname = pkg.get("name")
        if not pname.startswith(prefix):
            continue
        # Map sourcefile -> top-level class names via class entries.
        cls_by_sf = defaultdict(list)
        for g in pkg.findall("class"):
            sfname = g.get("sourcefilename")
            if sfname:
                cls_by_sf[sfname].append(g.get("name"))
        for sf in pkg.findall("sourcefile"):
            name = sf.get("name")
            missed = []
            covered = 0
            for ln in sf.findall("line"):
                mi, ci = int(ln.get("mi")), int(ln.get("ci"))
                if mi > 0 and ci == 0:
                    missed.append(int(ln.get("nr")))
                elif ci > 0:
                    covered += 1
            if not missed:
                continue
            classes = ", ".join(c.split("/")[-1] for c in cls_by_sf.get(name, []))
            print(f"{pname}/{name} [{classes}] missed={len(missed)} covered={covered}")
            print(f"    lines: {ranges(missed)}")


if __name__ == "__main__":
    main()
