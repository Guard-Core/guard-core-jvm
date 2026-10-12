#!/usr/bin/env python3
"""Print uncovered lines (with a context line) for given source-file fragments.

Usage: python3 scripts/w9d_uncovered_context.py <merged.xml> <Fragment> [<Fragment>...]
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    root = ET.parse(sys.argv[1]).getroot()
    fragments = [f.lower() for f in sys.argv[2:]]
    for pkg in root.findall("package"):
        cls_by_source = {}
        for g in pkg.findall("class"):
            sf = g.get("sourcefilename")
            if sf:
                cls_by_source.setdefault(sf, []).append(g.get("name").split("/")[-1])
        for sf in pkg.findall("sourcefile"):
            source = sf.get("name", "")
            if not any(fr in source.lower() for fr in fragments):
                continue
            missed = [
                int(ln.get("nr"))
                for ln in sf.findall("line")
                if int(ln.get("mi")) > 0 and int(ln.get("ci")) == 0
            ]
            if not missed:
                continue
            path = None
            for cand in ROOT.glob("*/src/main/kotlin/**/" + source):
                path = cand
                break
            print(f"== {pkg.get('name')}/{source}")
            if path is None:
                print("   (source not found) lines:", missed)
                continue
            text = path.read_text().splitlines()
            prev = 0
            for n in missed:
                if n - 1 >= len(text):
                    continue
                if prev != n - 1:
                    ctx = text[n - 2].strip()[:90] if n - 2 < len(text) else ""
                    print(f"  ... {ctx}")
                print(f"  {n}: {text[n - 1].strip()[:110]}")
                prev = n
            print()


if __name__ == "__main__":
    main()
