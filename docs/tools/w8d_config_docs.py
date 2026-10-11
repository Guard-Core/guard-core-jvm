#!/usr/bin/env python3
"""Generate docs/configuration.md for guard-core-jvm.

Joins two sources so every documented row is verified against code and spec:

1. `guard-core/src/main/kotlin/com/guardcore/config/ConfigFieldRegistry.kt`
   (the ported `_security_config_fields.py` table): python field name, Kotlin
   property, type kind, default, bounds, assignment-revalidation flag.
2. The normative field tables in the behavioral spec's 02-config section:
   per-group Type/Default/Semantics text (the "effect" column).

Output: one table per spec group with columns Field (python_name), Kotlin
property, Type, Default, Effect. A registry field with no spec row, or a spec
row with no registry entry, fails the generation (fail-closed, mirroring the
config registry consistency test).

Usage:
    python3 w8d_config_docs.py <path-to-ConfigFieldRegistry.kt> \
        <path-to-spec-02-config.md> <output.md>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FIELD_RE = re.compile(r'FieldMeta\(\s*"([^"]+)",\s*"([^"]+)",\s*Kind\.([A-Z_]+),\s*"([^"]*)"')
GROUP_RE = re.compile(r"^### (.+)$")
H2_RE = re.compile(r"^## (.+)$")
ROW_RE = re.compile(r"^\| `([^`]+)` \|(.*?)\|(.*?)\|(.*?)\|\s*$")


# Registry Kind -> human-readable type (appendix rows only; spec rows carry
# the normative type text).
KIND_LABELS: dict[str, str] = {
    "STR": "str",
    "STR_NULLABLE": "str or none",
    "INT": "int",
    "INT_NULLABLE": "int or none",
    "FLOAT": "float",
    "FLOAT_NULLABLE": "float or none",
    "BOOL": "bool",
    "BOOL_NULLABLE": "bool or none",
    "STR_LIST": "str list",
    "STR_LIST_NULLABLE": "str list or none",
    "STR_SET": "str set",
    "STR_DICT": "str map",
    "STR_DICT_NULLABLE": "str map or none",
    "INT_KEYED_STR_DICT": "int-keyed str map",
    "ENDPOINT_RATE_LIMITS": "per-endpoint rate-limit map",
    "PATH_NULLABLE": "path or none",
    "LEVEL_NULLABLE": "log level or none",
    "LOG_FORMAT": "log format",
    "POLICY_NULLABLE": "policy or none",
    "BEHAVIOR_RULES": "behavior rule list",
    "THREAT_BAN_CONFIG": "threat-ban config",
    "IP_LIST": "str list (IP/CIDR)",
    "IP_LIST_NULLABLE": "str list (IP/CIDR) or none",
    "COUNTRY_SET": "country set",
    "CLOUD_PROVIDERS_NULLABLE": "cloud provider list or none",
    "CALLABLE_NULLABLE": "callable or none",
    "ANY_NULLABLE": "any or none",
    "HANDLER_NULLABLE": "handler or none",
    "CLOUD_IP_STORE_NULLABLE": "cloud IP store or none",
}


def split_entries(lines: list[str]) -> list[str]:
    """Join the multiline/singeline FieldMeta(...) constructor calls."""
    entries: list[str] = []
    current: str | None = None
    for raw in lines:
        s = raw.strip()
        if current is None:
            if s.startswith("FieldMeta("):
                if s.endswith("),"):
                    entries.append(s)
                else:
                    current = s
            continue
        current += " " + s
        if s.endswith("),"):
            entries.append(current)
            current = None
    return entries


def parse_registry(path: Path) -> dict[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    fields: dict[str, dict[str, str]] = {}
    for entry in split_entries(text.splitlines()):
        head = FIELD_RE.search(entry)
        if not head:
            continue
        name, kotlin, kind, default = head.groups()
        bounds: list[str] = []
        for tag, label in (
            ("ge", "ge"),
            ("le", "le"),
            ("gt", "gt"),
            ("geFloat", "ge"),
            ("leFloat", "le"),
        ):
            bound = re.search(rf"\b{tag}\s*=\s*([0-9.]+)", entry)
            if bound:
                bounds.append(f"{label}={bound.group(1)}")
        fields[name] = {
            "kotlin": kotlin,
            "kind": kind,
            "default": default,
            "bounds": ", ".join(bounds),
            "revalidated": "revalidatedOnAssignment = true" in entry,
        }
    return fields


def parse_spec(path: Path) -> list[tuple[str, str, str, str, str]]:
    """Return ordered (group, field, type, default, semantics) tuples from the
    `## Field semantics` section only (other tables describe rule objects,
    bypass names, and validation messages, not SecurityConfig fields)."""
    rows: list[tuple[str, str, str, str, str]] = []
    group = ""
    in_field_semantics = False
    for line in path.read_text(encoding="utf-8").splitlines():
        h2 = H2_RE.match(line.strip())
        if h2:
            in_field_semantics = h2.group(1).strip() == "Field semantics"
            group = ""
            continue
        if not in_field_semantics:
            continue
        heading = GROUP_RE.match(line.strip())
        if heading:
            group = heading.group(1).strip()
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 4 and cells[0].startswith("`"):
                name = cells[0].strip("`")
                # A cell may itself contain a pipe character inside backticks
                # (e.g. "Principal | null"); the semantics column is the
                # remainder of the row.
                semantics = " | ".join(cells[3:])
                rows.append((group, name, cells[1], cells[2], semantics))
            continue
    return rows


# Effect text for registry fields with no row in the spec 02 field tables
# (verified against the reference descriptions in
# guard_core/_security_config_fields.py). A registry field missing here AND
# in spec 02 fails generation, so a new field cannot silently skip docs.
REGISTRY_ONLY_EFFECTS: dict[str, str] = {
    "exempt_ips": (
        "IP addresses or CIDR ranges that skip rate limiting and the "
        "user-agent and cloud-provider checks. Not restrictive: every other "
        "IP is checked as usual. The blacklist, dynamic IP bans, per-route "
        "IP rules and penetration detection still apply to listed IPs."
    ),
    "detection_pattern_validation_cache_path": (
        "Optional file path for a disk-backed pattern-validation cache. When "
        "set, the empirical cost-verdict outcome of pattern-safety "
        "validation is cached keyed by pattern, flags, and engine version, "
        "so a process boot reuses prior certifications instead of re-timing "
        "every custom pattern; the cheap deterministic layers always re-run. "
        "Cache entries from a different engine version are ignored and "
        "overwritten. Leave unset (the default) to keep every validation "
        "fully empirical."
    ),
    "detection_binary_min_run_length": (
        "Minimum length a consecutive printable-character run inside a "
        "binary-dense multipart file-part payload must reach before that run "
        "is handed to the pattern scan. Text uploads and short or "
        "mostly-text payloads never reach the binary-density ratio and keep "
        "their full scan, and whole-body fallback scans are never "
        "island-reduced, so raw-body signature coverage stays intact."
    ),
}


def main() -> int:
    registry_path, spec_path, out_path = (Path(a) for a in sys.argv[1:4])
    registry = parse_registry(registry_path)
    spec_rows = parse_spec(spec_path)

    spec_fields = {name for _, name, *_ in spec_rows}
    missing_in_spec = sorted(set(registry) - spec_fields)
    missing_in_registry = sorted(spec_fields - set(registry))
    unexplained = [name for name in missing_in_spec if name not in REGISTRY_ONLY_EFFECTS]
    if unexplained or missing_in_registry:
        print("FAIL: registry/spec mismatch", file=sys.stderr)
        if unexplained:
            print(
                "  in registry, not in spec (and not in REGISTRY_ONLY_EFFECTS): "
                + ", ".join(unexplained),
                file=sys.stderr,
            )
        if missing_in_registry:
            print("  in spec, not in registry: " + ", ".join(missing_in_registry), file=sys.stderr)
        return 1

    lines: list[str] = [
        "# Configuration",
        "",
        "Every `SecurityConfig` field with its type, default, and effect. The",
        "canonical field names are the snake_case python names (the cross-language",
        "interop surface, spec 02): the Kotlin properties are the camelCase forms,",
        "and adapters bind them idiomatically (Spring relaxed binding maps",
        "`guard.redis-url` to `redisUrl`; Ktor takes the builder or the Kotlin",
        "property names). Types and defaults are normative; a conformant build",
        "with default config behaves as the reference with default config.",
        "",
        "Generated by `docs/tools/w8d_config_docs.py` from",
        "`ConfigFieldRegistry.kt` (the ported reference field table) joined with",
        "the spec 02 field semantics. Re-run it whenever the registry or spec 02",
        "changes; a field that exists in code but not here is a defect.",
        "",
    ]
    current_group: str | None = None
    for group, name, ftype, default, semantics in spec_rows:
        if group != current_group:
            lines += [f"## {group}", "", "| Field | Kotlin property | Type | Default | Effect |", "|---|---|---|---|---|"]
            current_group = group
        meta = registry[name]
        bounds = f" ({meta['bounds']})" if meta["bounds"] else ""
        lines.append(f"| `{name}` | `{meta['kotlin']}` | {ftype}{bounds} | {default} | {semantics} |")

    appendix = [name for name in missing_in_spec if name in REGISTRY_ONLY_EFFECTS]
    if appendix:
        lines += [
            "",
            "## Registry fields beyond the spec 02 tables",
            "",
            "These fields exist in the reference field table and the JVM",
            "registry but have no row in the spec 02 field semantics tables.",
            "Their effect text here is verified against the reference's field",
            "descriptions (`guard_core/_security_config_fields.py`).",
            "",
            "| Field | Kotlin property | Type | Default | Effect |",
            "|---|---|---|---|---|",
        ]
        for name in appendix:
            meta = registry[name]
            bounds = f" ({meta['bounds']})" if meta["bounds"] else ""
            label = KIND_LABELS.get(meta["kind"], meta["kind"])
            lines.append(
                f"| `{name}` | `{meta['kotlin']}` | {label}{bounds} | "
                f"`{meta['default']}` | {REGISTRY_ONLY_EFFECTS[name]} |"
            )
    lines += [
        "",
        "Assignment-time revalidation: the fields flagged in the registry",
        "(list at `ConfigFieldRegistry.kt`, `revalidatedOnAssignment`) re-run",
        "their validators on every mutation after construction, mirroring",
        "`_FIELD_REVALIDATORS` in the reference.",
        "",
    ]
    out_path.write_text("\n".join(lines), encoding="utf-8")
    total = len(spec_rows)
    print(f"wrote {out_path}: {total} fields in {len({g for g, *_ in spec_rows})} groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
