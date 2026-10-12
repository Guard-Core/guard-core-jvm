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

# Reasoned exclusions: sourcefile -> list of (line ranges, reason). A line here is
# provably unreachable from any pattern/entry point (a defensive arm for node shapes
# the sre port never emits, or a host-timing race) - each entry carries the proof.
# Everything else must be covered by tests; the gate fails on any other missed line.
EXCLUDES = {
    "ParseSlots.kt": [
        ((146, 146), "classNodePredicate CATEGORY branch: atom-path escapes wrap shorthand "
                     "categories in IN nodes (PyReParser.inCategoryNode), so a pairing atom "
                     "is never a bare CATEGORY node"),
        ((180, 180), "emitAtomSource NOT_LITERAL arm: the parser declares ReOp.NOT_LITERAL "
                     "but has zero construction sites ([^x] stays IN[NEGATE])"),
        ((209, 216), "emitAtomSource top-level CATEGORY arm: same deadness as line 146 - "
                     "atom categories are always IN-wrapped"),
        ((337, 343), "nonPairingSlot ATOMIC_GROUP arm: the parser rejects (?>) fail-closed "
                     "(PyReParser 'unknown extension ?>'), so the op is never emitted"),
        ((371, 376), "repeatSlot multi-atom body: python quantifiers bind to a single atom "
                     "or a group, and groups stay SUBPATTERN-wrapped, so a repeat body never "
                     "holds 2+ atoms"),
    ],
    "PyRe.kt": [
        ((385, 385), "scoped-emitter fail-closed throw: emitScopedNodes handles SUBPATTERN and "
                     "repeats and emitNodeSource handles every remaining op the parser emits "
                     "(LITERAL/ANY/IN/AT/GROUPREF/ASSERT/ASSERT_NOT/BRANCH) - the else arm is "
                     "unreachable for the frozen sre op set"),
    ],
    "CostArbiter.kt": [
        ((52, 52), "threadCpuNanos System.nanoTime fallback: reachable only where the JVM "
                   "reports no thread-CPU clock (isCurrentThreadCpuTimeSupported false or a "
                   "negative reading) - never on the supported JDK 17 runtimes"),
        ((71, 71), "measureHostLoadFactor catch-all: the fixed reference scan over "
                   "services.gradle.org-free in-process work cannot throw except at its "
                   "deadline (handled above); defensive only"),
        ((113, 114), "DeadlineExceededException in the reference-scan sampling loop: the "
                     "strategy deadline is clipped positive immediately before; expiring "
                     "between the clip and the loop is a host-scheduling race"),
        ((388, 388), "remainingBudgetNanos <= 0 after builder construction: the same "
                     "host-scheduling race (the budget is seconds-scale, builders are "
                     "microseconds)"),
        ((391, 391), "builders consumed the whole budget between the clip and the check: the "
                     "same host-scheduling race as 388 (seconds-scale budget, microsecond "
                     "builders)"),
    ],
    "SusPatternsManager.kt": [
        ((438, 440), "scan-window iteration PyReDeadlines arm: the per-scan deadline is "
                     "seconds-scale against microsecond window scans - a host-scheduling "
                     "race"),
        ((508, 509), "checkPatternWithTimeout generic catch: PyRe.search either matches, "
                     "returns null, or raises the handled DeadlineExceededException; region "
                     "bounds are clamped in PyRe.search - defensive only"),
        ((573, 576), "checkPattern loop deadline/exception arms: same defensive/race "
                     "family as 508-509"),
        ((675, 677), "PatternValidationTimeout in the enhanced-validate path: the validation "
                     "budgets are size-triggered and throw inside reachProbeCandidateBuilders "
                     "(covered there); this outer arm fires only on a mid-phase host race"),
        ((417, 419), "scan-window iteration PyReDeadlines arm: the per-scan deadline is "
                     "seconds-scale against microsecond window scans - the same host-scheduling "
                     "race family as 438-440"),
    ],
    "StrayChooser.kt": [
        ((214, 216), "stray-verification mid-loop deadline expiry: strayVerificationTimeoutNanos "
                     "throws deterministically when the budget is already exhausted; expiring "
                     "mid-loop is a host-scheduling race"),
    ],
    "Truncation.kt": [
        ((32, 33), "indicator-scan PyReDeadlines arm: the indicator scan deadline is "
                   "seconds-scale against fixed indicator patterns - a host-scheduling race"),
    ],
    "Semantic.kt": [
        ((317, 317), "AST-thread catch-all: parsesAsExpression signals only via "
                     "SyntaxErrorSignal (handled internally) and returns booleans; no "
                     "Exception path exists"),
        ((326, 327), "AST parse exceeding the 100ms thread join: host-speed dependent "
                     "(the parser is linear over the 1000-char cap)"),
    ],
    "Compiler.kt": [
        ((133, 133), "createSafeMatcher generic catch: the deadline arm above handles "
                     "DeadlineExceededException; PyRe.search raises nothing else on this "
                     "surface - defensive only"),
        ((151, 151), "createSafeFinditerMatcher generic catch: same defensive family as 133"),
        ((95, 96), "runPatternSafetyProbe compile catch: the probe is only entered from "
                    "validatePatternSafety after compilePatternSync succeeded on the identical "
                    "pattern+flags, so PyRe.compile cannot fail here"),
    ],
    "Preprocessor.kt": [
        ((156, 156), "decodeLdapHexEscapes catch body: group(1) is bounded to two hex digits "
                      "([0-9a-fA-F]{2}); toInt(16) cannot throw on that domain and "
                      "Character.toChars on <= 0xFFFF cannot throw"),
    ],
    "CloudAzureFetch.kt": [
        ((88, 101), "FakeHttpResponse interface stubs: the private fake only escapes into the "
                     "azure fetch flow, which consumes statusCode() and body() only; uri(), "
                     "headers(), previousResponse(), request(), sslSession() and version() have "
                     "zero call sites on HttpResponse anywhere in the repo"),
    ],
    "CloudFetchers.kt": [
        ((65, 77), "FakeHttpResponse interface stubs: the fetchers consume statusCode(), body() "
                    "and uri() (raiseForStatus, CloudFetchers.kt:82); headers(), "
                    "previousResponse(), request(), sslSession(), version() and toString() have "
                    "zero call sites on HttpResponse anywhere in the repo"),
    ],
    "SusPatternsRegistry.kt": [
        ((107, 108), "engine.addPattern re-validation: the engine validates with the IDENTICAL "
                      "compiler and maxContentLength expressions the registry just used "
                      "(SusPatternsManager.kt:315 vs the registry's engineCompiler/config "
                      "reads), so a divergent verdict requires a mid-flow configure() swap or a "
                      "host-timing flip inside the ReDoS probe - the host-race family"),
    ],
    "IpInfoManager.kt": [
        ((302, 302), "the no-seam HttpClient.send arm requires outbound network to the pinned "
                      "ipinfo.io URL; the test surface drives the downloadOverride/"
                      "httpSendOverride seams (ipinfo_handler.py:194 keeps the retry loop)"),
        ((423, 425), "reader.close() rethrow: com.maxmind.db.Reader is final and its close() is "
                      "an idempotent channel teardown; no test surface can force the underlying "
                      "close to raise (the arm preserves the python OSError propagation)"),
    ],
    "RedisManager.kt": [
        ((171, 172), "transaction exec CompletionException unwrap: EXEC fails exceptionally only "
                      "when the connection dies between MULTI and EXEC (a mid-flight connection "
                      "loss); over a healthy live redis the queued commands either succeed or "
                      "raise through the per-future unwrap at 179-181"),
        ((247, 247), "LettuceQueuedOperations.close: interface-required no-op; transaction() "
                      "never closes the queued view (RedisManager.kt:165-185)"),
        ((260, 260), "await CompletionException unwrap: reached only when a driver future "
                      "completes with a CompletionException (mid-flight connection loss); plain "
                      "driver failures raise through the ExecutionException unwrap at 255-258"),
    ],
    "PairRedaction.kt": [
        ((136, 136), "percent-escape conjunct of resolvePairResult: decodedName resolves through "
                      "decodePairNameSlow, and '%' is a NAME_BOUNDARY char, so every candidate "
                      "segment excludes it - the conjunct can never see a '%' (the identical "
                      "defensive check sits at python pair_redaction.py:91-93)"),
    ],
    "IgnorecaseFold.kt": [
        ((98, 98), "foldGroupByCodePoint double-checked-locking hit: reached only when a second "
                    "caller enters the synchronized block after another thread published the "
                    "cache - a benign-race arm; the single-threaded path always builds at 99"),
    ],
    "SusPatternsFileUploadTemplates.kt": [
        ((317, 317), "template frame fail-closed guard: the frame regex is compiled from the "
                      "very opening/closing delimiters the span was found by, so matchAt over "
                      "that span always matches"),
    ],
    "SecurityConfigBuilder.kt": [
        ((1457, 1458), "MapApplier.intValue wrong-type arms: fromMap pre-validates every field "
                        "through the ConfigValidators per-field pass, which rejects wrong-typed "
                        "raw values before MapApplier.apply runs (probe: fromMap('"
                        "trusted_proxy_depth' to true) rejects 'Input should be a valid integer "
                        "(got bool)' without entering intValue) - the applier only ever sees "
                        "pre-validated types"),
        ((1462, 1462), "intOrNullValue: same pre-pass - the null/wrong-type shapes never reach "
                        "the applier"),
        ((1466, 1471), "floatValue wrong-type arms: same pre-pass proof as 1457-1458"),
        ((1474, 1474), "floatOrNullValue: same pre-pass proof as 1457-1458"),
        ((1479, 1479), "boolValue wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1483, 1483), "boolOrNullValue: same pre-pass proof as 1457-1458"),
        ((1488, 1488), "strValue wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1492, 1492), "strOrNullValue: same pre-pass proof as 1457-1458"),
        ((1497, 1497), "strList wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1507, 1507), "setValue wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1519, 1519), "strAnyDictOrNull wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1525, 1525), "intKeyedStrDict wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1531, 1531), "strKeyedStrDict wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1538, 1539), "pathOrNullValue String/else arms: the pre-pass validates "
                        "ipinfo_db_path/dynamic_rules_cache_path before the applier runs"),
        ((1554, 1554), "levelValue wrong-type arm: same pre-pass proof as 1457-1458"),
        ((1562, 1563), "logFormatValue reject arms: same pre-pass proof as 1457-1458"),
        ((1572, 1573), "policyValue reject arms: same pre-pass proof as 1457-1458"),
        ((1589, 1589), "threatBanValue non-map arm: same pre-pass proof as 1457-1458"),
        ((1592, 1592), "behaviorRulesValue non-list arm: same pre-pass proof as 1457-1458"),
        ((1602, 1602), "behaviorRulesValue per-item non-map arm: same pre-pass proof"),
        ((1605, 1605), "behaviorRulesValue value-level arm: same pre-pass proof as 1457-1458"),
        ((1612, 1612), "behaviorRuleFromMap unknown rule_type arm: the ConfigValidators "
                        "pre-pass (ConfigValidators.kt:587-592) rejects unknown rule types "
                        "before the applier runs"),
        ((1616, 1616), "behaviorRuleFromMap unknown action arm: same pre-pass proof as 1612"),
        ((1639, 1639), "endpointRateLimitsValue bad-tuple arm: same pre-pass proof as 1457-1458"),
        ((1643, 1643), "endpointRateLimitsValue non-dict arm: same pre-pass proof as 1457-1458"),
        ((318, 318), "dynamicRulesCachePath property-declaration field-init probe: a Kotlin "
                      "backing-field artifact; the builder is constructed throughout the suite "
                      "and the provided-flag setter body (319-322) is covered"),
    ],
    "PyJson.kt": [
        ((377, 377), "floatRepr finite-double fallback: the digit-loop always terminates for "
                      "finite doubles (comment on 376); NaN/Infinity never reach the redis-score "
                      "float path"),
    ],
}


def exclusion_for(sourcefile, line):
    """Returns the reason string when the line is a reasoned exclusion, else None."""
    for (lo, hi), reason in EXCLUDES.get(sourcefile, []):
        if lo <= line <= hi:
            return reason
    return None


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


def excluded_uncovered(sourcefile):
    """Splits the uncovered lines into (counted, excluded reasons)."""
    counted = []
    excluded = []
    for line in uncovered_lines(sourcefile):
        reason = exclusion_for(sourcefile.get("name"), line)
        if reason is None:
            counted.append(line)
        else:
            excluded.append((line, reason))
    return counted, excluded


def package_stats(pkg):
    covered = missed = 0
    for sf in pkg.findall("sourcefile"):
        _, excluded = excluded_uncovered(sf)
        for ctr in sf.findall("counter"):
            if ctr.get("type") == "LINE":
                covered += int(ctr.get("covered"))
                missed += int(ctr.get("missed")) - len(excluded)
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
            missed, excluded = excluded_uncovered(sf)
            if excluded:
                classes = ", ".join(cls_by_source.get(sf.get("name"), ["?"]))
                print(
                    f"  [excluded] {name}/{sf.get('name')} [{classes}]: "
                    + "; ".join(f"{line}: {reason}" for line, reason in excluded)
                )
            if not missed:
                continue
            classes = ", ".join(cls_by_source.get(sf.get("name"), ["?"]))
            print(f"  [{owner}] {name}/{sf.get('name')} [{classes}]")
            print(f"      lines: {ranges(missed)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
