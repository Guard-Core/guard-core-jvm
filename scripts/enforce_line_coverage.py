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
        ((146, 146), "classNodePredicate CATEGORY branch: atom-path escapes wrap "
                     "shorthand categories in IN nodes (PyReParser.inCategoryNode), so a "
                     "pairing atom is never a bare CATEGORY node"),
        ((180, 180), "emitAtomSource NOT_LITERAL arm: the parser declares "
                     "ReOp.NOT_LITERAL but has zero construction sites ([^x] stays "
                     "IN[NEGATE])"),
        ((209, 216), "emitAtomSource top-level CATEGORY arm: same deadness as line 146 - "
                     "atom categories are always IN-wrapped"),
        ((337, 343), "nonPairingSlot ATOMIC_GROUP arm: the parser rejects (?>) fail- "
                     "closed (PyReParser 'unknown extension ?>'), so the op is never "
                     "emitted"),
        ((371, 376), "repeatSlot multi-atom body: python quantifiers bind to a single "
                     "atom or a group, and groups stay SUBPATTERN-wrapped, so a repeat "
                     "body never holds 2+ atoms"),
    ],
    "PyRe.kt": [
        ((385, 385), "scoped-emitter fail-closed throw: emitScopedNodes handles "
                     "SUBPATTERN and repeats and emitNodeSource handles every remaining "
                     "op the parser emits "
                     "(LITERAL/ANY/IN/AT/GROUPREF/ASSERT/ASSERT_NOT/BRANCH) - the else "
                     "arm is unreachable for the frozen sre op set"),
    ],
    "CostArbiter.kt": [
        ((52, 52), "threadCpuNanos System.nanoTime fallback: reachable only where the "
                   "JVM reports no thread-CPU clock (isCurrentThreadCpuTimeSupported "
                   "false or a negative reading) - never on the supported JDK 17 "
                   "runtimes"),
        ((71, 71), "measureHostLoadFactor catch-all: the fixed reference scan over "
                   "services.gradle.org-free in-process work cannot throw except at "
                   "its deadline (handled above); defensive only"),
        ((113, 114), "DeadlineExceededException in the reference-scan sampling loop: the "
                     "strategy deadline is clipped positive immediately before; expiring "
                     "between the clip and the loop is a host-scheduling race"),
        ((388, 388), "remainingBudgetNanos <= 0 after builder construction: the same "
                     "host-scheduling race (the budget is seconds-scale, builders are "
                     "microseconds)"),
        ((391, 391), "builders consumed the whole budget between the clip and the check: "
                     "the same host-scheduling race as 388 (seconds-scale budget, "
                     "microsecond builders)"),
    ],
    "SusPatternsManager.kt": [
        ((437, 439), "scan-window iteration PyReDeadlines arm: the per-scan deadline is "
                     "seconds-scale against microsecond window scans - a host-scheduling "
                     "race"),
        ((507, 508), "checkPatternWithTimeout generic catch: PyRe.search either matches, "
                     "returns null, or raises the handled DeadlineExceededException; "
                     "region bounds are clamped in PyRe.search - defensive only"),
        ((572, 575), "checkPattern loop deadline/exception arms: same defensive/race "
                     "family as 508-509"),
        ((674, 676), "PatternValidationTimeout in the enhanced-validate path: the "
                     "validation budgets are size-triggered and throw inside "
                     "reachProbeCandidateBuilders (covered there); this outer arm fires "
                     "only on a mid-phase host race"),
        ((416, 418), "scan-window iteration PyReDeadlines arm: the per-scan deadline is "
                     "seconds-scale against microsecond window scans - the same host- "
                     "scheduling race family as 438-440"),
    ],
    "StrayChooser.kt": [
        ((214, 216), "stray-verification mid-loop deadline expiry: "
                     "strayVerificationTimeoutNanos throws deterministically when the "
                     "budget is already exhausted; expiring mid-loop is a host- "
                     "scheduling race"),
    ],
    "Truncation.kt": [
        ((32, 33), "indicator-scan PyReDeadlines arm: the indicator scan deadline is "
                   "seconds-scale against fixed indicator patterns - a host-scheduling "
                   "race"),
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
        ((151, 151), "createSafeFinditerMatcher generic catch: same defensive family as "
                     "133"),
        ((95, 96), "runPatternSafetyProbe compile catch: the probe is only entered "
                   "from validatePatternSafety after compilePatternSync succeeded on "
                   "the identical pattern+flags, so PyRe.compile cannot fail here"),
    ],
    "Preprocessor.kt": [
        ((156, 156), "decodeLdapHexEscapes catch body: group(1) is bounded to two hex "
                     "digits ([0-9a-fA-F]{2}); toInt(16) cannot throw on that domain and "
                     "Character.toChars on <= 0xFFFF cannot throw"),
    ],
    "CloudAzureFetch.kt": [
        ((88, 101), "FakeHttpResponse interface stubs: the private fake only escapes "
                    "into the azure fetch flow, which consumes statusCode() and body() "
                    "only; uri(), headers(), previousResponse(), request(), "
                    "sslSession() and version() have zero call sites on HttpResponse "
                    "anywhere in the repo"),
        ((75, 75), "the no-seam httpGet arm requires outbound network to "
                   "microsoft.com; the test surface drives the httpGetOverride seam "
                   "(the same family as the excluded IpInfoManager 302)"),
        ((298, 298), "fetchAzureIpRanges page-timeout arm: pageTimeout <= 0 requires a "
                     "full AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS host stall between the two "
                     "adjacent monotonic() reads - a host-scheduling race"),
        ((88, 101), "FakeHttpResponse interface stubs: the private fake only escapes "
                    "into the azure fetch flow, which consumes statusCode() and body() "
                    "only; uri(), headers(), previousResponse(), request(), "
                    "sslSession() and version() have zero call sites on HttpResponse "
                    "anywhere in the repo"),
    ],
    "CloudFetchers.kt": [
        ((65, 77), "FakeHttpResponse interface stubs: the fetchers consume "
                   "statusCode(), body() and uri() (raiseForStatus, "
                   "CloudFetchers.kt:82); headers(), previousResponse(), request(), "
                   "sslSession(), version() and toString() have zero call sites on "
                   "HttpResponse anywhere in the repo"),
    ],
    "SusPatternsRegistry.kt": [
        ((107, 108), "engine.addPattern re-validation: the engine validates with the "
                     "IDENTICAL compiler and maxContentLength expressions the registry "
                     "just used (SusPatternsManager.kt:315 vs the registry's "
                     "engineCompiler/config reads), so a divergent verdict requires a "
                     "mid-flow configure() swap or a host-timing flip inside the ReDoS "
                     "probe - the host-race family"),
        ((305, 305), "patternInfo unknown arm: sendThreatEvent only runs when "
                     "result.isThreat, and isThreat = regexAnomaly(regexThreats) >= "
                     "threshold OR semanticThreats.isNotEmpty() "
                     "(SusPatternsManager.kt:1028-1030) - either way at least one of the "
                     "two complementary filtered lists is non-empty, so the else arm "
                     "cannot fire"),
    ],
    "IpInfoManager.kt": [
        ((285, 285), "downloadDatabase declaration probe: JaCoCo maps the coroutine state "
                      "machine's resume labels to the declaration line; the entry probe sits "
                      "in the unmapped prologue and the resume labels fired across the "
                      "override, suspending-retry, and zero-retry drives without covering it "
                      "- the line has no coverable probe (the same compiler-artifact family "
                      "as the excluded PyJson 46 accessor probes)"),
        ((302, 302), "the no-seam HttpClient.send arm requires outbound network to the "
                     "pinned ipinfo.io URL; the test surface drives the "
                     "downloadOverride/httpSendOverride seams (ipinfo_handler.py:194 "
                     "keeps the retry loop)"),
        ((423, 425), "reader.close() rethrow: com.maxmind.db.Reader is final and its "
                     "close() is an idempotent channel teardown; no test surface can "
                     "force the underlying close to raise (the arm preserves the python "
                     "OSError propagation)"),
        ((97, 102), "getInstance synchronized again-branch: the double-checked lock re- "
                    "reads instance inside synchronized(this) after the outer fast path "
                    "already saw null; between the two reads a second creator thread "
                    "would have to win the race - a benign-race arm no deterministic "
                    "single-threaded test can reach"),
        ((302, 302), "the no-seam HttpClient.send arm requires outbound network to the "
                     "pinned ipinfo.io URL; the test surface drives the "
                     "downloadOverride/httpSendOverride seams (ipinfo_handler.py:194 "
                     "keeps the retry loop)"),
        ((423, 425), "reader.close() rethrow: com.maxmind.db.Reader is final and its "
                     "close() is an idempotent channel teardown; no test surface can "
                     "force the underlying close to raise (the arm preserves the python "
                     "OSError propagation)"),
    ],
    "RedisManager.kt": [
        ((171, 172), "transaction exec CompletionException unwrap: EXEC fails "
                     "exceptionally only when the connection dies between MULTI and EXEC "
                     "(a mid-flight connection loss); over a healthy live redis the "
                     "queued commands either succeed or raise through the per-future "
                     "unwrap at 179-181"),
        ((247, 247), "LettuceQueuedOperations.close: interface-required no-op; "
                     "transaction() never closes the queued view "
                     "(RedisManager.kt:165-185)"),
        ((260, 260), "await CompletionException unwrap: reached only when a driver "
                     "future completes with a CompletionException (mid-flight connection "
                     "loss); plain driver failures raise through the ExecutionException "
                     "unwrap at 255-258"),
        ((171, 172), "transaction exec CompletionException unwrap: EXEC fails "
                     "exceptionally only when the connection dies between MULTI and EXEC "
                     "(a mid-flight connection loss); over a healthy live redis the "
                     "queued commands either succeed or raise through the per-future "
                     "unwrap at 179-181"),
        ((179, 180), "queued-future CompletionException unwrap: "
                     "java.util.concurrent.Future.get() documentedly wraps completion "
                     "failures in ExecutionException (handled at 181-182) or throws "
                     "InterruptedException/CancellationException - CompletionException "
                     "is a join() outcome, not a get() outcome, so the arm is a "
                     "defensive wrap that no driver future can take"),
        ((247, 247), "LettuceQueuedOperations.close: interface-required no-op; "
                     "transaction() never closes the queued view "
                     "(RedisManager.kt:165-185)"),
        ((260, 260), "await CompletionException unwrap: reached only when a driver "
                     "future completes with a CompletionException (mid-flight connection "
                     "loss); plain driver failures raise through the ExecutionException "
                     "unwrap at 255-258"),
        ((351, 353), "getInstance synchronized again-branch: the same double-checked- "
                     "locking benign-race family as the excluded IpInfoManager 97-102 - "
                     "a second creator thread must win the race between the outer read "
                     "and the synchronized re-read"),
        ((736, 736), "unparseableRedisUrl default-arg synthetic: the only default- "
                     "omitting call site is the urlsplit catch at 750-751 (the covered "
                     "764 call passes the scheme explicitly), and 750-751 is dead below "
                     "- the synthetic has no live caller"),
        ((750, 751), "redactRedisUrl urlsplit catch: the ported PyUrllib.urlsplit is "
                     "total over every string input (zero throw sites in PyUrllib.kt; "
                     "the python Invalid-IPv6-URL checks live in splitHostPort, whose "
                     "catch at 763-765 is covered), so the catch cannot fire"),
    ],
    "PairRedaction.kt": [
        ((136, 136), "percent-escape conjunct of resolvePairResult: decodedName resolves "
                     "through decodePairNameSlow, and '%' is a NAME_BOUNDARY char, so "
                     "every candidate segment excludes it - the conjunct can never see a "
                     "'%' (the identical defensive check sits at python "
                     "pair_redaction.py:91-93)"),
    ],
    "IgnorecaseFold.kt": [
        ((98, 98), "foldGroupByCodePoint double-checked-locking hit: reached only when "
                   "a second caller enters the synchronized block after another thread "
                   "published the cache - a benign-race arm; the single-threaded path "
                   "always builds at 99"),
    ],
    "SusPatternsFileUploadTemplates.kt": [
        ((317, 317), "template frame fail-closed guard: the frame regex is compiled from "
                     "the very opening/closing delimiters the span was found by, so "
                     "matchAt over that span always matches"),
    ],
    "SecurityConfigBuilder.kt": [
        ((1457, 1458), "MapApplier.intValue wrong-type arms: fromMap pre-validates every "
                       "field through the ConfigValidators per-field pass, which rejects "
                       "wrong-typed raw values before MapApplier.apply runs (probe: "
                       "fromMap('trusted_proxy_depth' to true) rejects 'Input should be a "
                       "valid integer (got bool)' without entering intValue) - the applier "
                       "only ever sees pre-validated types"),
        ((1462, 1462), "intOrNullValue: same pre-pass - the null/wrong-type shapes never "
                       "reach the applier"),
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
        ((1605, 1605), "behaviorRulesValue value-level arm: same pre-pass proof as "
                       "1457-1458"),
        ((1612, 1612), "behaviorRuleFromMap unknown rule_type arm: the ConfigValidators "
                       "pre-pass (ConfigValidators.kt:587-592) rejects unknown rule types "
                       "before the applier runs"),
        ((1616, 1616), "behaviorRuleFromMap unknown action arm: same pre-pass proof as "
                       "1612"),
        ((1639, 1639), "endpointRateLimitsValue bad-tuple arm: same pre-pass proof as "
                       "1457-1458"),
        ((1643, 1643), "endpointRateLimitsValue non-dict arm: same pre-pass proof as "
                       "1457-1458"),
        ((318, 318), "dynamicRulesCachePath property-declaration field-init probe: a "
                     "Kotlin backing-field artifact; the builder is constructed "
                     "throughout the suite and the provided-flag setter body (319-322) "
                     "is covered"),
    ],
    "PyJson.kt": [
        ((377, 377), "floatRepr finite-double fallback: the digit-loop always terminates "
                     "for finite doubles (comment on 376); NaN/Infinity never reach the "
                     "redis-score float path"),
        ((46, 46), "Parser.pos synthetic accessors: kotlinc emits getPos()/setPos() "
                   "for the 'var pos: Int = 0' property and maps their bytecode to "
                   "line 46, but Parser is private and every in-class access reads the "
                   "backing field directly, so the accessors have zero call sites "
                   "(same compiler-artifact family as the excluded "
                   "SecurityConfigBuilder.kt 318 field-init probe)"),
    ],
    "PyDiffLib.kt": [
        ((134, 136), "junk-extension backward pass: SequenceMatcher is the isjunk=None "
                     "port - bJunk is a hard-wired emptySet with no setter, so "
                     "bJunk.contains(...) is always false and the loop body cannot run "
                     "(the loop is kept for structural parity with CPython "
                     "Lib/difflib.py find_longest_match)"),
        ((142, 144), "junk-extension forward pass: same permanently-empty bJunk as "
                     "134-136 - the third conjunct short-circuits before the line-142 "
                     "comparison evaluates"),
    ],
    "SecurityHeadersManager.kt": [
        ((36, 36), "getInstance synchronized again-branch: the double-checked-locking "
                   "benign-race family (see the excluded IpInfoManager 97-102)"),
    ],
    "RateLimitManager.kt": [
        ((347, 348), "getInstance synchronized again-branch: the double-checked-locking "
                     "benign-race family (see the excluded IpInfoManager 97-102)"),
    ],
    "HandlerSeams.kt": [
        ((24, 24), "register synchronized double-check return: @Volatile registered is "
                   "read outside the block and re-read inside; the inner return needs "
                   "a second registration thread to win the race between the reads - a "
                   "benign-race arm"),
    ],
    "DynamicRuleManager.kt": [
        ((134, 136), "update-loop generic catch: updateRules() swallows every exception "
                     "internally (its own catch at DynamicRuleManager.kt:268 logs and "
                     "returns), and interruptibleSleep handles its withTimeout "
                     "internally, so nothing in the loop body can raise except "
                     "CancellationException (handled above) - the arm is provably dead "
                     "defensive code"),
        ((647, 649), "persistLastKnownRules dump catch: dumpLastKnownRulesSnapshot is "
                     "total over the typed DynamicRules domain (every field renders "
                     "through JsonPrimitive/stringListJson and PyJsonDumps of a "
                     "JsonObject cannot throw), so the wrapper only guards failure "
                     "classes python's json.dumps could raise (the arm preserves the "
                     "reference's structural wrapper)"),
        ((687, 687), "writeLastKnownRulesFile cleanup-ignored arm: deleteIfExists runs "
                     "on a temp file this function just created in a freshly-writable "
                     "parent, which on POSIX always deletes; the arm exists for Windows "
                     "file-lock semantics (the same family as the excluded IpInfoManager "
                     "close rethrow)"),
    ],
    "AuthenticationCheck.kt": [
        ((132, 132), "unsupported-verifier else arm: verifier is the elvis of exactly "
                     "routeConfig.authVerifier (RouteAuthVerifier?) and "
                     "config.authVerifier (AuthVerifier?), and the null case returns "
                     "earlier - no third runtime type can reach the when; Kotlin's Any? "
                     "static type merely forces the exhaustive else"),
    ],
    "ChecksFactory.kt": [
        ((32, 32), "SecurityCheckFactory.containerFields interface default: every "
                   "implementer shadows it - all 13 check companions go through "
                   "CheckCompanion (which overrides the property with a backing field) "
                   "and the four checks with real container fields override it again "
                   "on their companions, so the interface default getter has no "
                   "dispatch site"),
    ],
    "HandlerInitializer.kt": [
        ((214, 215), "lazy cloud-IP initialization catch: initializeCloudRedis guards "
                     "every failure inside its own per-provider try bodies "
                     "(refreshAsync's loop catch and refreshProvidersViaRedisHandler's "
                     "loop catch), the pre-loop returns are clean, and "
                     "bareProviderNames/parseCloudSelectors are total string ops - no "
                     "exception can escape initializeCloudRedis to reach the lazy-init "
                     "catch (the geo arm at 223-224 is covered by a throwing handler "
                     "test)"),
    ],
    "IpExtraction.kt": [
        ((150, 150), "resolveForwardedChainRightToLeft metachar null-return: the metachar set "
                      "(* ? [ ]) is disjoint from the address grammar parseAddress accepts "
                      "(digits, dots, colons, hex, %), so forwardedHeaderCandidateAddr never "
                      "succeeds on a metachar-carrying entry and the conjunct's return is "
                      "unreachable (the candidateAddr-null return above it is covered)"),
        ((153, 153), "resolveForwardedChainRightToLeft loop-tail null: the function is only "
                      "called when forwardedHeaderRightSideUnlistedCount > 0, which guarantees "
                      "a predicate-failing entry exists in the window, and the reversed loop "
                      "returns at or before the first such entry - the loop cannot exhaust"),
        ((307, 308), "resolveClientIpFromForwardedChain outer catch: every call inside the try "
                      "either handles ConfigValidationError internally (canonicalizeIp, "
                      "isTrustedProxy, forwardedHeaderCandidateAddr) or is a total string/parse "
                      "operation - parseAddress raises only ConfigValidationError (verified by "
                      "probing 20+ hostile shapes), so no exception reaches the catch"),
    ],
    "ChecksHelpers.kt": [
        ((347, 347), "isReferrerDomainAllowed urlsplit catch: the ported "
                     "PyUrllib.urlsplit is total over every string input (zero throw "
                     "sites in PyUrllib.kt; the python Invalid-IPv6-URL ValueError "
                     "checks live in RedisManager's splitHostPort instead), so the catch "
                     "cannot fire"),
    ],
    "PyReParser.kt": [
        ((262, 262), "parseQuantifier else arm: the only caller gates on the quantifier "
                     "characters before calling (PyReParser.kt:186: a char outside *+?{ "
                     "returns the atom), so the when's else arm has no dispatch site"),
    ],
    "MiddlewareSurfaceProtocols.kt": [
        ((22, 22), "sendMiddlewareEvent default-arg tail: the instruction maps to the "
                   "DefaultImpls.sendMiddlewareEvent$default compatibility shim (the "
                   "pre-1.4-caller layout); every call site in the repo compiles "
                   "against the interface's own $default (whose instructions map to "
                   "lines 16/21), so the shim has no caller - a Kotlin compiler- "
                   "artifact line"),
    ],
    "ClassIntersection.kt": [
        ((72, 72), "crossNonPairingSlot boundary null-crossing with a non-null exact "
                   "fill: pairingUnitsFrom keeps exactState equal to shared as a set "
                   "after every narrowing step (pairing overlap narrows both by the "
                   "slot intervals; a boundary group narrows shared to its crossing "
                   "result and exactState by the same group's isolated state; non- "
                   "boundary groups narrow neither), so a group whose crossing over "
                   "shared is empty also has an empty exact-overlap fill and line 71 "
                   "returns before 72"),
        ((141, 148), "advancePairingChain exactFill arms: the same exactState == shared "
                     "invariant - exactFill = exactState intersect slot.intervals is "
                     "empty whenever overlap = shared intersect slot.intervals is empty, "
                     "so the exactFill path has no reachable input; the overlap-empty "
                     "verdict returns at 138-139"),
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
