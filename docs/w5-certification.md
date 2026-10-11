# W5 Corpus Certification (guard-core-jvm)

The W5 gate: the full vendored corpus runs against the engine in one command and every suite
meets its comparison contract. This is the campaign's zero-xfail bar for the corpus arm
(specs/impl/jvm.md, "Parity bar" item 1); the every-feature matrix and section-table arms remain
the W8 release bar.

## The one gate

```bash
./gradlew :guard-core-conformance:fullCorpusGate
```

runs all 21 suites plus the cost budgets in one command and prints the per-suite summary
(pass / fail / ledgered + total). CI's `ci` job runs it as the "Full corpus certification gate"
step after the standard build. The gate also pins the totals so drift is loud: 375 corpus cases,
the events ledger at its 2-entry floor, the pattern-safety ledger at 6 entries, and an empty cost
ledger.

## Per-suite results (spec 4.1.0, engine 4.3.2 corpus, this branch)

| suite | cases | result | ledger |
|---|---|---|---|
| xss | 22 | 22/22 | - |
| sqli | 22 | 22/22 | - |
| cmd_injection | 18 | 18/18 | - |
| path_traversal | 10 | 10/10 | - |
| inclusion_sensitive_recon | 18 | 18/18 | - |
| misc_injection | 29 | 29/29 | - |
| encoding | 8 | 8/8 | - |
| semantic | 6 | 6/6 | - |
| benign | 15 | 15/15 | - |
| context_matrix | 9 | 9/9 | - |
| boundaries | 8 | 8/8 | - |
| binary_bodies | 19 | 19/19 | - |
| cost_bodies (detect arm) | 9 | 9/9 | - |
| pipeline_ip_control | 12 | 12/12 | - |
| pipeline_rate_limits | 5 | 5/5 | - |
| pipeline_detection_response | 8 | 8/8 | - |
| pipeline_headers_cors | 7 | 7/7 | - |
| pipeline_behavior_rules | 3 | 3/3 | - |
| event_stream (W4b) | 39 | 37 exact + 2 ledgered | 2 reason-string shapes (the TS floor) |
| redis_interop (W3) | 14 | 14/14 | - |
| safety_gates (W5) | 94 | 88 exact + 6 ledgered | 6 cost-verdict timing facts |
| cost budgets (W5) | 9 workloads | 9/9 under self-relative ceiling | empty fail-closed manifest |
| **total** | **375 cases + 9 budgets** | **0 failing** | **8 ledgered** |

Wave history: detect 193/193 (W2), pipeline 35/35 (W4a), redis_interop 14/14 (W3), event_stream
37+2 (W4b), safety_gates + budgets (W5).

## Pattern-safety certification

`safety_gates.json` replays through the ported chain exactly the way the reference oracle drives it
(`generate_safety_gates.py._worker`): a fresh `PatternCompiler` per case; `test_strings` mode passes
the case strings; `cost_verdict` mode passes `max_content_length=10000`. Comparison is
`{safe, reason_class}` under the index.json `pattern_safety_records` rule - the numeric parts of
over-budget reason strings are host-measured and never compared; the reason class is compared
exactly. A divergence names its producing chain module and the python anchor.

### Certification-revealed engine bugs (fixed here, byte-exact, with tests)

1. **`StructureRules.isBroadCharClassInner` double escape.** The non-negated branch compared the
   Kotlin literal `"\\\\s\\\\S"` (runtime text `\\s\\S`, six chars) instead of the raw class inner
   text `\s\S` (python: `inner in ("\\s\\S", "\\S\\s")`), so `[\s\S]` was never counted as a broad
   atom. The adjacent-broad prefilter missed `[\s\S]*[\s\S]+$` and `[\s\S]*x[^%]+`
   (`safety_test_strings_structural_adjacent_broad_05/06`). Fixed to the python literal text;
   regression tests in `RedosChainTest`.
2. **`PyRe.translateSource` skipped the documented named-group translation.** The verbatim path
   never applied `(?P<name>` -> `(?<name>` / `(?P=name)` -> `\k<name>`, so python-spelled named
   groups failed the compile gate in java.util.regex ("Unknown inline modifier") before the
   structural checks could classify - five corpus cases diverged to `compile_failed`. Fixed in the
   translator (class-aware: `(?P<` inside a character class stays literal); regression tests in
   `PyReBehaviorTest`.
3. **Cloud checks' `applies_to` missed the dynamic-rules disjunct.** The reference
   `cloud_blocking_enabled` helper is `bool(block_cloud_providers) or enable_dynamic_rules`; the
   JVM `CloudIpRefreshCheck`/`CloudProviderCheck` companions checked only the providers set, so
   `applies_to` dropped both checks under `enable_dynamic_rules` with no providers configured.
   Found by the ported `test_check_applies_to.py` matrix; fixed and covered there.

### The 6 ledgered divergences (`jvm_safety_xfail.json`, fail-closed)

All six are `cost_verdict`-mode timing facts: the corpus pins the reference engine's probe timings
(python re on the generating host), and the arbiter certifies what THIS engine's executor
(java.util.regex backtracking under the DeadlineCharSequence abort) measures on the same
synthesized probe sets. The structural, compile, dangerous-construct, and test-string-probe layers
reproduce every reference verdict exactly.

| case | reference | JVM | measured | class |
|---|---|---|---|---|
| safety_cost_verdict_over_budget_01 `(\d)\|(\w)*;` | over_budget | safe | under budget | strict |
| safety_cost_verdict_structural_nested_unbounded_01 `(a\|aa)+$` | structural_nested_unbounded | safe | under budget | strict |
| safety_cost_verdict_safe_05 `<!\[CDATA\[.*?\]\]>` | safe | structural_unreachable_terminator | extrapolated 0.053-0.057s vs 0.05s | boundary |
| safety_cost_verdict_safe_06 `<script[^>]*>` | safe | structural_unreachable_terminator | 0.057-0.073s vs 0.05s | boundary |
| safety_cost_verdict_safe_08 `\$\([^)]+\)` | safe | structural_unreachable_terminator | 0.19-0.26s vs 0.05s | strict |
| safety_cost_verdict_safe_09 `\$\{[^}]+\}` | safe | structural_unreachable_terminator | 0.249-0.260s vs 0.05s | strict |

- The two accept-direction entries mirror the Rust family's ledger of the same cases: the
  reference over-budget is a python-re timing fact (`(\d|\w)*;` linearizes under java's
  deterministic-loop optimization; `(a|aa)+$` times under budget on java.util.regex).
- The four reject-direction entries are java.util.regex measuring the prefix-flood probe sets
  over budget where python re measures under (relative engine speed on the same probes).
- Two entries carry the `boundary` marker: their extrapolated cost sits within ~1.5x of the
  0.05s budget, so ordinary host load-factor movement (the normalization divides by the measured
  reference-scan load factor) legitimately flips them between the divergent verdict and the
  reference verdict. The ledger accepts either outcome for those; any third verdict is red. The
  Go family documented the identical flip on `safety_cost_verdict_safe_05` on its engine
  (guard-core#75 era transient note in the corpus refresh record).
- Fail-closed semantics: a failing case not listed is red; a listed non-boundary case that
  reproduces the reference verdict is a stale baseline (red); a listed case whose observed
  divergent verdict drifts from the recorded one is red.

## Cost-budget certification

`cost_bodies.json` verdict parity rides the detect runner (193/193 includes these 9); the budget
runner enforces scan-cost ceilings per index.json `cost_budgets.method`:

```
best_ms <= K * best8_ms * (size_bytes / 8192) + floor_ms    (K=5, floor_ms=250)
```

with adaptive best-of-N sampling (min of 3 below 64 KiB, 2 below 256 KiB, 1 above - the reference
runners' CI-viable sampling). Every workload sits 5.7x-16x under its self-relative ceiling on the
certification host; the curve is linear in input size:

| workload | size | best (ms) | ceiling (ms) | headroom |
|---|---|---|---|---|
| cost_prose_8kib (baseline) | 8192 | ~50-77 | - | - |
| cost_prose_64kib | 65536 | ~310-368 | ~2250-3300 | 6.1x-10.7x |
| cost_prose_256kib | 262144 | ~1200-1446 | ~8200-12500 | 5.7x-10.4x |
| cost_prose_1mib | 1048576 | ~3800-4500 | ~32200-49200 | 7.1x-12.8x |
| cost_encoded_64kib | 65536 | ~330-384 | ~2250-3300 | 5.9x-10.0x |
| cost_binnoise_64kib | 65536 | ~334-386 | ~2250-3300 | 5.8x-9.9x |
| cost_threat_8kib | 8192 | ~40-50 | ~500-630 | 10.3x-16.0x |
| cost_threat_tail_256kib | 260608 | ~1180-1427 | ~8190-12400 | 5.7x-10.5x |
| cost_threat_mid_1mib | 1048576 | ~3670-4360 | ~32200-49200 | 7.4x-13.4x |

The fail-closed manifest `jvm_cost_xfail.json` ships EMPTY: a workload over ceiling must be
listed with a reason, and a listed workload that comes back under ceiling fails the build (stale
entry). `reference_ms` in the index is drift-review metadata and is never compared.

## G-13 remainder (W4b -> W5 re-scope)

Landed this wave (ports of tests/test_core/, file-for-file):

- `BehavioralGlobalRulesTest` (test_behavioral_global_rules.py: correlation halving + floor,
  tracker resolution halves, apply_action through the live ban manager)
- `IpSecurityBannedIpEventsTest` (test_ip_security_banned_ip_events.py)
- `ExemptIpsTest` (test_exempt_ips.py: flag semantics, blacklist/ban/whitelist precedence, route
  overrides, cloud block, per-check exempt skips, /0 warning)
- `InitializationCloudProviderTypingTest` (test_initialization_cloud_provider_typing.py async
  half; the sync-mirror half is N/A by construction - the facade blocking bridge is the recorded
  idiom mapping)
- `AuthenticationVerifierTest` (test_authentication_verifier.py; the async-verifier-await half is
  N/A by construction - the JVM verifier SAMs are synchronous)
- `CheckAppliesToTest` (test_check_applies_to.py: the full config-driven and route-driven
  matrices, the dynamic-rules keep flag, the behavior-rules-can-ban ip_security survival)
- `IpSecurityEdgeCasesTest` (test_ip_security_edge_cases.py)

Deferred with precise owners (see KNOWN_GAPS.md): test_edge_cases.py,
test_ip_security_global_route_merge.py, test_pipeline_route_config_revision.py,
test_block_vs_ban_escalation.py, test_escalate_identity_violation.py, test_initialization.py,
and the handler-side halves of test_check_rate_limit_by_ip*.py.

## Verdict

Corpus arm of the Parity bar: SATISFIED - zero unledgered xfails across all 375 corpus cases and
the cost budgets, one command green locally and in CI. The 8 ledgered entries are documented
reason-string shapes (2, the TS floor) and per-engine timing facts (6, the RS class), each with a
written cause and fail-closed drift semantics. The remaining Parity-bar arms (every-feature matrix
zero PARTIAL/MISSING, section table) are the W8 certification bar per the work order.
