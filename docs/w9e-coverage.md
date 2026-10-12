# W9e coverage report (the 100 percent push, batches 3+4+5 - IN FLIGHT)

Measured 2026-10-13 with the W8d/W9a merged method: ALL module exec files
counted against ALL kotlin classes (per-module reports UNDERCOUNT because the
conformance module exercises facade/engine code from another JVM). Reproduce:

    ./gradlew cleanTest test --no-daemon
    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9e

## Before/after per module (merged cross-module JaCoCo)

| module | W9d baseline (master 7ae562c) | after batch 3 (fc48355) | after batch 4 (45662d2) | after batch 5 (this branch) | missed |
|---|---|---|---|---|---|
| guard-core-engine | 97.02% (220 missed) | 98.47% | 99.15% | 99.15% (62 reasoned excludes) | 62 |
| guard-core (facade) | 94.67% (784 missed) | 95.93% | 96.84% | 97.15% | 413 |
| guard-core-conformance (runners) | 90.76% (116 missed) | 99.76% | 99.76% | 99.76% | 3 |
| workspace total | 95.20% (1,120 missed) | 96.94% | 97.73% | 97.95% (22,847/23,347) | 500 |

Net: 405 lines closed this batch (1,120 -> 715) with 91 new test methods over
7 new JUnit classes. The push-to-100% ruling (spec 14.2) remains OPEN: the
batch landed mid-wave and the next slice closes the remaining 721 lines (the
per-class worklist is printed by the gate itself:

    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9e

).

## Tests added this batch

- HarnessArmsW9eTest (conformance): the PipelineHarness seeded arms (the
  RecordingEventBus https/decorator surfaces, the StubGeoHandler lifecycle,
  the StubRouteResolver cloud-provider arm, the redirect/https/applyModifier
  factory arms, the middleware surface getters, the CaseInsensitiveHeaders
  full map surface, the seeded route/config keys incl. the geo_rate_limits
  and global-behavior default-action arms, the process_response stage and
  the unknown-stage guard) + the EventsHarness seeded arms (the config and
  route key tables, the routes-elvis arm, the decorator sender guard, the
  redis_connect_error arm both ways, the script-reload 429 path over a new
  step-key seam) + the comparison-runner arms (the PatternSafety probe
  chain-module table, the vacuous-corpus guard, the CostBudgetRunner
  default-arg loaders and the empty-budget guard, the DetectRunner
  threat-field mismatch matrix over a scratch corpus rendered from live
  verdicts, the EventsComparison diff/render tables).
- EngineW9eTailsTest (engine/detection): the ParseSlots category/
  not-literal/class-item/multi-atom arms, the ReachProbe group-synthesis
  arms (named groups, flag scopes with negation, unknown forms, brace
  bounds, unrepresentable escapes), the builder families over crafted
  crossing patterns, the repeat-prefix state/text/candidate budget
  rejections, the repeat-unit pair-count budget, the large-bounded-repeat
  probe, the unreachable-terminator malformed-brace/class/escape arms, the
  structure-rules nesting-depth rejections, the IntervalSet render, the
  group-scan ignorecase expansion + cache hit, the JsonNull sentinel, the
  safe-matcher deadline arms over a redos bomb, the batchCompile skip arms
  over a duplicate-group-name pattern, and the probe compile guard.
- SusPatternsW9eTailsTest (engine/suspatterns): the pickle signed-int and
  quoted-escape decoders, the pickle-global marker scan advance, the
  recon-path probe contexts, the backtick-pair verdict windows, the manager
  add/remove default and custom arms over the shared singleton, the
  candidate-rejection scan loop (benign-then-malicious backtick pairs), the
  semantic fallback threat over a near-zero threshold, the arbiter deadline
  injection via firstOverBudgetReason with a nanosecond budget, the
  construction-timeout verdict, and the file-upload truncation + the
  date-anchored template arm.
- CoreW9eTailsTest (facade/core + events): the bypass warn-once guard, the
  response-factory required-seam guards, the process-response behavioral
  sweep, the decorator violation events on threshold hits, the pipeline
  redis fail-open arm + toString, the SecurityCheck default-method
  synthetics, the decorator/rate-limit emit helpers, the fixed-order
  factory check, the Verifier completion-stage unwrap, the global cloud
  block-list resolver fallback, the logfire/otel handler lifecycles over
  installed surfaces, the composite fan-out with a failing member and the
  default member bodies, the enricher tolerance arms, the metrics filter,
  and the event-type gate.
- HandlersW9eTailsTest (facade/handlers): the snapshot type-error matrix,
  the redis URL redaction arms (bracketed hosts, bad ports, userinfo
  drops), the PyJsonDumps shapes, the JavaBridges default-arg synthetics
  and the redis initialize bridges, the rate-limit script load + 429 +
  fail-open + in-memory arms over the live redis, the ipinfo download/
  refresh/country arms over the test seams, the cloud manager + azure + aws
  fetcher arms over the http seams, the security-headers disabled/cors
  arms, the behavior tracker tables and the dispatch arms, the suspatterns
  registry add/remove arms, the pattern-source escape redaction, the
  snapshot field table, the seam idempotence, and the ban-migration quiet
  arms.
- FacadeW9eConfigUtilTest (facade/config + util): the cross-field
  validator/warn/error arms, the copyWith field-write surface, the tracked
  route containers, the header/param/body scan component arms, the
  multipart binary/malformed arms, the pair-redaction decoders, the
  sanitize arm, the ipv6 parse-error matrix, the py-urllib/py-json
  delimiter arms, and the difflib ratio/matching arms.
- BuilderW9eSurfaceTest (facade/config): the builder property write/read
  sweep over the provided-flag custom setters.

## Bugs found and fixed (byte-exact, with regression tests)

1. **The template date scan passed its end bound as a deadline**
   (SusPatternsFileUploadTemplates.finditerWithin): python's
   `_template_after_dates` scans with `pattern.finditer(content, pos,
   endpos)` - the bound is an ENDPOS. The port called
   `search(text, searchFrom, to.toLong())`, feeding the bound as the
   DEADLINE, so every scan expired immediately and the date-anchored
   re-anchor of `template_expression_matches` was INERT (the corpus never
   exercises a date between two frames). Fixed with the endpos-bounded
   search overload; regression: the dated-template arms in
   SusPatternsW9eTailsTest.

## Residual worklist (the honest remainder)

715 lines remain (facade 599, engine 113, conformance 3). Dominants from the
gate's per-class print: the manager event-armed tails (IpInfoManager,
CloudManager, DynamicRuleManager, RateLimitManager, SecurityHeadersManager),
the builder/copy field-write sweeps, the decorator factory singles, the
per-check arms (HttpsEnforcementCheck, the per-check early returns), the
HandlerInitializer initialize arms, the SecurityEventBus forwarded-header and
agent-failure arms, and in the engine the timing-race and defensive-catch
arms (arbiter/matcher/stray deadlines, the thread-CPU fallback) that are
exclude candidates with written reasons, plus the PyRe scoped-emitter
fail-closed arm for node kinds the sre port never emits.

The gate is NOT wired into ci.yml in this batch: the workspace holds at 721
missed, and the W9b rule stands (the red-gate-on-master rule: the
byte-for-byte block in docs/w9b-coverage.md lands only when the enforcement
passes locally across repeated runs).

CORPUS GATE: unchanged by this batch - 375 cases + 9 budget workloads,
0 failing, 8 ledgered (verified with `--rerun` on
:guard-core-conformance:fullCorpusGate after the harness seam and the
finditerWithin fix; the seeded step keys the pinned corpus never sets keep
the runner behavior byte-identical).
