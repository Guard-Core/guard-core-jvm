# W9c coverage report (the 100 percent push, batch 1)

Measured 2026-10-12 with the W8d/W9a merged method: ALL module exec files
counted against ALL kotlin classes (per-module reports UNDERCOUNT because the
conformance module exercises facade/engine code from another JVM). Reproduce:

    ./gradlew cleanTest test --no-daemon
    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9c

## Before/after per module (merged cross-module JaCoCo)

| module | W9b baseline (master f55803e) | after W9c batch 1 | missed |
|---|---|---|---|
| guard-core-engine | 91.68% (616 missed) | 95.31% | 263 |
| guard-core (facade) | 90.54% (1,391 missed) | 91.09% | 1,184 |
| guard-core-conformance (runners) | 87.82% (153 missed) | 89.89% | 127 |
| workspace total | 90.76% (21,215/23,375) | 95.31/91.09/89.89 per module | 1,574 |

Net: 494 lines closed this wave (2,068 -> 1,574). The 100 percent gate is NOT
wired into ci.yml in this wave: the workspace holds at 1,574 missed, and the
W9b rule stands (the gate lands byte-for-byte from docs/w9b-coverage.md only
when the enforcement passes locally). The worklist below is the precise
remainder, per class, from the final merged run.

## Tests added this wave

- PyW9cTailsTest (engine/py): PyAst grammar corners (comments, aug-ops, escapes,
  triple strings, lambda param shapes, await, attribute arms, call-arg shapes,
  subscript/slice shapes, paren/list/brace bodies, comprehension clauses and
  target shapes, the StackOverflowError fail-closed), PyUnicode arms
  (allPrintable, per-code-point case mappings, charToCpIndex), PyRe translation
  tails (group-ref escapes, named groups, the scoped-emitter matrix: anchors,
  branches, lookaround, quantifier spellings, control-char literals, non-ASCII
  literals, repeats), DeadlineCharSequence timeouts, astral-plane match offsets,
  region/endpos search arms; PyReParser escape/inline-flag/comment arms.
- DetectionW9cTailsTest (engine/detection): ParseSlots copy/equals/hashCode,
  ASCII category predicates, node-interval arms, candidate-char arms, slot
  shapes; AmbiguousTail fallback arms; ReachProbe synth shapes + overflow +
  budget arms; ClassIntersection crossing walks; CostArbiter load-factor
  fallback, timing arms via firstOverBudgetReason, verdict components; Compiler
  timeout counters + safe matchers + batch compile; Base64Decode gzip/candidate
  arms; IgnorecaseFold expansions; Monitor metric defaults + nested send
  failure; the small scanners (structure rules, unreachable terminator,
  primitives, repeat units/alphabet, interval sets, scan windows, semantic
  analyzer, truncation/preprocessor, base64 alphabet, binary islands, literal
  runs, encoders) and the ValidationCache JSON-escape round trip.
- SusPatternsW9cTailsTest (engine/suspatterns): the XML/XXE public-DTD walker
  (minimum-gap shapes, earliest-doctype, the product matrix, precompute/candidate
  span/public-run bounds, scheme-completion rejections, system/internal-entity
  finders), the pickle opcode-VM tails (V/I/L/i/p/g opcodes, escapes, buffer
  opcodes via the surrogateescape window, parse-int arms, suffix reduce/build,
  the prefix-window mapping), the file-upload scan window, the template
  keyword/expression matchers, the LDAP null-byte attr walkers, the LDAP breakout
  windows, the legacy IPv4 decoders, the glob dangerous-command predicate, the
  manager timeout arms (a 1e-12s compiler timeout trips the wall-clock guard),
  the validation-cache-backed state, the semantic category map, the debug-views
  arm.
- ConfigW9cTailsTest (facade/config): every builder setter's provided
  bookkeeping, the geoIpHandler factory wiring, fromMap sweeps + unknown-key
  warning posture, per-validator rejection arms, copyWith revalidation (exclude
  paths, country shadow, geo-state re-resolution), valueByName, RuleConfigs
  enum tables, BehaviorRuleConfig/ThreatBanConfig equality + validation.
- CoreW9cTailsTest (facade/core): the SecurityCheck base surface (appliesTo,
  sendEvent, createErrorResponse, passive mode), pipeline signature/staleness
  via reflection, RequestValidator trusted-proxy + time-window arms, the
  BehavioralProcessor usage/return pass-through, the event bus middleware path,
  composite fan-out with a failing member, otel/logfire surfaces, the enricher,
  JavaBridges checkRateLimit/initializeRedis futures, the response factory.
- ChecksW9cTailsTest (facade/checks): request-size arms (413, garbage length,
  content-type allowlist), emergency mode (whitelisted/stranger/passive), HTTPS
  enforcement (redirect, forwarded proto via trusted/untrusted proxies),
  required headers (missing/wrong/exact).
- DecoratorsW9cTailsTest (facade/decorators): every SecurityDecorator factory
  surface, the tracked-container revision bumps, the per-call-site route-id
  derivation asserted over the live map.
- RunnerErrorArmsW9cTest (conformance): the DetectRunner case-failure arms over
  a seeded scratch corpus (flag/score/count/field mismatches and the thrown-case
  root-cause walk); the pinned corpus is never touched and the shared manager is
  restored.

## Bugs found and fixed (byte-exact, with regression tests)

1. **PyAst aug-assignment operators looped forever** (PyAst.kt tokenize): the
   `**=` / `//=` / `>>=` / `<<=` arm ran `i += 0`, so any input containing those
   operators pinned the tokenizer (and the scan worker) in an infinite loop;
   python ast.parse raises SyntaxError immediately. Fixed with `i += 3` (the
   token stream then fails the eval grammar, matching the python verdict).
   Regression: testAugmentedAssignmentOpsReject.
2. **The (?-i:...) scoped emitter inverted case sensitivity outside the scope**
   (PyRe.kt emitScopedNodes): non-locked segments were wrapped using the BASE
   flags (the global flag minus the removed one), so under `re.IGNORECASE` the
   unlocked literal `b` in `(?-i:a)b` compiled case-SENSITIVE and the locked `a`
   case-INSENSITIVE - the exact opposite of python. Fixed by re-applying the
   ORIGINAL top flags to unlocked segments (and clearing them inside a delFlags
   scope), and by threading topFlags through assert/branch bodies.
   Regression: testScopedEmitterArms.
3. **The call-argument walrus never parsed its value** (PyAst.kt parseCallArgs):
   `f(x:=1)` (valid python) was rejected because the `:=` arm consumed the name
   and stopped. Fixed by parsing the assigned expression.
   Regression: testCallArgShapes.
4. **Valid python constructs the PyAst grammar rejected**: `f(*args, **kwargs)`
   (the `*`/`**` call-arg prefix order) and the interleaved comprehension
   clauses (`for x in y if a for z in w if b`) both raised against python-valid
   input; the comprehension loop was restructured into
   parseComprehensionClauses (if/for interleaving). Regressions in
   testCallArgShapes + testComprehensionContinuationAndTargets.
5. **`\g<num>` / `\g<name>` group references were rejected at parse time**
   (PyReParser.kt parseEscapeAtom): python accepts the spelled-out form; the JVM
   raised "bad escape \g". Added the sre_parse-equivalent arm (numeric with the
   open/invalid-group guards, named via the group table).
   Regression: testCompileNamedGroupAndBackrefPattern.
6. **Dead defensive code removed (behavior-preserving)**: AmbiguousTail's
   shape-only parser (uncalled in python and the JVM), PyReParser's unreachable
   post-quantifier repeat check + the unreachable parseQuantifier fall-through +
   the sequence-level ')' atom arm, PyAst's atom-level lambda arm and the
   empty-call-arg arm (parseExpression always consumes or throws), PyRe's
   NOT_LITERAL/CATEGORY emitter arms (the parser never produces those node
   shapes), RegexWorkers' catch around FutureTask.run (failures ride the
   future), and the Manager's deadline catch around a Long.MAX_VALUE-bounded
   scan (byte-exact behavior; noted per site in the commit).

## Residual worklist (per class, from the final merged run)

- engine 263: SusPatternsManager 42 (timeout/view arms), AmbiguousTail 29 (dead
  function now removed - re-measured on the next run), Pickle 28, FileUpload
  templates 18, ReachProbe 18, Monitor 9 (default-arg synthetics - make the
  private params required next pass), Compiler 12, ClassIntersection 12,
  IgnorecaseFold 10, CostArbiter 8, ParseSlots + tails, PyReParser 11,
  PyRe 8, PyAst 6, Base64Decode 7, ProbeFill 7, Preprocessor 4, Truncation 6,
  RepeatAlphabet/RepeatUnits/RepeatPrefix/StructureRules/UnreachableTerminator/
  StrayChooser/Semantic/IntervalSet/RegexWorkers singles.
- facade 1,184: handlers ~430 (IpInfoManager 82 incl. the download retry loop
  via httpGetOverride seams, SecurityConfigBuilder 89, CloudManager 39,
  RedisManager 38, DynamicRuleManager 38, RateLimitManager 30,
  SecurityHeadersManager 23, CloudAzureFetch 22, BehaviorActionDispatch 22,
  BehaviorResponsePattern 26, BehaviorTracker 18, SusPatternsRegistry 11, the
  small tails), util ~300 (BodyContentScan 79, BodyFormScan 25,
  PenetrationDetection 19, DetectionScan 18, PairHiddenAssign 13, BodyReader 11,
  BodyJsonScan 11, RequestLogging 10, DetectionConfig 9, the tails), checks ~120
  (SecurityCheck base default-method synthetics - make the params required,
  RequestSizeContentCheck body-scan arms, the per-check singles), decorators
  ~86 (BaseSecurityDecorator 31, SecurityDecorator closure bodies, RouteConfig
  tracked tails), initialization 56 (HandlerInitializer with a REAL
  RedisManager), events ~60 (otel/logfire metric-kind arms, enricher tails,
  composite arms), config ~50 (ConfigValidators rejection tails,
  SecurityConfig copyWith tails), java 16 (the remaining xFuture variants),
  protocols/responses/routing singles.
- conformance 127: PipelineHarness 49, DetectRunner ~30 (the remaining compare
  arms), EventsHarness 29, CostBudgetRunner 12, PatternSafetyRunner 8,
  EventsComparison 7 - runner error/edge arms need direct unit tests per runner
  (the DetectRunner seeding pattern in RunnerErrorArmsW9cTest is the template).

## Bugs: 6 more for the family (19 total)

The PyAst infinite loop is the headline: a remote request body containing `**=`
would have pinned a detection worker CPU-side with no timeout escape (the
tokenizer ran before the deadline machinery). The scoped-flag inversion silently
flipped the case sensitivity of every negative-flag table pattern's unlocked
segments.
