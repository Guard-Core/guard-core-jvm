# W9d coverage report (the 100 percent push, batch 2)

Measured 2026-10-13 with the W8d/W9a merged method: ALL module exec files
counted against ALL kotlin classes (per-module reports UNDERCOUNT because the
conformance module exercises facade/engine code from another JVM). Reproduce:

    ./gradlew cleanTest test --no-daemon
    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9d

## Before/after per module (merged cross-module JaCoCo)

| module | W9c baseline (master 83da39a) | after W9d batch 2 | missed |
|---|---|---|---|
| guard-core-engine | 96.44% (263 missed) | 97.02% | 220 |
| guard-core (facade) | 91.96% (1,182 missed) | 94.67% | 784 |
| guard-core-conformance (runners) | 89.89% (127 missed) | 90.76% | 116 |
| workspace total | 93.27% (1,572 missed) | 95.20% (22,219/23,339) | 1,120 |

Net: ~452 lines closed this wave (1,572 -> 1,120) with ~120 new test methods
over 8 new JUnit classes.

## Tests added this wave

- UtilW9dTailsTest (facade/util): DetectionConfig constant/route/address-chain
  arms, the DetectionScan enhanced-detect failure arms over the new
  enhancedDetectOverride seam (budget-exhausted miss, the recursion-class
  re-raise, both fallback arms, the empty-threats verdict), the
  BodyContentScan query-param/header/body-field/blob arms incl. sensitive
  redaction logging, the BodyFormScan multipart parser shapes (LF-only
  separators, folded headers, missing content-disposition), the
  PenetrationDetection surrogateescape decoders, the BodyReader
  oversized-declared-body path, the pair-redaction defaults, and the
  IpExtraction forwarded-chain containment arm.
- ConfigW9dTailsTest (facade/config): the full builder-setter booking sweep,
  the hook/verifier appliers, and the fromMap coercion rejection matrix
  (int/float/bool/str/list/set/dict/path/level/format/policy/threat-ban/
  behavior-rules/endpoint-rate-limits) with the valid coercions alongside.
- HandlersW9dTailsTest + HandlerSmallTailsTest (facade/handlers): CloudManager
  refresh/ledger/store arms over the fetcher httpGetOverride seam, the Redis
  URL redaction shapes, RateLimitManager singleton + in-memory window counting,
  IpInfoManager singleton bookkeeping + country access + the download retry
  loop over the new httpSendOverride seam, SecurityHeadersManager disabled
  arm, the behavior dispatch/passive/return-pattern surface, the
  SusPatternsRegistry event/removal arms, the Azure ServiceTags URL helpers,
  and the dynamic-rules snapshot validation rejections.
- CoreW9dTailsTest (facade/core + decorators): the HandlerInitializer
  buildEventBus/buildMetricsCollector fail-closed arms + composite wiring, the
  CompositeAgentHandler lifecycle with a failing member, the otel/logfire
  surfaces, the enricher, the event bus muted/cloud arms, the
  BaseSecurityDecorator event surface, and the RouteConfig tracked-container
  mutation sweep.
- EngineW9dTailsTest (engine): the never-touched constant tables, the pickle
  opcode-VM walk arms (V/I/L/p/g, signed parse-int, quoted escapes, the
  over-budget short reads), the manager add/remove + enhanced-state arms, the
  file-upload template keyword/expression/date arms, the ParseSlots renderer
  categories, the ReachProbe builder shapes, the compiler failure arms, the
  ignorecase group-scan fold, the PyReParser numeric/named group-ref
  rejections, and the Monitor default-synthetic + sink-failure arms.
- RunnerW9dTailsTest (conformance): the pattern-safety mismatch/classifier/
  chain-module arms and the cost-budget drift/vacuous/over-ceiling/stale-ledger
  arms over seeded scratch corpora (the pinned corpus is never touched).

## Bugs found and fixed (byte-exact, with regression tests)

1. **decodeSurrogateEscape rejected every F0-led 4-byte UTF-8 sequence**
   (PenetrationDetection.kt): the `b and 0x07 != 0` validity test fails for
   first byte 0xF0, i.e. ALL of U+10000..U+3FFFF (every emoji); python decodes
   them as the code point. Fixed with the CPython overlong/range guards
   (F0 -> second byte >= 0x90, F4 -> second byte <= 0x8F). Regression:
   testDecodeSurrogateEscapeMultibyte.
2. **decodeSurrogateEscape dropped bare continuation bytes**: a standalone
   0x80..0xBF byte decoded to nothing; python's surrogateescape maps each
   error byte to U+DC00+b. Added the length-1 decode arm. Same regression.
3. **decodeSurrogateEscape shifted the whole escape range by 0x80**: the
   error-byte formula was `0xDC00 + b - 0x80` (0x80 -> U+DC00) instead of the
   PEP 383 mapping `0xDC00 + b` (0x80 -> U+DC80); both error paths now carry
   the python-exact char, keeping the DetectionScanRedaction round trip
   intact. Same regression.
4. **Template keyword/expression indicators could never match**:
   SusPatternsFileUploadTemplates searched with python endpos semantics over a
   java Matcher region, but java \\Z is the ABSOLUTE end of input while python
   endpos TRUNCATES the subject (so \\Z anchors at the barrier). The
   file-upload keyword scan was inert for every python-matchable frame. Fixed
   by truncating the subject to the barrier at both call sites. Regression:
   the template arms in EngineW9dTailsTest.
5. **Scoped (?L:...) leaked into the java pattern**: the parser parsed the
   LOCALE letter then emitted the scope verbatim, so java died later with a
   bare "Unknown inline modifier" instead of the documented fail-closed
   UnsupportedPatternFeature (the top-level re.LOCALE gate's error). Fixed at
   the parser arm. Regression: the scoped-LOCALE arm in
   testPyReParserNumericGroupRefArms.

Dead defensive code removed (behavior-preserving, written reasons inline):
the DetectionEngineWiring DeadlineExceededException catch (Long.MAX_VALUE is
the engine's no-deadline sentinel and never throws), the PairHiddenAssign
escapedGapLength loop fall-through (the regex always matches exactly one named
alternative), the LoggingUtils printable arm inside the surrogate-pair branch
(a pair always decodes above the BMP), and the Monitor recent-times empty
fallback (the window floor guarantees a non-empty deque after the append;
python's conditional else is unreachable for the same reason).

## Residual worklist (the honest remainder)

The gate is NOT wired into ci.yml in this wave: the workspace holds at 1,120
missed, and the W9b rule stands (the red-gate-on-master rule: the
byte-for-byte block in docs/w9b-coverage.md lands only when the enforcement
passes locally). The push-to-100% ruling (spec 14.2) remains OPEN: W9e (batch
3) closes the remaining 1,120 lines. The remaining uncovered lines after this
wave are enumerated by the gate itself:

    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9d

(headline residuals: the PipelineHarness/EventsHarness seeded-corpus arms, the
SecurityCheck base default-method synthetics, the JavaBridges xFuture
variants, and the per-check/decorator singles.)
