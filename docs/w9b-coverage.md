# W9b coverage report (engine + the fail-closed line gate)

Measured 2026-10-12 with the W8d/W9a merged method: ALL module exec files
counted against ALL kotlin classes (per-module reports UNDERCOUNT because the
conformance module exercises facade/engine code from another JVM). Reproduce:

    ./gradlew test --no-daemon
    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9b

## Before/after per module (merged cross-module JaCoCo)

| module | W9a baseline (master 3859791) | after W9b | missed |
|---|---|---|---|
| guard-core-engine | 76.6% (1,593 missed: detection 894, py 279, suspatterns 421) | 91.68% | 616 (detection 258, py 153, suspatterns 202) |
| guard-core (facade) | 90.54% (1,391 missed) | 90.54% (untouched this wave) | 1,391 |
| guard-core-conformance (runners) | 87.82% (153 missed) | 87.82% (untouched this wave) | 153 |
| workspace total | 86.58% (20,237/23,374) | 90.76% (21,215/23,375) | 2,160 |

Net: 977 engine lines closed this wave (1,593 -> 616) with 34 new test methods
across 10 new JUnit classes. The facade + conformance residuals are enumerated
per line in docs/w9a-coverage.md (issue #26 worklist) and are the explicit
remainder tracked in KNOWN_GAPS.md (W9b section) for the follow-up wave.

## Tests added this wave

- ValidationCacheTest: the disk-backed validation cache (put/get round trip,
  version filtering, corrupt/foreign-shape rejection, atomic write, the
  directory-as-path arm) + JsonMini (parse arms, string escapes, control-char
  rendering, every value kind, the JSON-null sentinel).
- RedosWalkTest: the prefix walk (assertion/capture-preserving reaching
  prefixes, constraint shapes, nested-assertion and lookbehind/capture fail-
  closed budgets, dead-prefix requireReachable), the prefix state machine,
  prefixed/group probe builders with their dedup + budget arms, repeat-group
  units, repeat alphabets, exact-state narrowing, literal runs, suffix
  history, containsRepeat, and the walker node arms (atomic, backref,
  conditional, group capture, branch union, prefix collection).
- MonitorTest: every anomaly detector arm, event builders, reporting
  helpers, and the PerformanceMonitor lifecycle (truncation, clamping,
  eviction, agent sink emission, the per-pattern cooldown, callback failure
  error events, sink-failure swallowing, summary stats).
- RedosProbesTest: load-factor and deadline scaling, verdict components,
  cost/unreachable reason text, timing-row validation arms, batched
  measurement (valid + null batches), probe-fill builders, reach synthesis,
  stray chooser.
- EncodingTruncationTest: escape decoders (hex/unicode/percent-u/overlong
  UTF-8), base64 candidate decoding incl. gzip peeling, attack-region
  extraction/merging, safe truncation branches, ignorecase fold expansion,
  binary prefix/islands, PyUnicode tails.
- CompilerSafetyTest: the cached compiler (LRU arms, eviction, sync compile),
  validatePatternSafety ordering (dangerous constructs -> compile -> cache ->
  probe), the probe timeout path, safe matchers under deadline, batch
  compilation.
- ParseSlotsStructureTest: slot shapes, category predicates (ASCII + marks),
  the ambiguous-tail grammar, structure rules (broad shorthands are the
  uppercase S/W/D), structure primitives, unreachable-terminator detection,
  SemanticAnalyzer full surface, the preprocessor pipeline (decode budget
  exhaustion via a 20-deep nested percent encoding, signal-preserving views,
  sql-comment stripping), PyUrllib/PyHtml.
- PyReParserErrorsTest: the sre_parse fail-closed arms (nothing/multiple
  repeat, overflowed repetition, unterminated sets, bad ranges, incomplete
  escapes, the \N gate, octal escapes, group references, named groups,
  inline flags incl. the global-flags position rule, the 20-nesting limit,
  verbose-mode comment skipping).
- PyReTailsTest: translation edges (named groups, leading-] classes, {,m},
  scoped (?-i:...) rewrite + capture, the LOCALE gate), the hard deadline
  (search abort + the periodic charAt tick), the match-group surface.
- PyGrammarTailsTest: the PyAst expression grammar arms + PyUnicode helpers.
- SusPatternsPickleTest: the pickle opcode VM (every opcode family through
  the prefix/suffix walkers, blocked globals, the injection predicate, the
  surrogateescape window mapping).
- SusPatternsTailsTest + SusPatternsManagerTailTest: xml/xxe walkers, ldap
  null-byte and quote-splice matchers through the real table patterns
  (WINDOWED_PATTERN_FINDERS), template scan matchers, brace-expansion
  danger, threat helpers, legacy ipv4 decoding, the enhanced-state builder,
  and the manager lifecycle (add/remove bookkeeping, detect() threat shape,
  the decode-budget-exhaustion threat, semantic category mapping, the Quad
  destructuring).

## Bugs found and fixed (byte-exact, with regression tests)

1. **Monitor anomaly cooldown compared raw nanoseconds against a seconds
   cooldown** (Monitor.kt reserveAnomalyEmission): python times the window
   with time.monotonic() (seconds, monitor.py:197); the JVM fed
   System.nanoTime() straight in, making the suppression window 1e9x too
   small - every record re-emitted the anomaly to the agent sink. Fixed with
   the seconds analog. Regression: monitorAnomalyEmissionCooldownReservesPerPattern.
2. **positiveAssertion crashed on longer lookbehind witnesses**
   (RepeatPrefixState.kt): python's `state.text[: -len(witness.text)]`
   yields "" when the witness exceeds the text (negative slice,
   _redos_repeat_prefix_state.py:101); the Kotlin substring threw
   StringIndexOutOfBoundsException. Fixed with the clamp. Anchored by the
   (?<=(X))\\1 corpus shapes.
3. **Unterminated char classes crashed the structure scanners**: python's
   reversed slices (`pattern[i+1:j-1]`) yield "" for a bare "["
   (_redos_unreachable_terminator.py:77, _redos_structure_rules.py:58,
   _redos_structure_primitives.py); the Kotlin substring threw. Guarded at
   all five sites (UnreachableTerminator x2, StructureRules x2,
   StructurePrimitives x1).
4. **JsonMini coerced parsed JSON nulls to ""** (ValidationCache.kt):
   python's json.loads preserves None and the load() shape checks reject a
   file with a null reason; the JVM accepted it as the empty string. A
   sentinel now preserves the null (cache-corruption contract).
5. **Atom-position 3-digit octal escapes parsed as group references**
   (PyReParser.kt): "\\\\101" (octal 65 = 'A') became group reference 10
   because the third-digit check peeked PAST the unconsumed digit
   (python's source.next is the char at the read position,
   sre_parse.py _escape). Fixed to peek().
6. **Overflowed brace-quantifier bounds silently became {0,0}**
   (PyReParser.kt parseQuantifier): "x{99999999999}" must raise the
   repetition-number-too-large error (python MAXREPEAT check); the overflow
   flag only ran when parseDecimal returned null, but the overflow result
   carries parsed=false with a non-null Dec. Fixed.

## The fail-closed 100 percent line gate

`scripts/enforce_line_coverage.sh` + `scripts/enforce_line_coverage.py`
(the guard-core-rs enforce_line_coverage.py analog):

1. Downloads jacococli 0.8.15-nodeps if absent, VERIFYING THE SHA256
   (d2b74b20b415163c1f53261e7c5ef4445b788327094208ff821e0c2baf9bc8f1);
   a mismatch aborts the gate.
2. Runs `./gradlew test` (every module).
3. Merges ALL exec files against ALL modules' kotlin classes via jacococli
   (the merged method is load-bearing: per-module reports undercount
   cross-JVM execution).
4. `enforce_line_coverage.py` fails (exit 1) unless the workspace total AND
   every module hold 100.0 percent covered lines, printing the
   uncovered-line ranges per class, attributed per module, on failure.
   JaCoCo excludes in the build config are only acceptable for genuinely
   unreachable arms and must carry a written reason next to the exclude.

Seeded-regression proof (run this wave): with
ValidationCacheTest.kt removed, the engine test task stays green but the
gate exits 1 and its report pins the exact uncovered lines:

    guard-core-engine: covered 6737, missed 670, 90.9545% (threshold 100.00%)
    [guard-core-engine] com/guardcore/engine/detection/ValidationCache.kt
        lines: 45-46, 74, 87, 123-129, 131, 141-145, ...

Restoring the test returns the engine to 91.68% (616 missed) and drops the
class from the report. The gate catches a dropped/decayed test even when the
test TASK stays green.

## ci.yml wiring (lands when the numbers hold)

The gate is NOT wired into ci.yml in this wave: the workspace is at 90.76%,
and a red gate on master is worse than a missing gate. The follow-up wave
closes the remaining 2,160 lines (the facade worklist in docs/w9a-coverage.md,
the conformance runner arms, and the engine tail below), then adds one job to
ci.yml, byte-for-byte:

    coverage:
      name: coverage (100 percent line gate)
      runs-on: ubuntu-latest
      permissions:
        contents: read
      steps:
        - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
          with:
            persist-credentials: false
        - uses: actions/setup-java@de727f081f381c8f8158605e0321c36c376e2e6 # v6.0.1
          with:
            distribution: temurin
            java-version: 17
        - name: Start Redis
          run: |
            docker run -d --name guard-redis -p 6379:6379 redis:8
            for i in $(seq 1 30); do
              if docker exec guard-redis redis-cli ping | grep -q PONG; then break; fi
              sleep 1
            done
        - name: Fail-closed 100 percent line-coverage gate
          run: scripts/enforce_line_coverage.sh
        - name: Stop Redis
          if: always()
          run: docker rm -f guard-redis || true

plus `coverage` added to the required contexts and to the paths filter.

## Residual engine tail (per-class, from the W9b merged run)

- engine/detection 258: ParseSlots 40 (repeat-slot shapes), AmbiguousTail 34
  (parseFlatQuantifiedAtomsWithText brace/variability arms), ReachProbe 27,
  ClassIntersection 25 (the crossing walk needs class-feeding-class table
  shapes), StructurePrimitives 14, CostArbiter 14 (the batching/timing-
  strategy arms need >=128 builder sets), Base64Decode 13, Compiler 12,
  UnreachableTerminator 11, IgnorecaseFold 10, Monitor 9, PrefixHistory 5.
- engine/py 153: PyAst 74 (expression-grammar corners the corpus never
  parses), PyRe 70 (the scoped-emitter arms need (?-i:...) scopes holding
  anchors/branches/asserts - compile-verified this wave, the match arms
  remain), PyReParser 29 (the inline-flag group arms), PyUnicode 12.
- engine/suspatterns 202: Manager 76 (the multi-view aggregation arms),
  XmlXxe 38 (publicRunBounds/candidateSpan table shapes), Pickle 29,
  FileUploadTemplates 24, Matchers 19.
