# W2 Detection Engine Parity (guard-core-jvm)

Wave 2 ports the detection engine: the regex compiler, semantic analyzer, preprocessor,
monitor, the full `_redos_*` static-safety chain, and the SusPatterns pattern tables, into
`guard-core-engine` (kotlin-stdlib only, no frameworks), proven by the corpus detect suites
going green under a fail-closed pattern translation ledger.

## Gate results (this PR)

| Gate | Result |
|---|---|
| Detect suites (193 cases, 13 files) | GREEN - 193/193 match the corpus under the index.json comparison contract (6-decimal floats, sorted-canonical threat multisets, execution_time dropped, fixed IP 203.0.113.7, the 12 detection config_knobs replayed through the W1 SecurityConfig) |
| Pattern translation ledger | `conformance/pattern_ledger.json`: 158 entries - 158 as_is, 0 translated, 0 unmatchable; the fail-closed gate test (`PatternLedgerTest`) fails CI on any corpus/table pattern missing from the ledger or drifting in status |
| Redos chain unit tests | `RedosChainTest`, `CompilerRedosTest`, `PyReBehaviorTest`, `PyAstTest` - structural detectors, interval algebra, literal runs, class intersection, stray chooser, probe synthesis, arbiter verdict classes, hard-deadline abort, python-grammar fail-closed rejection, python-expression validator |
| Engine unit tests | `SusPatternsUnitTest` (monitor stats/anomalies, base64 view, preprocessor decoders/truncation), `PyReScratchTest`, `TableCompileTest` (all 157 table rows compile under the python-grammar oracle) |

## Python -> Kotlin module map

Anchor lines are the Kotlin declarations; python references are the source files. All
python paths relative to `guard_core/`, Kotlin paths relative to
`guard-core-engine/src/main/kotlin/com/guardcore/engine/`.

### Regex compatibility layer (new surface: JVM analog of CPython `re`/`sre`)

| python | kotlin | notes |
|---|---|---|
| (CPython `re._parser` grammar) | `py/PyReParser.kt` | python-grammar fail-closed parser producing the sre AST: ReParseError carries the reference's message classes ("unbalanced parenthesis", "multiple repeat", "nothing to repeat", "invalid group reference N", "redefinition of group name", "global flags not at the start", "unknown extension ?>", nesting-depth cap 20). Atomic groups and possessive quantifiers reject fail-closed (python 3.10 oracle). |
| (CPython `re._compile` + stdlib flags) | `py/PyRe.kt` | `translateSource` (\Z->\z, (?P<->(?<, (?P=->\k<name>, \g<n>->\n, {,n}->{0,n}, python-literal `{` escaped, (?-i:...) hoisted to scoped positive flags with the CI flag re-applied per segment); flag map: IGNORECASE->CASE_INSENSITIVE|UNICODE_CASE, MULTILINE, DOTALL, VERBOSE->COMMENTS, ASCII->(nothing), else UNICODE_CHARACTER_CLASS; UNIX_LINES always (python `.` excludes only \n, `$` anchors only at \n). `PyReMatch` snapshots groups (the java Matcher is mutable across find() iterations). `matchSubstring` = python pattern.match(slice) with anchoring bounds; `matchAt` = pattern.match(s, pos, endpos) with transparent bounds (CPython lookbehind sees before pos). |
| (CPython `ast.parse(mode="eval")`) | `py/PyAst.kt` | python-expression validator for SemanticAnalyzer._check_ast_parsing_risk: recursive-descent over the eval-mode grammar (lambda, conditional, boolean/comparison/arithmetic, displays, comprehensions, calls, subscripts, f-strings); assignments/statements reject. |
| (thread with large stack) | `py/RegexWorkers.kt` | `shared_regex_executor` analog (compiler.py:20-38, 4 workers). The pool carries 512 MiB stacks: java.util.regex recurses per group-repetition iteration, and the corpus's 256 KiB workloads drive ~256k nested frames through the table's negated-newline-star scans. `detect()` and `reachProbeCostVerdict` each take one worker hop; matches inside run inline. |

### ReDoS static-safety chain (25 `_redos_*` modules + cache)

| python (`detection_engine/`) | kotlin (`detection/`) | status |
|---|---|---|
| `_redos_intervals.py` | `IntervalSet.kt` | full: normalize/union/intersection/complement/difference, first_member, component_first_members, cached_category_intervals |
| `_redos_ignorecase_fold.py` | `IgnorecaseFold.kt` | full: union-find fold groups over the whole code-point space, member-scan and group-scan expansion, ascii_only partner filter |
| `_redos_parse_slots.py` | `ParseSlots.kt` | full: PairingAtom/NonPairingSlot model, node_intervals, category predicates (ascii + unicode), class-node predicate cache, candidate_chars_for_atom_text |
| `_redos_structure_primitives.py` | `StructurePrimitives.kt` | full: skip_char_class, strip_escapes_and_char_classes, find_group_end, transparent-wrapper unwrap, alternation splitting, quantified-group iterator with the depth-20 cap |
| `_redos_structure_rules.py` | `StructureRules.kt` | full: nested-unbounded and adjacent-broad-unbounded detectors, broad atom spans ([SWD shorthand, negated-class, dot), NESTING_DEPTH_REJECTION_REASON verbatim |
| `_redos_structure.py` | (re-export shim in python; merged into `StructureRules.kt`/`StructurePrimitives.kt`) | full surface ported |
| `_redos_unreachable_terminator.py` | `UnreachableTerminator.kt` | full: prefix-reset/escape/group-open/broad-scan steps, terminator-char analysis, finding text format verbatim |
| `_redos_ambiguous_tail.py` | `AmbiguousTail.kt` | full: flat quantified-atom parse (shape and text forms), ambiguous-pair/cyclic-neighbor checks, representative char probing, extract_literal_chars |
| `_redos_literal_in_wildcard.py` | `LiteralInWildcard.kt` | full: wildcard-absorbs-literal detection |
| `_redos_structural_prefilters.py` | `StructuralPrefilters.kt` | full: 3 dangerous-construct regexes + the 5-check structural chain, message prefixes verbatim |
| `_redos_exact_state.py` | `ExactState.kt` | full: exact-state narrowing, isolated group state, MAX_GROUP_CROSSING_DEPTH 16 |
| `_redos_literal_runs.py` | `LiteralRuns.kt` | full: adversarial literal-run walker (class steps, group open/close, escape quantifier steps) |
| `_redos_stray_chooser.py` | `StrayChooser.kt` | full: leading literal prefix, fill_to_length, repeat_probe_to_length, class-intersection and repeat-unit stray selection; the killable-subprocess verification is replaced by inline verification under the hard deadline (the JVM analog - PatternValidationTimeout carries the reference's TimeoutError semantics and message texts) |
| `_redos_class_intersection.py` | `ClassIntersection.kt` | full: pairing-chain walking, group crossing, exact-state fills, bounded-repeat widening |
| `_redos_prefixed_probe.py` | `PrefixedProbe.kt` | full: prefixed_repeat_probe, prefixed/group unit builders with the 4096/8192 budgets |
| `_redos_prefix_history.py` | `PrefixHistory.kt` | full: history-observability analysis (AT/anchors, backrefs, capture flags) |
| `_redos_repeat_prefix_state.py` | `RepeatPrefixState.kt` | full: RepeatPrefixState, consume_piece/atom, capture_state, positive/negative assertion merging, 24000/1024/16384/2000000 budgets |
| `_redos_repeat_lookbehind.py` | `RepeatLookbehind.kt` | full: negative lookbehind mutation and alphabet alternatives |
| `_redos_repeat_prefix.py` | `RepeatPrefix.kt` | full: PrefixWalk over the sre AST (repeat/branch/group/assertion/backreference/conditional handlers), record_prefixes, pending_repeats, repeat_reaching_prefixes |
| `_redos_repeat_alphabet.py` | `RepeatAlphabet.kt` | full: alphabet atom collection, constraint splitting, large-bounded-repeat detection (limit 4096) |
| `_redos_repeat_units.py` | `RepeatUnits.kt` | full: repeat-group unit pairs with 4096/1000000 budgets |
| `_redos_probe_batches.py` | `ProbeBatches.kt` | full: sha256 probe-set digest, timing-row validation, batched measurement (the batch subprocess becomes a batched inline call; yield order preserved) |
| `_redos_probe_fill.py` | `ProbeFill.kt` | full: all builder families (repeat fills, class intersection, prefixed, group, literal runs, prefix cuts, ambiguous group fills) |
| `_redos_reach_probe.py` | `ReachProbe.kt` | full: reaching-probe synthesis with the 12000 budget, group-text backreferences, flag-scoped group skipping, stress-fill clamps |
| `_redos_cost_arbiter.py` | `CostArbiter.kt` | full: host load factor via the reference scan timed with thread CPU time (`time.process_time` analog via ThreadMXBean), scaled deadline, verdict-from-samples math (identical formula and 0.05s budget), reason texts verbatim, retry-on-over-budget, stride sampling to 512 sets, batching above 128 builders. The probe-timing subprocess becomes in-process timing under the DeadlineCharSequence hard deadline. |
| `_validation_cache.py` | `ValidationCache.kt` | full: disk cache keyed by pattern+flags+engine version, atomic tmp-replace save, corrupt-cache tolerance |

### Detection engine core

| python (`detection_engine/`) | kotlin (`detection/`) | status |
|---|---|---|
| `compiler.py` | `Compiler.kt` | full: PatternCompiler (LRU cache capped at 5000, default timeout, compile/compile_pattern_sync, validate_pattern_safety with test-string probe / cost-verdict branches and validation-cache wiring, create_safe_matcher/create_safe_finditer_matcher with deadline aborts, batch_compile, clear_cache); report_scan_success/timeout counters |
| `preprocessor.py` | `Preprocessor.kt` + `py/PyUrllib` (unquote errors=ignore) + `py/PyHtml` (html.unescape) | full: normalize_unicode NFKC + 25 lookalikes, decode_common_encodings 16-iteration loop with the exact decoder order and gunzip budget, remove_null_bytes, remove_excessive_whitespace, strip_sql_comments, preprocess_with_decoded/signal_preserving/url_decoded_newline_preserving/short_base64_additive_view/batch. The agent-event seam is a no-op (no agent handler in the engine module; the facade wires telemetry in W4) |
| `truncation.py` | `Truncation.kt` | full: extract_attack_regions (25 indicators, per-scan deadline, +/-100 windows, merge, max_regions), cap_with_tail (4096 tail), extract_and_concatenate, build_result_with_attack_regions_and_context gap budget |
| `base64_alphabet.py` | `Base64.kt` | full: data/separator/widened sets incl. the surrogateescape range (U+DC80..U+DCFF), urlsafe translate |
| `base64_decode.py` | `Base64Decode.kt` | full: BASE64_RE/RUN_RE/SUB_FLOOR_RUN_RE built from the same interpolated class bodies, hex-literal skip, urlsafe translate + stripped retry, printable-ratio gates (0.5/0.95/0.2), bounded_gunzip with 8192 output cap and 8-attempts-per-pass budget, sub-floor reassembly |
| `base64_view.py` | `Base64View.kt` | full: short-token decode (4..11), marker-char qualification, 20000-candidate cap, newline join |
| `encoding_decoders.py` | `EncodingDecoders.kt` | full: hex/unicode/percent-u decoders, overlong UTF-8 percent-run decoding with the lead-byte spec table |
| `scan_window.py` | `ScanWindow.kt` | full: bounded_finditer/bounded_search over live prefixes to the farthest reachable terminator |
| `binary_prefix.py` | `Binary.kt` (BinaryPrefix) | full: artifact class verbatim (incl. surrogateescape), prefix table, density radius 64 / limit 4 |
| `binary_islands.py` | `Binary.kt` (BinaryIslands) | full: island run class, value_is_binary_like 0.2 ratio, extract_binary_islands |
| `semantic.py` | `Semantic.kt` | full: looks_like_binary_content (0.2), keyword maps, attack structures, token extraction (50000/1000 caps), entropy, encoding layers, obfuscation, structural boosts, suspicious patterns, code-pattern/ast/injection risks (the ast branch validates against `PyAst.parsesAsExpression` under the same 0.1s thread budget with the 0.3/0.2/0.0 outcomes), analyze/get_threat_score formulas verbatim |
| `monitor.py` + `monitor_types.py` + `monitor_anomalies.py` + `monitor_reporting.py` | `Monitor.kt` | full: PerformanceMonitor (all 6 clamped options), record_metric (100-char truncation, recent-times window, avg/max/min), timeout/slow/statistical anomaly detection (Kahan-fsum analog of math.fsum), sanitize_anomaly_data, pattern reports/slow/problematic collections, summary dict; the agent-send seam notifies registered callbacks only (telemetry sink lands in W4) |
| `__init__.py` | re-exports in each Kotlin file + `Semantic.kt` (looks_like_binary_content) | full |

### SusPatterns surface

| python (`handlers/`) | kotlin (`suspatterns/`) | status |
|---|---|---|
| `_suspatterns_sources.py` | `SusPatternsSources.kt` | full: every source constant byte-identical to the python values (verified against the reference module by regenerating literals from it), context sets, category maps, regex_anomaly, recon path gates |
| `_suspatterns_state.py` | `SusPatternsState.kt` | full: DetectionState, LEGACY_DETECTION_STATE, build_enhanced_detection_state (all 11 knobs + cache path), the 208-entry HTML event-handler set with the longest-first alternation |
| `_suspatterns_regex.py` | `SusPatternsManager.kt` (check paths + threat builders) | full: candidate rejection validators (12 entries in reference order), windowed finders (6), scan-window bounds (10 pairs) + xml special cases, build_regex_threat (recon/noise gates, sanitize_for_reporting), build_timeout_threat, first_accepted, context normalization, per-view filtering, binary-prefix gate, monitor metric per pattern |
| `_suspatterns_views.py` | `SusPatternsManager.kt` (view methods) | full: raw/url-decoded/decoded-traversal/short-base64 views, legacy traversal decode path, view-dedup merge (drop_view_duplicate_threats) |
| `_suspatterns_enhanced.py` | `SusPatternsManager.kt` (configure/preprocess/semantic/score) | full: configure state swap, _preprocess_content with per-call preprocessor, semantic threats with threshold/probability gates, calculate_threat_score |
| `_suspatterns_registry.py` | `SusPatternsManager.kt` (add/remove/get) | full: validate-then-add with the max-body-inspect cap, custom/default tables, remove with cache clearing |
| `_suspatterns_matchers.py` | `SusPatternsMatchers.kt` | full: shell -c assignment-prefix walk, ldap null-byte attr/value walkers, quote-splice walker, load-file and dollar-substitution windows, template scan matchers, brace-expansion checker, pickle-global chain/run walkers |
| `_suspatterns_file_upload.py` | `SusPatternsFileUploadTemplates.kt` (SusPatternsFileUpload) | full: extension sets + php\d* alternations (sorted -len,name), filename-equals prefix, 4 pattern rows, scan window, match-start walk, double-extension/truncation/decoded-truncation kind checks, scan matches |
| `_suspatterns_templates.py` | `SusPatternsFileUploadTemplates.kt` (SusPatternsTemplates) | full: region scanning, keyword/expression matchers, date-avoidance, frame construction |
| `_suspatterns_shell_sources.py` + `_suspatterns_shell_validators.py` | `SusPatternsShell.kt` | full: scan-window matcher table, raw/url-decoded view source sets, glued backtick/dollar patterns, strong-SQL keyword glues, backtick window/context/metacharacter analysis, dollar-substitution implausibility, quote-splice run counting, glob wildcard word-shape and boundary prefix |
| `_suspatterns_xml_xxe.py` | `SusPatternsXmlXxe.kt` | full: system/internal-entity walkers, quote-completion precompute, public-run bounds, candidate spans |
| `_suspatterns_pickle.py` | `SusPatternsPickle.kt` | full: the pickle opcode walker over the prefix/suffix windows with the 4096-byte budget, surrogateescape window mapping, REDUCE/BUILD reachability; the python pickle._Unpickler dispatch is modeled as an explicit opcode table (shape validation only - find_class/persistent_load paths raise, mirroring the blocked-resolution exceptions) |
| `_suspatterns_pattern_table.py` | `SusPatternsTable.kt` | full: all 157 _PATTERN_DEFINITIONS rows byte-identical to the reference values (each constant regenerated from the python module to eliminate transcription drift; verified by a dump-diff against `_PATTERN_DEFINITIONS`), NOISE_PRONE/RECON_OPTIONAL/RECON_RAW_VIEW source sets |
| `suspatterns_handler.py` | `SusPatternsManager.kt` (detect) | full: the detect() pipeline - preprocess, main/raw/url-decoded/decoded-traversal/short-base64 views in reference order, dedup merge, semantic threats, anomaly scoring, threat-score calc, detection_method; suspend->blocking is the recorded JVM idiom (the facade adds coroutine bridges in W4) |

## Idiom mappings (syntax, not substitutes)

1. **asyncio -> blocking engine + worker hop**: python's async detect and the shared regex
   executor map to a synchronous `detect()` executed on one 512 MiB-stack scan-pool worker.
   Coroutine bridges land in the facade (W4) per the work order's unasync ruling.
2. **killable subprocess -> hard deadline**: the reference times probes and verifies strays
   in killable subprocesses; the JVM analog is the DeadlineCharSequence abort
   (`PyRe.DeadlineExceededException` carries the reference's TimeoutError semantics and the
   reason strings name the same classes: "killable-subprocess timeout" texts kept verbatim
   for ledger comparability).
3. **sre internals -> PyReParser/PyAst**: python's re._parser grammar and ast.parse(mode=
   "eval") are CPython-internal; the JVM ports reproduce the accept/reject oracle
   fail-closed (ReParseError message classes verbatim; PyAst = eval-mode expression grammar).
4. **pickle._Unpickler -> opcode table**: the blocked-resolution exceptions map to explicit
   raises in the modeled dispatch; a raise means "not a provable opcode stream" exactly as
   the reference's exception-to-False conversions.

## Verification

- 193/193 detect cases green (`DetectConformanceTest`), config knobs replayed through the
  W1 `SecurityConfig` via `DetectRunner.configFromKnobs`.
- Table rows byte-verified against the reference: a dump-diff of
  `SusPatternsTable.PATTERN_DEFINITIONS` against python `_PATTERN_DEFINITIONS` (157 rows,
  source + category) shows zero diffs.
- Ledger: `conformance/pattern_ledger.json` (158 entries, 158 as_is) enforced fail-closed by
  `PatternLedgerTest` - a stray pattern or a status drift fails CI.
- Unit ports: `RedosChainTest`, `CompilerRedosTest`, `PyReBehaviorTest`, `PyAstTest`,
  `SusPatternsUnitTest`, `PyReScratchTest`, `TableCompileTest`.
