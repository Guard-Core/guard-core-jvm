package com.guardcore.conformance

import com.guardcore.engine.detection.PatternCompiler
import java.nio.file.Files
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W5 pattern-safety runner: safety_gates.json (94 cases) replayed through the ported
 * PatternCompiler.validatePatternSafety chain, exactly the way the reference oracle drives it
 * (specs/fixtures/tools/generate_safety_gates.py._worker: a fresh PatternCompiler per case;
 * test_strings mode passes the case strings, cost_verdict mode passes max_content_length).
 *
 * The reference oracle is guard_core.detection_engine.compiler.PatternCompiler.
 * validate_pattern_safety, whose verdict classes are the reference's full safety chain: the
 * dangerous-construct gate (_redos_dangerous_constructs), the compile gate (python-re parser), the
 * ordered structural prefilters (_redos_structural_prefilters), the per-string probe
 * (_run_pattern_safety_probe_subprocess analog), and the reach-probe cost arbiter
 * (_redos_cost_arbiter). The JVM engine ships that full chain 1:1 (W2), so the suite runs with the
 * Go family's posture: no divergence may pass silently.
 *
 * Contract (index.json comparison.pattern_safety_records): compare expected.safe and
 * expected.reason_class; the numeric parts of over-budget reason strings are host-measured and
 * never compared (reason_class is still compared exactly).
 */
public object PatternSafetyRunner {
  public data class CaseFailure(
      val caseId: String,
      val reason: String,
      val observedSafe: Boolean = false,
      val observedClass: String = "",
  )

  public data class SuiteResult(
      val total: Int,
      val passed: Int,
      val failures: List<CaseFailure>,
  )

  public data class SafetyCase(
      val id: String,
      val pattern: String,
      val mode: String,
      val testStrings: List<String>?,
      val maxContentLength: Int?,
      val expectedSafe: Boolean,
      val expectedReasonClass: String,
  )

  /** Loads the safety_gates suite file and asserts its registration pins. */
  public fun loadCases(corpus: java.nio.file.Path = DetectRunner.corpusDir()): Pair<String, List<SafetyCase>> {
    val suiteJson =
        Json.parseToJsonElement(Files.readString(corpus.resolve("safety_gates.json"))).jsonObject
    val suite = suiteJson.getValue("suite").jsonPrimitive.content
    val kind = suiteJson.getValue("kind").jsonPrimitive.content
    check(kind == "pattern_safety") { "suite kind drifted: $kind" }
    val cases =
        suiteJson.getValue("cases").jsonArray.map { element ->
          val obj = element.jsonObject
          val input = obj.getValue("input").jsonObject
          val expected = obj.getValue("expected").jsonObject
          SafetyCase(
              id = obj.getValue("id").jsonPrimitive.content,
              pattern = input.getValue("pattern").jsonPrimitive.content,
              mode = input.getValue("mode").jsonPrimitive.content,
              testStrings =
                  input["test_strings"]?.let {
                    it.jsonArray.map { s -> s.jsonPrimitive.content }
                  },
              maxContentLength =
                  input["max_content_length"]?.let { it.jsonPrimitive.int },
              expectedSafe = expected.getValue("safe").jsonPrimitive.boolean,
              expectedReasonClass = expected.getValue("reason_class").jsonPrimitive.content,
          )
        }
    return Pair(suite, cases)
  }

  /**
   * classifySafetyReason mirrors the corpus generator's CLASS_RULES
   * (specs/fixtures/tools/generate_safety_gates.py): the reason string prefix decides the
   * reason_class. Keep byte-identical with the generator table.
   */
  public fun classifySafetyReason(reason: String): String {
    val rules =
        arrayOf(
            Pair("Pattern contains dangerous construct", "dangerous_construct"),
            Pair("Pattern validation failed:", "compile_failed"),
            Pair("Pattern contains nested unbounded quantifier", "structural_nested_unbounded"),
            Pair("Pattern contains adjacent broad unbounded quantifiers", "structural_adjacent_broad"),
            Pair("terminator cannot be reached by", "structural_unreachable_terminator"),
            Pair("absorb the mandatory literal", "structural_literal_absorb"),
            Pair("ambiguous optional tail", "structural_ambiguous_tail"),
            Pair("Pattern timed out on test string", "probe_string_timeout"),
            Pair("probe exceeded the", "probe_subprocess_timeout"),
            Pair("could not construct a test string that", "unreachable_probe"),
            Pair("Pattern extrapolated CPU cost", "over_budget"),
            Pair("probe construction exceeded its deadline", "builder_deadline"),
            Pair("Pattern appears safe", "safe"),
        )
    for ((prefix, cls) in rules) {
      if (reason.contains(prefix)) return cls
    }
    return "other"
  }

  /**
   * Diagnostics only: which ported chain module produced a verdict, with the python anchor. Used
   * in failure output so a divergence names its producer.
   */
  public fun chainModuleOf(reasonClass: String): String =
      when (reasonClass) {
        "dangerous_construct" ->
            "guard-core-engine StructuralPrefilters.dangerousConstructViolation " +
                "(python anchor: _redos_dangerous_constructs._dangerous_construct_violation)"
        "compile_failed" ->
            "guard-core-engine PyReParser " +
                "(python anchor: re.compile via PatternCompiler.compile_pattern_sync)"
        "structural_nested_unbounded",
        "structural_adjacent_broad",
        "structural_unreachable_terminator",
        "structural_literal_absorb",
        "structural_ambiguous_tail" ->
            "guard-core-engine StructuralPrefilters " +
                "(python anchor: _redos_structural_prefilters._first_structural_safety_violation)"
        "probe_string_timeout",
        "probe_subprocess_timeout" ->
            "guard-core-engine PatternCompiler.runPatternSafetyProbe " +
                "(python anchor: compiler._run_pattern_safety_probe_subprocess)"
        "unreachable_probe",
        "builder_deadline",
        "over_budget" ->
            "guard-core-engine CostArbiter/ReachProbe " +
                "(python anchor: _redos_cost_arbiter._reach_probe_cost_verdict)"
        "safe" -> "guard-core-engine full chain, no rejection fired"
        else -> "unclassified reason (no CLASS_RULES prefix matched)"
      }

  /**
   * Runs every safety case through the ported chain; returns the suite result. A case passes when
   * (safe, reason_class) equals the pinned expectation - the raw reason string is never compared,
   * only classified (pattern_safety_records rule).
   */
  public fun runAll(corpus: java.nio.file.Path = DetectRunner.corpusDir()): SuiteResult {
    val (_, cases) = loadCases(corpus)
    check(cases.isNotEmpty()) { "safety_gates corpus matched zero cases: a vacuous pass is a failure" }
    val failures = ArrayList<CaseFailure>()
    var passed = 0
    for (case in cases) {
      // The generator's oracle uses a fresh PatternCompiler per case (no validation cache).
      val compiler = PatternCompiler()
      val (safe, reason) =
          if (case.mode == "test_strings") {
            compiler.validatePatternSafety(case.pattern, testStrings = case.testStrings)
          } else {
            compiler.validatePatternSafety(case.pattern, maxContentLength = case.maxContentLength)
          }
      val gotClass = classifySafetyReason(reason)
      if (safe == case.expectedSafe && gotClass == case.expectedReasonClass) {
        passed += 1
        continue
      }
      failures.add(
          CaseFailure(
              case.id,
              "mode=${case.mode}: got safe=$safe class=$gotClass (reason \"$reason\"), " +
                  "want safe=${case.expectedSafe} class=${case.expectedReasonClass}; " +
                  "producer: ${chainModuleOf(gotClass)}",
              observedSafe = safe,
              observedClass = gotClass,
          ),
      )
    }
    return SuiteResult(cases.size, passed, failures)
  }
}
