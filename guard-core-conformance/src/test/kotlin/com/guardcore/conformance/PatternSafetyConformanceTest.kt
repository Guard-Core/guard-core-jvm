package com.guardcore.conformance

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W5 pattern-safety gate: all 94 safety_gates cases replayed through the ported safety chain
 * (dangerous-construct gate, python-re compile gate, structural prefilters, test-string probe,
 * reach-probe cost arbiter).
 *
 * Fail-closed ledger semantics (conformance/jvm_safety_xfail.json), mirroring the family policy: a
 * failing case NOT listed is red; a listed case that now reproduces the reference verdict is red
 * (stale baseline); a listed case whose observed divergent verdict no longer matches the recorded
 * one is red (drifted entry). The six listed entries are cost-verdict-mode timing facts: the
 * extrapolated probe cost is measured on THIS engine's executor, and java.util.regex's relative
 * speed on the synthesized probe sets differs from the reference's python re on both directions
 * (two under-budget accepts where the reference rejects, four over-budget rejects where the
 * reference accepts). Every structural/compile/dangerous/test-string verdict matches the corpus
 * exactly.
 */
class PatternSafetyConformanceTest {
  public data class LedgeredOutcome(
      val boundary: Boolean,
      val observedSafe: Boolean,
      val observedClass: String,
  )

  public companion object {
    private const val LEDGER_RESOURCE = "/jvm_safety_xfail.json"

    public fun loadLedger(): Map<String, Pair<String, LedgeredOutcome>> {
      val text =
          PatternSafetyConformanceTest::class
              .java
              .getResourceAsStream(LEDGER_RESOURCE)
              ?.bufferedReader()
              ?.readText() ?: error("missing $LEDGER_RESOURCE")
      val obj = Json.parseToJsonElement(text).jsonObject
      return obj.getValue("cases").jsonObject.entries.associate { entry ->
        val raw = entry.value.jsonPrimitive.content
        val sep = raw.indexOf(" :: ")
        check(sep > 0) { "ledger entry ${entry.key} malformed: missing ' :: ' separator" }
        val observed = raw.substring(0, sep)
        val reason = raw.substring(sep + 4)
        val boundary = observed.startsWith("boundary ")
        val verdict = if (boundary) observed.removePrefix("boundary ") else observed
        val parts = verdict.split(",")
        check(parts.size == 2) { "ledger entry ${entry.key} malformed observed verdict" }
        check(parts[0].startsWith("safe=")) {
          "ledger entry ${entry.key} malformed observed safe"
        }
        Pair(
            entry.key,
            Pair(
                reason,
                LedgeredOutcome(
                    boundary,
                    parts[0].substringAfter("=").toBooleanStrict(),
                    parts[1].removePrefix("reason_class="),
                ),
            ),
        )
      }
    }

    /**
     * Runs every safety case under the fail-closed ledger; returns per-case failures (empty = all
     * match the corpus or are ledgered with their recorded divergence). A boundary entry accepts
     * either the reference verdict or the recorded divergent verdict (ordinary host load-factor
     * movement flips it between the two); any third verdict is red.
     */
    public fun runAll(): List<PatternSafetyRunner.CaseFailure> {
      val ledger = loadLedger()
      val result = PatternSafetyRunner.runAll()
      val failures = ArrayList<PatternSafetyRunner.CaseFailure>()
      val ledgered = HashSet<String>()
      for (failure in result.failures) {
        val key = "safety_gates/${failure.caseId}"
        val entry = ledger[key]
        when {
          entry == null ->
              failures.add(
                  PatternSafetyRunner.CaseFailure(
                      failure.caseId,
                      failure.reason +
                          " (unledgered divergence: list it in jvm_safety_xfail.json with a " +
                          "written reason or fix the chain)",
                  ),
              )
          else -> {
            val (reason, observed) = entry
            ledgered.add(key)
            if (!observed.boundary) {
              val actual = LedgeredOutcome(false, failure.observedSafe, failure.observedClass)
              if (
                  actual.observedSafe != observed.observedSafe ||
                      actual.observedClass != observed.observedClass
              ) {
                failures.add(
                    PatternSafetyRunner.CaseFailure(
                        failure.caseId,
                        "ledgered divergent verdict drifted; ledger records " +
                            "safe=${observed.observedSafe},reason_class=${observed.observedClass} " +
                            "($reason); observed safe=${actual.observedSafe}," +
                            "reason_class=${actual.observedClass}",
                    ),
                )
              }
            }
          }
        }
      }
      for (key in ledger.keys) {
        if (key !in ledgered) {
          val boundary = ledger[key]!!.second.boundary
          if (boundary) continue // a boundary case legitimately lands on the reference verdict
          failures.add(
              PatternSafetyRunner.CaseFailure(
                  key.substringAfter('/'),
                  "listed in jvm_safety_xfail.json but no longer diverges from the reference " +
                      "verdict (stale baseline): remove the entry",
              ),
          )
        }
      }
      return failures
    }

    public fun caseCount(): Int = PatternSafetyRunner.loadCases().second.size
  }

  @Test
  fun patternSafetyMatchesCorpus() {
    val failures = runAll()
    val count = caseCount()
    if (failures.isNotEmpty()) {
      fail(
          "pattern_safety conformance drift: ${failures.size} divergences over $count cases\n" +
              failures.joinToString("\n") { "  ${it.caseId}: ${it.reason}" },
      )
    }
    assertEquals(94, count, "safety_gates case count drift")
    println(
        "pattern_safety conformance gate: ${count - loadLedger().size} passed, " +
            "${loadLedger().size} ledgered timing facts, $count cases",
    )
  }
}
