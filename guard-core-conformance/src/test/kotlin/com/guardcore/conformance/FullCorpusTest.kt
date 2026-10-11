package com.guardcore.conformance

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W5 full-corpus certification gate: ALL 21 suites + the self-relative cost budgets in one
 * command, with a per-suite summary (pass / ledgered / total). Run via
 * `./gradlew :guard-core-conformance:fullCorpusGate`; CI's conformance step runs it.
 *
 * The campaign zero-xfail bar (specs/impl/jvm.md, W5 gate) is expressed here as: detect 193/0,
 * pipeline 35/0, redis_interop 14/0, event_stream 37+2 ledgered reason-string shapes (the TS
 * floor), pattern_safety 88+6 ledgered cost-verdict timing facts, cost budgets all under ceiling
 * with an empty fail-closed manifest. Ledger totals are asserted against the recorded manifests so
 * a silently-growing ledger is red.
 */
class FullCorpusTest {
  public data class SuiteSummary(
      val name: String,
      val total: Int,
      val failures: Int,
      val ledgered: Int,
  )

  @Test
  fun fullCorpusGate() {
    val redis = RedisInteropTest()
    assertTrue(
        redis.redisAvailableForGate(),
        "full corpus gate needs a live Redis on REDIS_URL (localhost:6379) for redis_interop",
    )

    val summaries = ArrayList<SuiteSummary>()
    val lines = ArrayList<String>()

    // ---- detect arm: 13 suites, 193 cases ----
    val detectFailures = DetectRunner.runAll()
    for (suite in DetectRunner.detectSuites()) {
      val count = suiteCaseCount(suite)
      val failed = detectFailures.count { it.suite == suite }
      summaries.add(SuiteSummary(suite, count, failed, 0))
    }

    // ---- pipeline arm: 5 suites, 35 cases ----
    val pipelineFailures = PipelineConformanceTest.runAll()
    for (suite in PipelineConformanceTest.pipelineSuites()) {
      val count = suiteCaseCount(suite)
      val failed = pipelineFailures.count { it.suite == suite }
      summaries.add(SuiteSummary(suite, count, failed, 0))
    }

    // ---- events arm: 39 cases, 2 ledgered reason-string shapes (the TS floor) ----
    val eventsLedger = EventsConformanceTest.loadLedger()
    val eventsFailures = EventsConformanceTest.runAll()
    for (suite in EventsConformanceTest.eventsSuites()) {
      val count = suiteCaseCount(suite)
      val failed = eventsFailures.count { it.suite == suite }
      summaries.add(SuiteSummary(suite, count, failed, eventsLedger.size))
    }

    // ---- redis arm: 14 cases ----
    val redisFailures = redis.runAll()
    summaries.add(SuiteSummary("redis_interop", suiteCaseCount("redis_interop"), redisFailures.size, 0))

    // ---- pattern-safety arm: 94 cases, 6 ledgered cost-verdict timing facts ----
    val safetyLedger = PatternSafetyConformanceTest.loadLedger()
    val safetyFailures = PatternSafetyConformanceTest.runAll()
    summaries.add(
        SuiteSummary(
            "safety_gates",
            PatternSafetyConformanceTest.caseCount(),
            safetyFailures.size,
            safetyLedger.size,
        ),
    )

    // ---- cost budgets: 9 workloads under self-relative ceilings ----
    val costLedger = CostBudgetConformanceTest.loadCostLedger()
    val cost = CostBudgetRunner.runAll(ledger = costLedger)
    val costFailures = cost.overs.size + cost.staleLedgerEntries.size
    summaries.add(SuiteSummary("cost_budgets", cost.timings.size, costFailures, costLedger.size))

    // ---- summary ----
    val corpusSuites = summaries.filter { it.name != "cost_budgets" }
    val totalCases = corpusSuites.sumOf { it.total }
    val totalFailures = summaries.sumOf { it.failures }
    val totalLedgered = summaries.sumOf { it.ledgered }
    lines.add("")
    lines.add("=== guard-core-jvm full-corpus certification gate (spec 4.1.0, 21 suites) ===")
    for (s in summaries.sortedBy { it.name }) {
      val status = if (s.failures == 0) "ok" else "FAIL"
      val ledger =
          when {
            s.ledgered > 0 -> ", ${s.ledgered} ledgered"
            else -> ""
          }
      lines.add(
          "  %-34s %3d cases, %d failures%s [%s]"
              .format(s.name, s.total, s.failures, ledger, status),
      )
    }
    lines.add(
        "  cost budgets: best8=%.1f ms; %d/%d workloads under self-relative ceiling"
            .format(cost.best8Ms, cost.timings.size - costFailures, cost.timings.size),
    )
    for (line in cost.lines) lines.add("    $line")
    lines.add(
        "  TOTAL: $totalCases cases + 9 budget workloads, $totalFailures failing, " +
            "$totalLedgered ledgered (events 2 reason-string shapes, pattern_safety 6 " +
            "cost-verdict timing facts)",
    )
    println(lines.joinToString("\n"))

    if (totalFailures > 0) {
      val details =
          (safetyFailures.map { "safety_gates/${it.caseId}: ${it.reason}" } +
                  eventsFailures.map { "event_stream/${it.caseId}: ${it.reason}" } +
                  detectFailures.map { "detect/${it.suite}/${it.caseId}: ${it.reason}" } +
                  pipelineFailures.map { "pipeline/${it.suite}/${it.caseId}: ${it.reason}" } +
                  redisFailures.map { "redis_interop/$it" })
              .take(20)
              .joinToString("\n")
      fail("full corpus gate: $totalFailures failing checks\n$details")
    }
    assertEquals(375, totalCases, "full corpus case count drift (21 suites)")
    assertEquals(2, eventsLedger.size, "events ledger must stay at the TS floor (2 entries)")
    assertEquals(6, safetyLedger.size, "pattern_safety ledger must stay at 6 timing facts")
    assertTrue(
        costLedger.isEmpty(),
        "cost ledger must stay empty (every workload under its self-relative ceiling)",
    )
  }

  private fun suiteCaseCount(suite: String): Int {
    val idx = DetectRunner.index()
    return idx
        .getValue("suites")
        .jsonObject
        .getValue(suite)
        .jsonObject
        .getValue("case_count")
        .jsonPrimitive
        .int
  }
}
