package com.guardcore.engine.suspatterns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The per-request scan time budget: CPU time of the worker that runs the scan. */
class ScanTimeBudgetTest {
  private fun config(): DetectionConfigView =
      object : DetectionConfigView {
        override val detectionCompilerTimeout: Double = 5.0
        override val detectionMaxTrackedPatterns: Int = 1000
        override val detectionMaxContentLength: Int = 10000
        override val detectionPreserveAttackPatterns: Boolean = true
        override val detectionAnomalyThreshold: Double = 3.0
        override val detectionSlowPatternThreshold: Double = 0.1
        override val detectionMonitorHistorySize: Int = 1000
        override val detectionAnomalyEmissionCooldown: Double = 60.0
        override val detectionMinSamplesForAnomaly: Int = 30
        override val detectionSemanticThreshold: Double = 0.7
        override val detectionThreatScoreThreshold: Double = 1.0
        override val detectionMaxBodyInspectBytes: Int = 262144
        override val detectionPatternValidationCachePath: String? = null
      }

  @Test
  fun anExhaustedBudgetRecordsAWeightedTimeoutThreatAndFailsClosed() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      val result = manager.detect("hello world", "203.0.113.7", scanBudget = ScanTimeBudget(0.0))
      // like a per-pattern timeout, every scanned view records one
      val budgetThreats = result.threats.filter { it.pattern == SCAN_TIME_BUDGET_EXHAUSTED_PATTERN }
      assertTrue(budgetThreats.isNotEmpty())
      for (budgetThreat in budgetThreats) {
        assertEquals("pattern_timeout", budgetThreat.type)
        assertEquals("custom", budgetThreat.category)
        assertTrue(budgetThreat.weight > 0.0)
      }
      assertTrue(SCAN_TIME_BUDGET_EXHAUSTED_PATTERN in result.timeouts)
      assertTrue(result.isThreat, "a spent budget must fail closed")
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun aBudgetWithRoomChargesCpuTimeAndFlagsNothing() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      val budget = ScanTimeBudget(10.0)
      val wallStart = System.nanoTime()
      val result = manager.detect("hello world", "203.0.113.7", scanBudget = budget)
      val wallSeconds = (System.nanoTime() - wallStart) / 1e9
      assertFalse(result.isThreat)
      assertFalse(budget.exhausted())
      assertTrue(budget.spentSeconds > 0.0, "the worker's CPU time is charged")
      assertTrue(budget.spentSeconds <= wallSeconds, "CPU time never exceeds the wall time here")
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun noBudgetMeansNoCap() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      val result = manager.detect("hello world", "203.0.113.7")
      assertTrue(result.threats.none { it.pattern == SCAN_TIME_BUDGET_EXHAUSTED_PATTERN })
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun theCpuClockIsReadASmallConstantNumberOfTimesPerPass() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      var reads = 0
      var wallReads = 0
      val budget =
          ScanTimeBudget(
              60.0,
              cpuClock = { reads++.toLong() },
              wallClock = { wallReads++.toLong() },
          )
      manager.detect("hello world", "203.0.113.7", scanBudget = budget)
      assertTrue(wallReads > 100, "the table has many patterns ($wallReads checked)")
      assertTrue(reads in 2..12, "CPU clock read $reads times over $wallReads patterns")
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun aLongPassStopsAtTheBudgetWithinAboutOneSlice() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      // Every pattern costs 1 ms on a fake clock shared by wall and CPU; the cap is 50 ms.
      var nowNanos = 0L
      val budget =
          ScanTimeBudget(
              0.05,
              cpuClock = { nowNanos },
              wallClock = {
                nowNanos += 1_000_000L
                nowNanos
              },
          )
      val result = manager.detect("hello world", "203.0.113.7", scanBudget = budget)
      assertTrue(SCAN_TIME_BUDGET_EXHAUSTED_PATTERN in result.timeouts)
      assertTrue(budget.spentSeconds >= 0.05, "spent ${budget.spentSeconds}")
      assertTrue(
          budget.spentSeconds <= 0.05 + 0.002 + 0.001,
          "overshoot beyond one slice plus one pattern: ${budget.spentSeconds}",
      )
    } finally {
      manager.configure(null)
    }
  }
}
