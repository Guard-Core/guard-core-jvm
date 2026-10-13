package com.guardcore.conformance

import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * W9i batch 7 (completing): the per-case cost-budget drift guard - the baseline passes so the loop
 * reaches a later workload whose recorded expectation drifted.
 */
class HarnessArmsW9iTest {
  /** runAll's per-workload verdict-drift guard (CostBudgetRunner.kt:160). */
  @Test
  fun `cost budget runner rejects a drifted workload verdict`() {
    val root = java.nio.file.Files.createTempDirectory("w9i-cost-drift")
    // The baseline expectation is honest (plain prose is not a threat), so runAll
    // reaches the per-case loop; the second workload's recorded expectation says
    // THREAT, which fires the loop's drift check with its lazy message (160).
    root
        .resolve("index.json")
        .writeText(
            """{"suites": {}, "config_knobs": {}, "fixed_ip": "203.0.113.1",
           "cost_budgets": {"k": 1.0, "floor_ms": 0.0, "budgets": {
             "cost_prose_8kib": {"reference_ms": 1.0, "expected_is_threat": false},
             "cost_probe_extra": {"reference_ms": 1.0, "expected_is_threat": true}}}}""",
        )
    root
        .resolve("cost_bodies.json")
        .writeText(
            """{"cases": [
             {"id": "cost_prose_8kib",
              "input": {"content": "plain prose body for the baseline workload", "context": "body"}},
             {"id": "cost_probe_extra",
              "input": {"content": "another plain prose workload body", "context": "body"}}]}""",
        )
    val error = assertFailsWith<IllegalStateException> { CostBudgetRunner.runAll(root) }
    assertTrue(
        error.message!!.contains("cost budgets/cost_probe_extra: verdict drifted"),
        error.message,
    )
  }
}
