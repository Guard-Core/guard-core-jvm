package com.guardcore.conformance

import com.guardcore.handlers.BehaviorRule
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * W9h batch 6: the last harness tails - the cost-budget baseline guard and the process-response
 * behavioral hook over a return-pattern route.
 */
class HarnessArmsW9hTest {
  /** runAll's verdict-drift guard (CostBudgetRunner.kt:160). */
  @Test
  fun `cost budget runner rejects a drifted baseline verdict`() {
    val root = java.nio.file.Files.createTempDirectory("w9h-cost-baseline")
    // The recorded expectation says THREAT; plain prose is not a threat -> the drift
    // check fires with its lazy message (160).
    root
        .resolve("index.json")
        .writeText(
            """{"suites": {}, "config_knobs": {}, "fixed_ip": "203.0.113.1",
           "cost_budgets": {"k": 1.0, "floor_ms": 0.0, "budgets": {
             "cost_prose_8kib": {"reference_ms": 1.0, "expected_is_threat": true}}}}""",
        )
    root
        .resolve("cost_bodies.json")
        .writeText(
            """{"cases": [{"id": "cost_prose_8kib",
             "input": {"content": "plain prose body for the baseline workload", "context": "body"}}]}""",
        )
    val error = assertFailsWith<IllegalStateException> { CostBudgetRunner.runAll(root) }
    assertTrue(
        error.message!!.contains("verdict drifted from the recorded expectation"),
        error.message,
    )
  }

  /** The process_response behavioral hook over a behavior_rules route (569-570). */
  @Test
  fun `process response drives the route behavioral hook`() {
    val case =
        mapOf(
            "routes" to
                mapOf(
                    "/api" to
                        mapOf<String, Any?>(
                            "behavior_rules" to
                                listOf(
                                    mapOf<String, Any?>(
                                        "rule_type" to "return_pattern",
                                        "threshold" to 1,
                                        "pattern" to "status:200",
                                    ),
                                ),
                        ),
                ),
            "drives" to
                listOf(
                    mapOf<String, Any?>(
                        "stage" to "process_response",
                        "url_path" to "/api",
                        "client_ip" to "203.0.113.9",
                        "response_status" to 200,
                        "response_body" to "ok",
                    ),
                ),
        )
    val observed = PipelineHarness.runCase(case)
    assertTrue(observed.isNotEmpty())
  }
}
