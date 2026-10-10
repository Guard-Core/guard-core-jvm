package com.guardcore.conformance

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The W2 detect-suite gate: every case in the 13 detect suites must match the corpus under the
 * index.json comparison contract.
 */
class DetectConformanceTest {
  @Test
  fun detectSuitesMatchCorpus() {
    val failures = DetectRunner.runAll()
    val bySuite = failures.groupBy { it.suite }
    val summary =
        bySuite.entries
            .sortedBy { it.key }
            .joinToString("\n") { (suite, fails) ->
              "  $suite: ${fails.size} failures, e.g. " +
                  fails.take(3).joinToString("; ") { "${it.caseId}: ${it.reason.take(160)}" }
            }
    assertTrue(
        failures.isEmpty(),
        "detect suite failures (${failures.size}):\n$summary",
    )
  }
}
