package com.guardcore.conformance

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * W9d arm closure for the remaining conformance runners: the seeded scratch-corpus error/edge
 * arms for the pattern-safety and cost-budget runners plus the shared classification tables.
 * The pinned corpus under conformance/guard-core-spec-4.1.0/ is never touched.
 */
class RunnerW9dTailsTest {
  private fun writePatternSafetyCorpus(root: Path, cases: String) {
    root
        .resolve("index.json")
        .writeText(
            """{"suites": {"w9d_safety": {"kind": "pattern_safety", "description": "seeded"}},
           "config_knobs": {},
           "fixed_ip": "203.0.113.1"}""",
        )
    root
        .resolve("safety_gates.json")
        .writeText("""{"kind": "pattern_safety", "suite": "seeded", "cases": $cases}""")
  }

  @Test
  fun `pattern safety runner walks the mismatch and classification arms`() {
    val root = Files.createTempDirectory("w9d-safety")
    val cases =
        """
        [
          {"id": "dangerous-mismatch",
           "input": {"pattern": "(a{2,}){2,}", "mode": "compile"},
           "expected": {"safe": true, "reason_class": "safe"}},
          {"id": "safe-ok",
           "input": {"pattern": "'[^']*'", "mode": "test_strings", "test_strings": ["abcdefghij"]},
           "expected": {"safe": true, "reason_class": "safe"}}
        ]
        """
            .trimIndent()
    writePatternSafetyCorpus(root, cases)
    val (suite, loaded) = PatternSafetyRunner.loadCases(root)
    assertEquals("seeded", suite)
    assertEquals(2, loaded.size)
    val result = PatternSafetyRunner.runAll(root)
    assertEquals(2, result.total)
    assertEquals(1, result.passed)
    val failures = result.failures
    assertEquals(listOf("dangerous-mismatch"), failures.map { it.caseId })
    assertTrue(failures[0].reason.contains("mode=compile"), failures[0].reason)
    assertFalse(failures[0].observedSafe)
    // the classifier tables: every prefix class + the unclassified fallback
    assertEquals("safe", PatternSafetyRunner.classifySafetyReason("Pattern appears safe"))
    assertEquals("other", PatternSafetyRunner.classifySafetyReason("no table prefix in this reason"))
    // the chain-module table resolves every known class
    assertTrue(PatternSafetyRunner.chainModuleOf("dangerous_construct").contains("StructuralPrefilters"))
    assertTrue(PatternSafetyRunner.chainModuleOf("compile_failed").contains("PyReParser"))
    assertTrue(PatternSafetyRunner.chainModuleOf("other").contains("unclassified"))
  }

  private fun writeCostCorpus(
      root: Path,
      budgets: String? =
          """{"k": 1e-12, "floor_ms": 0.0, "budgets": {
              "cost_prose_8kib": {"reference_ms": 1.0, "expected_is_threat": false},
              "cost_attack_small": {"reference_ms": 1.0, "expected_is_threat": false}}}""",
      cases: String? =
          """[{"id": "cost_prose_8kib", "input": {"content": "prose word ", "context": "body"}},
              {"id": "cost_attack_small", "input": {"content": "benign payload text", "context": "body"}}]""",
      includeBodies: Boolean = true,
  ) {
    val budgetBlock = budgets?.let { """, "cost_budgets": $it""" } ?: ""
    root
        .resolve("index.json")
        .writeText(
            """{"suites": {}, "config_knobs": {}, "fixed_ip": "203.0.113.1"$budgetBlock}""",
        )
    if (includeBodies) {
      root.resolve("cost_bodies.json").writeText("""{"cases": $cases}""")
    }
  }

  @Test
  fun `cost budget runner walks the drift, ledger and over-ceiling arms`() {
    // missing cost_budgets block fails the load
    val missing = Files.createTempDirectory("w9d-cost-missing")
    writeCostCorpus(missing, budgets = null)
    assertFailsWith<NoSuchElementException> { CostBudgetRunner.loadBudgets(missing) }
    // a vacuous cost_bodies.json fails the run
    val vacuous = Files.createTempDirectory("w9d-cost-vacuous")
    writeCostCorpus(vacuous, cases = "[]")
    assertFailsWith<IllegalStateException> {
      CostBudgetRunner.runAll(vacuous)
    }
    // a drifted expected verdict fails the run
    val drifted = Files.createTempDirectory("w9d-cost-drift")
    writeCostCorpus(
        drifted,
        budgets =
            """{"k": 1e-12, "floor_ms": 0.0, "budgets": {
                "cost_prose_8kib": {"reference_ms": 1.0, "expected_is_threat": true}}}""",
    )
    val driftError =
        assertFailsWith<IllegalStateException> {
          try {
            CostBudgetRunner.runAll(drifted)
          } finally {
            com.guardcore.engine.suspatterns.SusPatternsManager.shared().configure(null)
          }
        }
    assertTrue(driftError.message!!.contains("cost_prose_8kib"), driftError.message)
    // the tiny-k run drives every workload over ceiling (the overs arm)
    val tiny = Files.createTempDirectory("w9d-cost-tiny")
    writeCostCorpus(tiny)
    try {
      val result = CostBudgetRunner.runAll(tiny)
      assertTrue(result.timings.size == 2, result.lines.toString())
      assertTrue(result.overs.isNotEmpty(), result.lines.toString())
      assertTrue(result.staleLedgerEntries.isEmpty())
      assertTrue(result.best8Ms >= 0.0)
      // the huge-k run drives everything under ceiling; the ledgered workload goes stale
      val huge = Files.createTempDirectory("w9d-cost-huge")
      writeCostCorpus(
          huge,
          budgets =
              """{"k": 1e9, "floor_ms": 1e9, "budgets": {
                  "cost_prose_8kib": {"reference_ms": 1.0, "expected_is_threat": false},
                  "cost_attack_small": {"reference_ms": 1.0, "expected_is_threat": false}}}""",
      )
      val ledgered = CostBudgetRunner.runAll(huge, ledger = mapOf("cost_attack_small" to "w9d ledger"))
      assertEquals(listOf("cost_attack_small"), ledgered.staleLedgerEntries)
      assertTrue(ledgered.overs.isEmpty())
      assertTrue(ledgered.lines.any { it.contains("STALE ledger entry") }, ledgered.lines.toString())
    } finally {
      com.guardcore.engine.suspatterns.SusPatternsManager.shared().configure(null)
    }
  }
}
