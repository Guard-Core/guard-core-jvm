package com.guardcore.conformance

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W5 cost-budget gate: every cost_bodies workload must sit under its self-relative ceiling
 * (index.json cost_budgets.method: best_ms <= K * best8_ms * size/8192 + floor_ms, K=5,
 * floor_ms=250), measured against this engine's own 8 KiB baseline on this host. Fail-closed ledger
 * jvm_cost_xfail.json: an over-ceiling workload must be listed; a listed workload that comes back
 * under ceiling fails the build (stale entry).
 */
class CostBudgetConformanceTest {
  @Test
  fun costWorkloadsStayUnderSelfRelativeCeilings() {
    val ledger = loadCostLedger()
    val result = CostBudgetRunner.runAll(ledger = ledger)
    for (line in result.lines) println(line)
    if (result.staleLedgerEntries.isNotEmpty()) {
      fail(
          "cost budgets: listed in jvm_cost_xfail.json but now UNDER ceiling; remove the " +
              "stale entries: ${result.staleLedgerEntries}",
      )
    }
    if (result.overs.isNotEmpty()) {
      fail(
          "cost budgets: ${result.overs.size} workload(s) exceed their self-relative ceiling; " +
              "scan cost diverged superlinearly (fix the engine or register in " +
              "jvm_cost_xfail.json with a reason and a tracked fix):\n" +
              result.overs.joinToString("\n") {
                "  ${it.id}: best %.1f ms ceiling %.1f ms".format(it.bestMs, it.ceilingMs)
              },
      )
    }
    assertEquals(9, result.timings.size, "cost_bodies workload count drift")
  }

  public companion object {
    private const val LEDGER_RESOURCE = "/jvm_cost_xfail.json"

    public fun loadCostLedger(): Map<String, String> {
      val text =
          CostBudgetConformanceTest::class
              .java
              .getResourceAsStream(LEDGER_RESOURCE)
              ?.bufferedReader()
              ?.readText() ?: error("missing $LEDGER_RESOURCE")
      val obj = Json.parseToJsonElement(text).jsonObject
      return obj.getValue("workloads").jsonObject.entries.associate {
        it.key to it.value.jsonPrimitive.content
      }
    }
  }
}
