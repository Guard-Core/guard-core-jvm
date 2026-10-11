package com.guardcore.conformance

import com.guardcore.config.SecurityConfig
import com.guardcore.engine.suspatterns.SusPatternsManager
import java.nio.file.Files
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W5 cost-budget runner: self-relative scan-cost ceilings over the cost_bodies suite (see
 * index.json cost_budgets.method). Verdict parity for these workloads is enforced by the detect
 * runner (they are plain detect cases); this runner enforces the OTHER half, scan-cost ceilings, so
 * gross cost divergence can never pass silently.
 *
 * Each run measures its own best-of-N at the 8 KiB workload (cost_prose_8kib) and every other
 * workload must satisfy
 *
 *     best_ms <= K * best8_ms * (size_bytes / 8192) + floor_ms
 *
 * with K=5 and floor_ms=250 (index.json cost_budgets). Sampling is adaptive like the reference
 * runners: small workloads take the min of 3; at 256 KiB and beyond one timed run each keeps the
 * suite CI-viable, and the 5x-linear ceilings absorb the lost precision. reference_ms in the index
 * is the configured reference engine's best-of-5 on the generating host, recorded for drift review
 * only, never compared.
 */
public object CostBudgetRunner {
  public data class WorkloadTiming(
      val id: String,
      val sizeBytes: Int,
      val bestMs: Double,
      val ceilingMs: Double,
      val isThreat: Boolean,
      val expectedIsThreat: Boolean,
  )

  public data class CostResult(
      val best8Ms: Double,
      val timings: List<WorkloadTiming>,
      /** Workloads over ceiling with no ledger entry. */
      val overs: List<WorkloadTiming>,
      /** Workloads listed in the ledger that came back under ceiling (stale entries). */
      val staleLedgerEntries: List<String>,
      /** Summary lines for the log. */
      val lines: List<String>,
  )

  public data class CostCase(
      val id: String,
      val content: String,
      val context: String,
  )

  public fun loadBudgets(
      corpus: java.nio.file.Path = DetectRunner.corpusDir(),
  ): Triple<Double, Double, Map<String, Pair<Double, Boolean>>> {
    val index = Json.parseToJsonElement(Files.readString(corpus.resolve("index.json"))).jsonObject
    val budgetsBlock = index.getValue("cost_budgets").jsonObject
    val k = budgetsBlock.getValue("k").jsonPrimitive.double
    val floorMs = budgetsBlock.getValue("floor_ms").jsonPrimitive.double
    val budgets =
        budgetsBlock.getValue("budgets").jsonObject.entries.associate {
          val obj = it.value.jsonObject
          Pair(
              it.key,
              Pair(
                  obj.getValue("reference_ms").jsonPrimitive.double,
                  obj.getValue("expected_is_threat").jsonPrimitive.boolean,
              ),
          )
        }
    check(budgets.isNotEmpty()) {
      "index.json has no cost_budgets block; regenerate the corpus so cost stays enforced"
    }
    return Triple(k, floorMs, budgets)
  }

  public fun loadCases(corpus: java.nio.file.Path = DetectRunner.corpusDir()): List<CostCase> {
    val suiteJson =
        Json.parseToJsonElement(Files.readString(corpus.resolve("cost_bodies.json"))).jsonObject
    return suiteJson.getValue("cases").jsonArray.map { element ->
      val obj = element.jsonObject
      val input = obj.getValue("input").jsonObject
      CostCase(
          id = obj.getValue("id").jsonPrimitive.content,
          content = input.getValue("content").jsonPrimitive.content,
          context = input.getValue("context").jsonPrimitive.content,
      )
    }
  }

  /**
   * Times one workload best-of-N (adaptive: 1 run at 256 KiB and beyond, 2 at 64 KiB, else 3) and
   * returns the best wall-clock milliseconds plus the observed threat verdict.
   */
  public fun timeWorkload(
      case: CostCase,
      fixedIp: String,
      manager: SusPatternsManager,
  ): Pair<Double, Boolean> {
    val runs =
        when {
          case.content.length >= 256 * 1024 -> 1
          case.content.length >= 64 * 1024 -> 2
          else -> 3
        }
    var best = Double.MAX_VALUE
    var threat = false
    repeat(runs) {
      val start = System.nanoTime()
      val verdict = manager.detect(case.content, fixedIp, case.context)
      threat = verdict.isThreat
      val elapsedMs = (System.nanoTime() - start) / 1e6
      if (elapsedMs < best) best = elapsedMs
    }
    return Pair(best, threat)
  }

  /**
   * Measures every workload, asserts the recorded verdicts, applies the self-relative ceilings
   * under the fail-closed ledger (jvm_cost_xfail.json: a listed workload that is under ceiling is
   * stale and red; an unlisted workload over ceiling is red).
   */
  public fun runAll(
      corpus: java.nio.file.Path = DetectRunner.corpusDir(),
      ledger: Map<String, String> = emptyMap(),
      manager: SusPatternsManager = SusPatternsManager.shared(),
  ): CostResult {
    val (k, floorMs, budgets) = loadBudgets(corpus)
    val cases = loadCases(corpus)
    check(cases.isNotEmpty()) { "cost_bodies.json matched zero cases; a vacuous pass is a failure" }
    val idx = Json.parseToJsonElement(Files.readString(corpus.resolve("index.json"))).jsonObject
    val fixedIp = idx.getValue("fixed_ip").jsonPrimitive.content
    val config: SecurityConfig = DetectRunner.configFromKnobs(idx)
    manager.configure(DetectRunner.asDetectionConfigView(config))

    val byId = cases.associateBy { it.id }
    val baselineCase =
        byId["cost_prose_8kib"] ?: error("cost_bodies.json has no cost_prose_8kib baseline")
    val (best8Ms, baselineThreat) = timeWorkload(baselineCase, fixedIp, manager)
    val baselineExpected = budgets[baselineCase.id]?.second
    check(baselineExpected != null) { "index cost_budgets missing the baseline workload" }
    check(baselineThreat == baselineExpected) {
      "cost budgets/${baselineCase.id}: verdict drifted from the recorded expectation"
    }

    val lines = ArrayList<String>()
    lines.add("cost budgets: baseline cost_prose_8kib best8=%.1f ms".format(best8Ms))
    val timings = ArrayList<WorkloadTiming>()
    val overs = ArrayList<WorkloadTiming>()
    val stale = ArrayList<String>()
    for (case in cases) {
      val expected = budgets[case.id]?.second
      check(expected != null) { "index cost_budgets missing workload ${case.id}" }
      val (bestMs, threat) = timeWorkload(case, fixedIp, manager)
      check(threat == expected) {
        "cost budgets/${case.id}: verdict drifted from the recorded expectation"
      }
      val ceiling = k * best8Ms * (case.content.length.toDouble() / 8192.0) + floorMs
      val timing =
          WorkloadTiming(
              case.id,
              case.content.length,
              bestMs,
              ceiling,
              threat,
              expected,
          )
      timings.add(timing)
      val line =
          "cost budgets/${case.id}: best=%.1f ms ceiling=%.1f ms headroom=%.2fx (size %d bytes)"
              .format(bestMs, ceiling, ceiling / bestMs, case.content.length)
      val ledgered = ledger[case.id]
      if (ledgered != null) {
        if (bestMs <= ceiling) {
          stale.add(case.id)
          lines.add("$line: STALE ledger entry ($ledgered)")
        } else {
          lines.add("$line: ledgered (still over ceiling): $ledgered")
        }
        continue
      }
      lines.add(line)
      if (bestMs > ceiling) overs.add(timing)
    }
    return CostResult(best8Ms, timings, overs, stale, lines)
  }
}
