package com.guardcore.conformance

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.engine.suspatterns.DetectionConfigView
import com.guardcore.engine.suspatterns.SusPatternsManager
import com.guardcore.engine.suspatterns.Threat
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The W2 detect-suite runner: replays the 13 detect suites through the ported engine stack and
 * compares against the corpus under the index.json comparison contract.
 *
 * Contract (conformance/guard-core-spec-4.1.0/cases/index.json):
 * - threat multisets compared sorted-canonical, order-insensitively
 * - floats compared at 6-decimal precision
 * - execution_time dropped
 * - the 12 detection config_knobs replayed via the W1 SecurityConfig
 */
public object DetectRunner {
  /** Locates the vendored corpus relative to any working directory. */
  public fun corpusDir(startDir: Path = Path.of(System.getProperty("user.dir"))): Path {
    var dir: Path = startDir
    while (true) {
      val candidate = dir.resolve("conformance").resolve("guard-core-spec-4.1.0").resolve("cases")
      if (Files.exists(candidate.resolve("index.json"))) return candidate
      dir = dir.parent ?: error("corpus index.json not found relative to $startDir")
    }
  }

  public fun index(corpus: Path = corpusDir()): JsonObject =
      Json.parseToJsonElement(Files.readString(corpus.resolve("index.json"))).jsonObject

  /** The 12 detection config knobs from the index, replayed through SecurityConfig. */
  public fun configFromKnobs(index: JsonObject): SecurityConfig {
    val knobs = index.getValue("config_knobs").jsonObject
    val config = SecurityConfigBuilder().build()
    knobs["detection_compiler_timeout"]?.let {
      config.detectionCompilerTimeout = it.jsonPrimitive.double
    }
    knobs["detection_max_tracked_patterns"]?.let {
      config.detectionMaxTrackedPatterns = it.jsonPrimitive.int
    }
    knobs["detection_max_content_length"]?.let {
      config.detectionMaxContentLength = it.jsonPrimitive.int
    }
    knobs["detection_preserve_attack_patterns"]?.let {
      config.detectionPreserveAttackPatterns = it.jsonPrimitive.boolean
    }
    knobs["detection_max_body_inspect_bytes"]?.let {
      config.detectionMaxBodyInspectBytes = it.jsonPrimitive.int
    }
    knobs["detection_anomaly_threshold"]?.let {
      config.detectionAnomalyThreshold = it.jsonPrimitive.double
    }
    knobs["detection_slow_pattern_threshold"]?.let {
      config.detectionSlowPatternThreshold = it.jsonPrimitive.double
    }
    knobs["detection_monitor_history_size"]?.let {
      config.detectionMonitorHistorySize = it.jsonPrimitive.int
    }
    knobs["detection_anomaly_emission_cooldown"]?.let {
      config.detectionAnomalyEmissionCooldown = it.jsonPrimitive.double
    }
    knobs["detection_min_samples_for_anomaly"]?.let {
      config.detectionMinSamplesForAnomaly = it.jsonPrimitive.int
    }
    knobs["detection_semantic_threshold"]?.let {
      config.detectionSemanticThreshold = it.jsonPrimitive.double
    }
    knobs["detection_threat_score_threshold"]?.let {
      config.detectionThreatScoreThreshold = it.jsonPrimitive.double
    }
    return config
  }

  /** SecurityConfig seen through the engine's detection-config view. */
  public fun asDetectionConfigView(config: SecurityConfig): DetectionConfigView =
      object : DetectionConfigView {
        override val detectionCompilerTimeout: Double = config.detectionCompilerTimeout
        override val detectionMaxTrackedPatterns: Int = config.detectionMaxTrackedPatterns
        override val detectionMaxContentLength: Int = config.detectionMaxContentLength
        override val detectionPreserveAttackPatterns: Boolean =
            config.detectionPreserveAttackPatterns
        override val detectionAnomalyThreshold: Double = config.detectionAnomalyThreshold
        override val detectionSlowPatternThreshold: Double = config.detectionSlowPatternThreshold
        override val detectionMonitorHistorySize: Int = config.detectionMonitorHistorySize
        override val detectionAnomalyEmissionCooldown: Double =
            config.detectionAnomalyEmissionCooldown
        override val detectionMinSamplesForAnomaly: Int = config.detectionMinSamplesForAnomaly
        override val detectionSemanticThreshold: Double = config.detectionSemanticThreshold
        override val detectionThreatScoreThreshold: Double = config.detectionThreatScoreThreshold
        override val detectionMaxBodyInspectBytes: Int = config.detectionMaxBodyInspectBytes
        override val detectionPatternValidationCachePath: String? =
            config.detectionPatternValidationCachePath
      }

  /** round(value, 6) per the float_precision contract (python round: half-even). */
  public fun round6(value: Double): Double =
      BigDecimal(value).setScale(6, RoundingMode.HALF_EVEN).toDouble()

  /** The canonical threat sort key (category, pattern, position, type). */
  public fun threatSortKey(t: Threat): String =
      listOf(
              if (t.type == "semantic") "" else t.category,
              t.pattern,
              t.position.toString(),
              t.type,
          )
          .joinToString("\u001f")

  public fun canonicalThreats(threats: List<Threat>): List<Threat> = threats.sortedBy {
    threatSortKey(it)
  }

  public data class CaseFailure(
      val suite: String,
      val caseId: String,
      val reason: String,
  )

  public fun detectSuites(corpus: Path = corpusDir()): List<String> {
    val suites = index(corpus).getValue("suites").jsonObject
    return suites.entries
        .filter { it.value.jsonObject.getValue("kind").jsonPrimitive.content == "detect" }
        .map { it.key }
        .sorted()
  }

  /**
   * Runs every detect suite; returns per-suite failures. An empty list means all 193 cases match
   * the corpus.
   */
  public fun runAll(
      corpus: Path = corpusDir(),
      manager: SusPatternsManager = SusPatternsManager.shared(),
  ): List<CaseFailure> {
    val idx = index(corpus)
    val config = configFromKnobs(idx)
    manager.configure(asDetectionConfigView(config))

    val failures = ArrayList<CaseFailure>()
    for (suite in detectSuites(corpus)) {
      val suiteJson =
          Json.parseToJsonElement(Files.readString(corpus.resolve("$suite.json"))).jsonObject
      for (case in suiteJson.getValue("cases").jsonArray) {
        val caseObj = case.jsonObject
        val caseId = caseObj.getValue("id").jsonPrimitive.content
        val input = caseObj.getValue("input").jsonObject
        val content = input.getValue("content").jsonPrimitive.content
        val context = input.getValue("context").jsonPrimitive.content
        try {
          val verdict =
              manager.detect(
                  content,
                  idx.getValue("fixed_ip").jsonPrimitive.content,
                  context,
              )
          compareVerdict(suite, caseId, caseObj.getValue("expected").jsonObject, verdict, failures)
        } catch (e: Throwable) {
          var root: Throwable = e
          while (root.cause != null && root.cause !== root) root = root.cause!!
          val frames =
              root.stackTrace.take(6).joinToString(" | ") {
                it.className.substringAfterLast(".") + "." + it.methodName
              }
          failures.add(
              CaseFailure(
                  suite,
                  caseId,
                  "threw ${e::class.simpleName}: ${e.message} | root " +
                      "${root::class.simpleName}: ${root.message} @ $frames",
              ),
          )
        }
      }
    }
    return failures
  }

  private fun compareVerdict(
      suite: String,
      caseId: String,
      expected: JsonObject,
      verdict: com.guardcore.engine.suspatterns.DetectResult,
      failures: MutableList<CaseFailure>,
  ) {
    fun fail(reason: String) = failures.add(CaseFailure(suite, caseId, reason))

    val expectedIsThreat = expected.getValue("is_threat").jsonPrimitive.boolean
    if (verdict.isThreat != expectedIsThreat) {
      fail("is_threat: expected $expectedIsThreat got ${verdict.isThreat}")
      return
    }
    val expectedScore = expected.getValue("threat_score").jsonPrimitive.double
    if (round6(verdict.threatScore) != round6(expectedScore)) {
      fail("threat_score: expected $expectedScore got ${round6(verdict.threatScore)}")
      return
    }
    val expectedThreats = expected.getValue("threats").jsonArray.map { it.jsonObject }
    val actualThreats = canonicalThreats(verdict.threats)
    if (expectedThreats.size != actualThreats.size) {
      fail(
          "threat count: expected ${expectedThreats.size} got ${actualThreats.size} " +
              "(expected patterns: ${expectedThreats.map { it.getValue("pattern").jsonPrimitive.content.take(60) }}; " +
              "actual: ${actualThreats.map { it.pattern.take(60) }})",
      )
      return
    }
    for ((i, exp) in expectedThreats.withIndex()) {
      val act = actualThreats[i]
      val expType = exp.getValue("type").jsonPrimitive.content
      if (act.type != expType) {
        fail("threat[$i] type: expected $expType got ${act.type}")
        return
      }
      when (expType) {
        "regex",
        "pattern_timeout" -> {
          val expPattern = exp.getValue("pattern").jsonPrimitive.content
          if (act.pattern != expPattern) {
            fail("threat[$i] pattern: expected ${expPattern.take(60)} got ${act.pattern.take(60)}")
            return
          }
          val expMatch = exp.getValue("match").jsonPrimitive.content
          if (act.match != expMatch) {
            fail("threat[$i] match: expected ${expMatch.take(60)} got ${act.match.take(60)}")
            return
          }
          val expPosition = exp.getValue("position").jsonPrimitive.int
          if (act.position != expPosition) {
            fail("threat[$i] position: expected $expPosition got ${act.position}")
            return
          }
          val expCategory = exp.getValue("category").jsonPrimitive.content
          if (act.category != expCategory) {
            fail("threat[$i] category: expected $expCategory got ${act.category}")
            return
          }
          val expWeight = exp.getValue("weight").jsonPrimitive.double
          if (round6(act.weight) != round6(expWeight)) {
            fail("threat[$i] weight: expected $expWeight got ${act.weight}")
            return
          }
        }
        "semantic" -> {
          val expAttackType = exp.getValue("attack_type").jsonPrimitive.content
          if (act.attackType != expAttackType) {
            fail("threat[$i] attack_type: expected $expAttackType got ${act.attackType}")
            return
          }
          if (exp.containsKey("probability")) {
            val expProb = exp.getValue("probability").jsonPrimitive.double
            if (round6(act.probability ?: -1.0) != round6(expProb)) {
              fail("threat[$i] probability: expected $expProb got ${act.probability}")
              return
            }
          }
        }
      }
    }
    val expectedOriginal = expected.getValue("original_length").jsonPrimitive.int
    if (verdict.originalLength != expectedOriginal) {
      fail("original_length: expected $expectedOriginal got ${verdict.originalLength}")
      return
    }
    val expectedProcessed = expected.getValue("processed_length").jsonPrimitive.int
    if (verdict.processedLength != expectedProcessed) {
      fail("processed_length: expected $expectedProcessed got ${verdict.processedLength}")
      return
    }
    val expectedMethod = expected.getValue("detection_method").jsonPrimitive.content
    if (verdict.detectionMethod != expectedMethod) {
      fail("detection_method: expected $expectedMethod got ${verdict.detectionMethod}")
      return
    }
  }
}
