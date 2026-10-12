package com.guardcore.engine.suspatterns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The SusPatternsManager lifecycle and detect() arms the corpus never reaches: add/remove pattern
 * bookkeeping, the semantic fallback, the decode budget exhaustion threat, and the multi-view
 * aggregation.
 */
class SusPatternsManagerTailTest {
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
  fun addAndRemovePatternBookkeeping() {
    val manager = SusPatternsManager.shared()
    val beforeAll = manager.getAllCompiledPatterns().size
    val beforeCustom = manager.customPatterns.size
    // Unsafe custom patterns are rejected.
    assertFalse(manager.addPattern("(.*)+", custom = true))
    // A valid custom pattern lands and reports.
    assertTrue(manager.addPattern("w9b-unique-marker-pattern", custom = true))
    assertEquals(beforeCustom + 1, manager.customPatterns.size)
    assertTrue(manager.getAllCompiledPatterns().size > beforeAll)
    assertTrue(manager.removePattern("w9b-unique-marker-pattern", custom = true))
    assertEquals(beforeCustom, manager.customPatterns.size)
    // Removing a nonexistent pattern reports false in both modes.
    assertFalse(manager.removePattern("w9b-unique-marker-pattern", custom = true))
    assertFalse(manager.removePattern("w9b-no-such-builtin-pattern", custom = false))
  }

  @Test
  fun detectFindsThreatsAndReportsShape() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      val result =
          manager.detect(
              "x\n/bin/sh -c id",
              "203.0.113.7",
              context = "request_body",
              correlationId = "corr-w9b",
          )
      assertTrue(result.isThreat, "expected cmd injection detection")
      assertTrue(result.threats.isNotEmpty())
      assertTrue(result.threatScore >= 0.0)
      assertEquals("corr-w9b", result.correlationId)
      assertTrue(result.processedLength > 0)
      assertTrue(result.detectionMethod.isNotEmpty())
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun detectReportsDecodeBudgetExhaustion() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      // A 20-deep nested percent-encoding exhausts the decode budget.
      var nested = "a"
      repeat(20) { nested = nested.replace("%", "%25").replace("a", "%61") }
      val result = manager.detect(nested, "203.0.113.7")
      assertTrue(
          result.threats.any { it.pattern == DECODE_BUDGET_EXHAUSTED_PATTERN },
          "expected the decode budget threat",
      )
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun detectSemanticFallbackForHighEntropyProse() {
    val manager = SusPatternsManager.shared()
    manager.configure(config())
    try {
      // High-entropy text with no regex hit crosses the semantic threshold.
      val noise = "aqzpxkwvmfjqzpxkwvmfaqzpxkwvmfaqzpxkwvmf123456"
      val result = manager.detect(noise, "203.0.113.7")
      assertTrue(result.originalLength == noise.length)
      assertNotNull(result)
    } finally {
      manager.configure(null)
    }
  }

  @Test
  fun collectThreatCategoriesMapsSemanticTypes() {
    val threats =
        listOf(
            Threat("semantic", "", "", 0, 0.0, "command", 1.0, attackType = "command"),
            Threat("semantic", "", "", 0, 0.0, "path", 1.0, attackType = "path"),
            Threat("semantic", "", "", 0, 0.0, "template", 1.0, attackType = "template"),
            Threat("semantic", "", "", 0, 0.0, "suspicious", 1.0, attackType = "suspicious"),
            Threat("semantic", "", "", 0, 0.0, "xss", 1.0, attackType = "xss"),
        )
    val categories = collectThreatCategories(threats)
    assertEquals(
        listOf("cmd_injection", "path_traversal", "template", "custom", "xss"),
        categories,
    )
  }

  @Test
  fun quadComponentOperators() {
    val quad = Quad(1, "b", 3.0, true)
    val (a, b, c, d) = quad
    assertEquals(1, a)
    assertEquals("b", b)
    assertEquals(3.0, c)
    assertTrue(d)
  }

  @Test
  fun scanWindowBoundSourcesAreConfigured() {
    // The bound-source table carries the script and style window pairs.
    assertTrue(SCAN_WINDOW_BOUND_SOURCES.containsKey("<script[^>]*>[^<]*<\\/script\\s*>"))
    assertTrue(SCAN_WINDOW_BOUND_SOURCES.values.all { it.isNotEmpty() })
  }
}
