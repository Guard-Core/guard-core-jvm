package com.guardcore.engine.suspatterns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * W9i batch 7 (completing): the legacy (non-enhanced) detect path - the candidate-rejection
 * validator arm of buildRegexThreat and the retry loop's scan advance.
 */
class SusPatternsW9iTailsTest {
  /**
   * detect() over the LEGACY detection state: with no compiler the manager takes
   * checkRegexPatternWithRetry, and a benign legacy-IPv4-host match exercises buildRegexThreat's
   * candidate rejection plus the retry loop's advance.
   */
  @Test
  fun `legacy detect rejects a benign legacy ipv4 host candidate`() {
    val manager = SusPatternsManager.shared()
    val original = manager.detectionState
    try {
      manager.detectionState = LEGACY_DETECTION_STATE
      val result = manager.detect("visit http://8.8.8.8/ for docs", "203.0.113.7")
      // 8.8.8.8 is not a blocked legacy network, so the candidate validator
      // rejects the match and no ssrf threat surfaces for it.
      val threats = result.threats.filter { it.category == "ssrf" && it.pattern.contains("://") }
      assertTrue(threats.isEmpty(), "benign legacy ipv4 host must not be reported")
      assertNotNull(result)
    } finally {
      manager.detectionState = original
    }
  }

  /**
   * detect() over a path-probe token under a query-param context: the recon pattern matches but the
   * matched text is not a probe in that context, so buildRegexThreat rejects it.
   */
  @Test
  fun `legacy detect rejects a non-probe recon match under query params`() {
    val manager = SusPatternsManager.shared()
    val original = manager.detectionState
    try {
      manager.detectionState = LEGACY_DETECTION_STATE
      val result = manager.detect("actuator", "203.0.113.7", context = "query_param")
      assertTrue(result.threats.isEmpty(), "the recon match is not a probe under query params")
    } finally {
      manager.detectionState = original
    }
  }

  /** removePattern keeps both tables in lockstep over the builtin (non-custom) mode. */
  @Test
  fun `remove pattern drops a builtin pattern and restores it`() {
    val manager = SusPatternsManager.shared()
    val victim = manager.patterns.last()
    val before = manager.patterns.size
    assertTrue(manager.removePattern(victim, custom = false))
    assertEquals(before - 1, manager.patterns.size)
    assertEquals(before - 1, manager.compiledPatterns.size)
    // Adding it back restores the table.
    assertTrue(manager.addPattern(victim, custom = false))
    assertEquals(before, manager.patterns.size)
    assertEquals(before, manager.compiledPatterns.size)
  }
}
