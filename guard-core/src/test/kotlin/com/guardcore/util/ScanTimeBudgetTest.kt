package com.guardcore.util

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.engine.suspatterns.Threat
import com.guardcore.errors.ConfigValidationError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** detection_max_scan_seconds: the per-request scan time budget through the facade. */
class ScanTimeBudgetTest {
  init {
    forceDetectionConfigured()
  }

  private fun timeoutThreat() =
      Threat("pattern_timeout", "scan_time_budget_exhausted", "", 0, 0.0, "custom", 0.5)

  private fun regexThreat() = Threat("regex", "evil", "m", 0, 0.0, "xss", 1.0)

  @Test
  fun defaultIsTenSecondsAndRangeIsEnforced() {
    assertEquals(10.0, defaultScanConfig().detectionMaxScanSeconds)
    for (ok in listOf(0.1, 60.0)) {
      assertEquals(ok, defaultScanConfig { detectionMaxScanSeconds = ok }.detectionMaxScanSeconds)
    }
    for (bad in listOf(0.05, 60.5)) {
      assertFailsWith<ConfigValidationError> {
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              detectionMaxScanSeconds = bad
            }
            .build()
      }
    }
  }

  @Test
  fun aSpentBudgetFlagsTheValueAndNamesTheBudget() = scanRunTest {
    val hit =
        DetectionScanBudget.withScanBudget(maxValues = 512, maxScanSeconds = 0.0) {
          DetectionScan.checkValueEnhanced("hello world", "query_param", "203.0.113.7", "c1")
        }
    assertTrue(hit.detected)
    assertTrue("scan_time_budget_exhausted" in hit.trigger, hit.trigger)
    assertTrue(hit.threats.any { it.type == "pattern_timeout" })
  }

  @Test
  fun aRequestWithinBudgetIsUnaffected() = scanRunTest {
    val request = ScanRequest(queryParams = (1..50).associate { "p$it" to "value $it" })
    assertFalse(
        PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig()).isThreat,
    )
  }

  @Test
  fun theTriggerAppendsTheBudgetWhenItIsNotTheFirstThreat() {
    val timeout = DetectionScan.buildThreatMessage(timeoutThreat())
    val regex = DetectionScan.buildThreatMessage(regexThreat())
    assertEquals(
        "$regex; $timeout",
        DetectionScan.buildThreatsMessage(listOf(regexThreat(), timeoutThreat())),
    )
    assertEquals(timeout, DetectionScan.buildThreatsMessage(listOf(timeoutThreat(), regexThreat())))
    assertEquals(regex, DetectionScan.buildThreatsMessage(listOf(regexThreat())))
  }

  @Test
  fun theFallbackScanStopsOnceTheBudgetIsSpent() = scanRunTest {
    DetectionScan.enhancedDetectOverride = { _, _, _, _, _ -> error("engine down") }
    try {
      val hit =
          DetectionScanBudget.withScanBudget(maxValues = 512, maxScanSeconds = 0.0) {
            DetectionScan.checkValueEnhanced("hello world", "query_param", "203.0.113.7", "c1")
          }
      assertTrue(hit.detected)
      assertEquals("Scan time budget exhausted (fallback)", hit.trigger)
    } finally {
      DetectionScan.enhancedDetectOverride = { _, _, _, _, _ -> null }
    }
  }
}
