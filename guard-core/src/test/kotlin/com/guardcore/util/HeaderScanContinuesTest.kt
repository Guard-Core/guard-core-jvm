package com.guardcore.util

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Probe: a header whose threats are all category-filtered (an SSRF value in an address header) must
 * not end the request scan, so a later header still flags.
 */
class HeaderScanContinuesTest {
  init {
    forceDetectionConfigured()
  }

  private val ssrf = "http://169.254.169.254/latest/meta-data/"
  private val xss = "<script>alert(1)</script>"

  @Test
  fun categoryFilteredSsrfHeaderAloneIsNotAThreat() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-forwarded-for" to ssrf))
    assertFalse(
        PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig()).isThreat,
    )
  }

  @Test
  fun xssHeaderAfterCategoryFilteredSsrfHeaderStillFlags() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-forwarded-for" to ssrf, "x-custom" to xss))
    val result = PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig())
    assertTrue(result.isThreat)
    assertTrue("Header 'x-custom'" in result.triggerInfo, result.triggerInfo)
    assertEquals(listOf("xss"), result.threatCategories.filter { it == "xss" }.distinct())
  }
}
