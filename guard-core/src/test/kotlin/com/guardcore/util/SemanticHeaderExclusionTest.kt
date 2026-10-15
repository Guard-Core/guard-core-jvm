package com.guardcore.util

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.decorators.RouteConfig
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The opt-in excluded_semantic_detection_headers option: skips the semantic analyzer only. */
class SemanticHeaderExclusionTest {
  init {
    forceDetectionConfigured()
  }

  private val xss = "<script>alert(1)</script>"

  private fun b64(data: ByteArray): String =
      Base64.getUrlEncoder().withoutPadding().encodeToString(data)

  private fun sessionJwt(): String {
    val claims =
        """{"sub":"3f2c1b9e-8a47-4d2e-9c1f-5b6a7d8e9f01","name":"Jane Doe (Acme)","email":"jane.doe@example.com","roles":["admin"],"iat":1792000000,"exp":1792000900}"""
    return listOf(
            b64("""{"alg":"ES256","typ":"JWT"}""".encodeToByteArray()),
            b64(claims.encodeToByteArray()),
            b64(ByteArray(64) { it.toByte() }),
        )
        .joinToString(".")
  }

  private val semanticOnlyHeader: String
    get() = "session=${sessionJwt()}; theme=system; _ga=GA1.1.123456789.1792000000"

  private fun config(semantic: Set<String>) = defaultScanConfig {
    excludedSemanticDetectionHeaders = semantic
  }

  @Test
  fun defaultIsEmptyAndTheSemanticOnlyHeaderStillFlags() = scanRunTest {
    assertEquals(emptySet(), defaultScanConfig().excludedSemanticDetectionHeaders)
    val request = ScanRequest(headers = mapOf("x-session" to semanticOnlyHeader))
    val result = PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig())
    assertTrue(result.isThreat)
    assertEquals(listOf("suspicious"), result.threatCategories)
  }

  @Test
  fun globalExclusionSkipsTheSemanticAnalyzerForThatHeaderOnly() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-session" to semanticOnlyHeader))
    assertFalse(
        PenetrationDetection.detectPenetrationAttempt(request, config(setOf("X-Session"))).isThreat,
    )
  }

  @Test
  fun routeLevelExclusionSkipsTheSemanticAnalyzerForThatHeaderOnly() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-session" to semanticOnlyHeader))
    val route = RouteConfig().apply { excludedSemanticDetectionHeaders = setOf("x-session") }
    assertFalse(
        PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig(), route).isThreat,
    )
  }

  @Test
  fun regexScanningOfAnExcludedHeaderIsUnchanged() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-session" to xss))
    val result = PenetrationDetection.detectPenetrationAttempt(request, config(setOf("x-session")))
    assertTrue(result.isThreat)
    assertTrue("xss" in result.threatCategories, result.threatCategories.toString())
  }

  @Test
  fun otherHeadersStillGetTheSemanticAnalyzer() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-other" to semanticOnlyHeader))
    assertTrue(
        PenetrationDetection.detectPenetrationAttempt(request, config(setOf("x-session"))).isThreat,
    )
  }

  @Test
  fun exclusionNeverAppliesToANonHeaderValueWithTheSameName() = scanRunTest {
    val request = ScanRequest(queryParams = mapOf("x-session" to semanticOnlyHeader))
    assertTrue(
        PenetrationDetection.detectPenetrationAttempt(request, config(setOf("x-session"))).isThreat,
    )
  }

  @Test
  fun xssHeaderAfterASemanticExcludedHeaderStillFlags() = scanRunTest {
    val request = ScanRequest(headers = mapOf("x-session" to semanticOnlyHeader, "x-custom" to xss))
    val result = PenetrationDetection.detectPenetrationAttempt(request, config(setOf("x-session")))
    assertTrue(result.isThreat)
    assertTrue("Header 'x-custom'" in result.triggerInfo, result.triggerInfo)
  }

  @Test
  fun builderKeepsTheOptionThroughValidationAndCopy() {
    val built =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              excludedSemanticDetectionHeaders = setOf("cookie")
            }
            .build()
    assertEquals(setOf("cookie"), built.excludedSemanticDetectionHeaders)
    assertEquals(
        setOf("cookie"),
        SecurityConfigBuilder.fromConfig(built).build().excludedSemanticDetectionHeaders,
    )
  }
}
