package com.guardcore.util

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The Cookie header is scanned one name=value pair at a time. */
class CookiePairScanTest {
  init {
    forceDetectionConfigured()
  }

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

  @Test
  fun cookieHeaderIsSplitIntoPairs() {
    val headers = linkedMapOf("Accept" to "text/html", "Cookie" to "a=1;  b=2;;\r\nc=3")
    assertEquals(
        listOf(
            "Accept" to "text/html",
            "Cookie" to "a=1",
            "Cookie" to "b=2",
            "Cookie" to "\r\nc=3",
        ),
        BodyContentScan.headerItemsToScan(headers),
    )
  }

  @Test
  fun loggedInCookieHeaderIsNotAThreat() = scanRunTest {
    val cookie = "session=${sessionJwt()}; theme=system; _ga=GA1.1.123456789.1792000000"
    val request = ScanRequest(headers = mapOf("Cookie" to cookie))
    assertFalse(
        PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig()).isThreat,
    )
  }

  @Test
  fun attackInOneCookieIsStillDetected() = scanRunTest {
    for (cookie in
        listOf(
            "theme=dark; q=<script>alert(1)</script>",
            "theme=dark; id=1' OR 1=1--",
            "theme=dark;\r\nSet-Cookie: admin=1",
        )) {
      val request = ScanRequest(headers = mapOf("Cookie" to cookie))
      assertTrue(
          PenetrationDetection.detectPenetrationAttempt(request, defaultScanConfig()).isThreat,
          cookie,
      )
    }
  }

  @Test
  fun semanticExclusionAppliesPerCookiePair() = scanRunTest {
    val request =
        ScanRequest(headers = mapOf("Cookie" to "theme=dark; q=<script>alert(1)</script>"))
    val config = defaultScanConfig { excludedSemanticDetectionHeaders = setOf("cookie") }
    assertTrue(PenetrationDetection.detectPenetrationAttempt(request, config).isThreat)
  }
}
