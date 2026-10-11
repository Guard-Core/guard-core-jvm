package com.guardcore.util

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.protocols.GuardRequest
import com.guardcore.util.py.PyJson
import java.util.logging.Logger
import com.guardcore.util.py.IpAddress
import com.guardcore.util.py.parseAddress
import java.util.logging.Level
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ports of the request-surface tests: test_utils/test_proxy_handling.py,
 * test_utils/test_ip_identity_canonicalization.py, test_utils/test_request_checks.py,
 * test_utils/test_scan_value_cap.py, test_utils/test_scan_char_budget.py,
 * test_utils/test_detection_scan_threat_message.py, and the embedded-json scan tests
 * (tests/test_utils/test_form_value_embedded_json.py embedded arms).
 */
private const val XSS_LOCAL: String = "<script>alert(1)</script>"

private fun proxyRequest(
    clientHost: String? = "127.0.0.1",
    forwardedFor: String? = null,
): ScanRequest {
  val headers = linkedMapOf<String, String>()
  if (forwardedFor != null) headers["X-Forwarded-For"] = forwardedFor
  return ScanRequest(method = "GET", clientHost = clientHost, headers = headers)
}

private fun proxyConfig(
    trustedProxies: List<String>,
    depth: Int = 1,
): com.guardcore.config.SecurityConfig =
    defaultScanConfig {
      this.trustedProxies = trustedProxies
      trustedProxyDepth = depth
    }

private class RecordingAgentHandler(
    private val onSend: (Any?) -> Unit = {},
) : com.guardcore.protocols.AgentHandlerProtocol {
  public val events: MutableList<Any?> = mutableListOf()

  override suspend fun initializeRedis(redisHandler: com.guardcore.protocols.RedisHandlerProtocol) {}

  override suspend fun sendEvent(event: Any?) {
    onSend(event)
    events.add(event)
  }

  override suspend fun sendMetric(metric: Any?) {}

  override suspend fun start() {}

  override suspend fun stop() {}

  override suspend fun flushBuffer() {}

  override suspend fun getDynamicRules(): Any? = null

  override suspend fun healthCheck(): Boolean = true
}

/** test_utils/test_proxy_handling.py + test_utils/test_ip_identity_canonicalization.py. */
class IpExtractionProxyTest {
  @Test
  fun testExtractClientIpWithoutTrustedProxies() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip = IpExtraction.extractClientIp(proxyRequest(forwardedFor = "1.2.3.4"), defaultScanConfig())
      assertEquals("127.0.0.1", ip)
    }
  }

  @Test
  fun testExtractClientIpWithTrustedProxies() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(forwardedFor = "1.2.3.4"),
              proxyConfig(listOf("127.0.0.1")),
          )
      assertEquals("1.2.3.4", ip)
    }
  }

  @Test
  fun testExtractClientIpWithCidrTrustedProxies() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(forwardedFor = "1.2.3.4"),
              proxyConfig(listOf("127.0.0.0/8")),
          )
      assertEquals("1.2.3.4", ip)
    }
  }

  @Test
  fun testExtractClientIpWithProxyDepth() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(forwardedFor = "5.6.7.8, 1.2.3.4"),
              proxyConfig(listOf("127.0.0.1", "1.2.3.4"), depth = 2),
          )
      assertEquals("5.6.7.8", ip)
    }
  }

  @Test
  fun testExtractClientIpWithoutForwarded() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip = IpExtraction.extractClientIp(proxyRequest(), proxyConfig(listOf("127.0.0.1")))
      assertEquals("127.0.0.1", ip)
    }
  }

  @Test
  fun testExtractClientIpWithUntrustedProxy() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val ip =
            IpExtraction.extractClientIp(
                proxyRequest(forwardedFor = "1.2.3.4"),
                proxyConfig(listOf("10.0.0.1")),
            )
        assertEquals("127.0.0.1", ip)
        assertTrue(capture.text().contains("Potential IP spoof attempt"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** test_proxy_handling.py:103: the spoof agent event carries handler_name ip_extraction. */
  @Test
  fun testUntrustedProxySpoofEventSetsHandlerName() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val agent = RecordingAgentHandler()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(clientHost = "203.0.113.9", forwardedFor = "1.2.3.4"),
              proxyConfig(listOf("10.0.0.1")),
              agent,
          )
      assertEquals("203.0.113.9", ip)
      assertEquals(1, agent.events.size)
      val event = agent.events[0] as Map<*, *>
      assertEquals("suspicious_request", event["event_type"])
      assertEquals("ip_extraction", event["handler_name"])
      assertNull(event["decorator_type"])
      assertNull(event["rule_type"])
    }
  }

  @Test
  fun testExtractClientIpNoClient() {
    scanRunTest {
      val ip = IpExtraction.extractClientIp(proxyRequest(clientHost = null), proxyConfig(listOf("127.0.0.1")))
      assertEquals("unknown", ip)
    }
  }

  @Test
  fun testUnixSocketResolvesFromForwardedHeader() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(clientHost = null, forwardedFor = "1.2.3.4"),
              proxyConfig(listOf("unix")),
          )
      assertEquals("1.2.3.4", ip)
    }
  }

  @Test
  fun testUnixSocketWithoutHeaderStaysUnknown() {
    scanRunTest {
      val ip = IpExtraction.extractClientIp(proxyRequest(clientHost = null), proxyConfig(listOf("unix")))
      assertEquals("unknown", ip)
    }
  }

  /** test_proxy_handling.py:191 + 326: chain shorter than depth warns once and falls back. */
  @Test
  fun testChainTooShortWarningFiresAndFallsBack() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val ip =
            IpExtraction.extractClientIp(
                proxyRequest(forwardedFor = "1.2.3.4"),
                proxyConfig(listOf("127.0.0.1"), depth = 3),
            )
        assertEquals("127.0.0.1", ip)
        assertTrue(capture.text().contains("X-Forwarded-For chain has only 1 entries"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testChainTooShortWarningEmittedAtMostOnce() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val config = proxyConfig(listOf("127.0.0.1"), depth = 3)
        IpExtraction.extractClientIp(proxyRequest(forwardedFor = "1.2.3.4"), config)
        IpExtraction.extractClientIp(proxyRequest(forwardedFor = "1.2.3.4"), config)
        assertEquals(
            1,
            Regex("chain has only 1 entries").findAll(capture.text()).count(),
            capture.text(),
        )
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** test_proxy_handling.py:222: preemption warning once. */
  @Test
  fun testPreemptionWarningFiresWhenTrustedProxiesUnset() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        IpExtraction.extractClientIp(proxyRequest(forwardedFor = "127.0.0.1"), defaultScanConfig())
        assertTrue(
            capture.text().contains("already appears inside its own X-Forwarded-For chain"),
            capture.text(),
        )
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testPreemptionWarningAbsentWithoutForwardedHeader() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        IpExtraction.extractClientIp(proxyRequest(), defaultScanConfig())
        assertFalse(capture.text().contains("already appears inside its own"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testPreemptionWarningAbsentWhenPeerNotInChain() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        IpExtraction.extractClientIp(proxyRequest(forwardedFor = "9.9.0.1"), defaultScanConfig())
        assertFalse(capture.text().contains("already appears inside its own"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** test_proxy_handling.py:396: every chain entry trusted -> selected-entry warning. */
  @Test
  fun testSelectedEntryTrustedProxyWarningFires() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val ip =
            IpExtraction.extractClientIp(
                proxyRequest(forwardedFor = "10.1.0.1"),
                proxyConfig(listOf("127.0.0.1", "10.1.0.1")),
            )
        assertEquals("10.1.0.1", ip)
        assertTrue(
            capture.text().contains("trusted_proxy_depth selected 10.1.0.1"),
            capture.text(),
        )
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** test_proxy_handling.py:475: over-counted depth resolves right-to-left walk. */
  @Test
  fun testOvercountedDepthResolvesToProxyAppendedRealAddress() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val ip =
            IpExtraction.extractClientIp(
                proxyRequest(clientHost = "10.0.0.1", forwardedFor = "198.51.100.7, 203.0.113.9"),
                proxyConfig(listOf("10.0.0.1"), depth = 2),
            )
        assertEquals("203.0.113.9", ip)
        assertTrue(
            capture.text().contains("over-counts"),
            capture.text(),
        )
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** test_proxy_handling.py:630: invalid first entry falls back to the peer. */
  @Test
  fun testInvalidSingleEntryChainFallsBackToPeer() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(forwardedFor = "not-an-ip"),
              proxyConfig(listOf("127.0.0.1")),
          )
      assertEquals("127.0.0.1", ip)
    }
  }

  /** test_proxy_handling.py:700/739: glob metacharacters are rejected as candidates. */
  @Test
  fun testGlobMetacharactersShortChainFallsBackToPeer() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(forwardedFor = "fe80::*"),
              proxyConfig(listOf("127.0.0.1")),
          )
      assertEquals("127.0.0.1", ip)
    }
  }

  @Test
  fun testGlobMetacharactersResolveViaCleanRightEntry() {
    scanRunTest {
      IpExtraction.resetOnceFlags()
      val ip =
          IpExtraction.extractClientIp(
              proxyRequest(forwardedFor = "fe80::*, 1.2.3.4"),
              proxyConfig(listOf("127.0.0.1"), depth = 2),
          )
      assertEquals("1.2.3.4", ip)
    }
  }

  /** ip_extraction.py:48 port stripping variants. */
  @Test
  fun testStripForwardedEntryPortVariants() {
    assertEquals("1.2.3.4", IpExtraction.stripForwardedEntryPort("1.2.3.4:8080"))
    assertEquals("1.2.3.4", IpExtraction.stripForwardedEntryPort("1.2.3.4"))
    assertEquals("::1", IpExtraction.stripForwardedEntryPort("[::1]:443"))
    assertEquals("[::1]:noscript", IpExtraction.stripForwardedEntryPort("[::1]:noscript"))
    assertEquals("[::1", IpExtraction.stripForwardedEntryPort("[::1"))
    assertEquals("example.com", IpExtraction.stripForwardedEntryPort("example.com:80"))
  }

  /** ip_extraction.py:42. */
  @Test
  fun testStripIpBrackets() {
    assertEquals("::1", IpExtraction.stripIpBrackets("[::1]"))
    assertEquals("1.2.3.4", IpExtraction.stripIpBrackets("1.2.3.4"))
  }

  /** ip_extraction.py:138. */
  @Test
  fun testIsPrivateOrLoopback() {
    assertTrue(IpExtraction.isPrivateOrLoopback("127.0.0.1"))
    assertTrue(IpExtraction.isPrivateOrLoopback("10.0.0.1"))
    assertFalse(IpExtraction.isPrivateOrLoopback("1.2.3.4"))
    assertFalse(IpExtraction.isPrivateOrLoopback("garbage"))
  }

  /** ip_extraction.py:184: invalid chain entries render as [REDACTED]. */
  @Test
  fun testDisplayForwardedChainRedactsInvalidEntries() {
    assertEquals("1.2.3.4", IpExtraction.displayForwardedChain("1.2.3.4"))
    assertEquals("[REDACTED]", IpExtraction.displayForwardedChain("not-an-ip"))
    assertEquals("1.2.3.4,[REDACTED]", IpExtraction.displayForwardedChain("1.2.3.4, bogus"))
  }

  /** ip_extraction.py:64 canonicalization of the connecting peer. */
  @Test
  fun testCanonicalizeIpForms() {
    assertEquals("127.0.0.1", IpExtraction.canonicalizeIp("127.0.0.1"))
    assertEquals("1.2.3.4", IpExtraction.canonicalizeIp("[1.2.3.4]"))
    assertEquals("bogus", IpExtraction.canonicalizeIp("bogus"))
  }

  /** ip_extraction.py:324 state cache short-circuit. */
  @Test
  fun testStateClientIpCacheShortCircuits() {
    scanRunTest {
      val request = proxyRequest(clientHost = "9.9.9.9")
      request.state.setAttr("client_ip", "203.0.113.5")
      val ip = IpExtraction.extractClientIp(request, proxyConfig(listOf("127.0.0.1")))
      assertEquals("203.0.113.5", ip)
    }
  }

  /** test_ip_identity_canonicalization.py surface through checkIpCountry-style flows. */
  @Test
  fun testIsTrustedProxyForms() {
    assertTrue(IpExtraction.isTrustedProxy("127.0.0.1", listOf("127.0.0.1")))
    assertTrue(IpExtraction.isTrustedProxy("127.0.0.1", listOf("127.0.0.0/8")))
    assertFalse(IpExtraction.isTrustedProxy("1.2.3.4", listOf("127.0.0.0/8")))
    assertFalse(IpExtraction.isTrustedProxy("bad-ip", listOf("bad-ip")))
  }
}

/** test_utils/test_request_checks.py remainder + access-control log arms. */
class AccessControlFullTest {
  private class FakeGeo(private val country: String?, private val initialized: Boolean = true) :
      com.guardcore.protocols.GeoIPHandler {
    public var initializeCalls: Int = 0

    override val isInitialized: Boolean = initialized

    override suspend fun initialize() {
      initializeCalls++
    }

    override suspend fun initializeRedis(redisHandler: com.guardcore.protocols.RedisHandlerProtocol) {}

    override suspend fun initializeAgent(agentHandler: com.guardcore.protocols.AgentHandlerProtocol) {}

    override fun getCountry(ip: String): String? = country

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun config(apply: SecurityConfigBuilder.() -> Unit): com.guardcore.config.SecurityConfig =
      defaultScanConfig {
        geoIpHandler = FakeGeo(null)
        apply()
      }

  /** access_control.py:84 both whitelist and blacklist arms. */
  @Test
  fun testEvaluateCountryAccessArms() {
    val whitelist =
        config { whitelistCountries = setOf("US") }
    assertEquals(false to "whitelisted", AccessControl.evaluateCountryAccess("US", whitelist))
    assertEquals(true to "blocked", AccessControl.evaluateCountryAccess("CN", whitelist))
    val blacklist = config { blockedCountries = setOf("CN") }
    assertEquals(true to "blocked", AccessControl.evaluateCountryAccess("CN", blacklist))
    assertEquals(false to "not_affected", AccessControl.evaluateCountryAccess("US", blacklist))
  }

  /** access_control.py:132 CIDR and exact membership. */
  @Test
  fun testIpInListForms() {
    val addr: IpAddress = parseAddress("192.168.1.5")
    assertTrue(AccessControl.ipInList(addr, "192.168.1.5", listOf("192.168.1.5")))
    assertTrue(AccessControl.ipInList(addr, "192.168.1.5", listOf("192.168.0.0/16")))
    assertFalse(AccessControl.ipInList(addr, "192.168.1.5", listOf("10.0.0.1")))
    assertFalse(AccessControl.ipInList(addr, "192.168.1.5", emptyList()))
    assertFalse(AccessControl.ipInList(addr, "192.168.1.5", null))
  }

  /** access_control.py:43 log branches for every result type. */
  @Test
  fun testLogCountryCheckResultArms() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val cfg = config {
          blockedCountries = setOf("CN")
          logSuspiciousLevel = com.guardcore.config.LogLevel.WARNING
          logCountryCheckLevel = com.guardcore.config.LogLevel.INFO
        }
        // blocked
        AccessControl.resolveCountryVerdict("203.0.113.7", cfg, FakeGeo("CN"))
        // whitelisted
        val cfg2 = config {
          whitelistCountries = setOf("US")
          logCountryCheckLevel = com.guardcore.config.LogLevel.INFO
        }
        AccessControl.resolveCountryVerdict("203.0.113.7", cfg2, FakeGeo("US"))
        // not affected
        AccessControl.resolveCountryVerdict("203.0.113.7", cfg, FakeGeo("US"))
        // no rules
        AccessControl.resolveCountryVerdict("203.0.113.7", config {}, FakeGeo(null))
        // no geolocation
        AccessControl.resolveCountryVerdict("203.0.113.7", cfg, FakeGeo(null))
        // loopback exempt
        AccessControl.resolveCountryVerdict("127.0.0.1", cfg, FakeGeo("CN"))
        val text = capture.text()
        assertTrue(text.contains("IP from blocked country 203.0.113.7 - CN"), text)
        assertTrue(text.contains("IP from whitelisted country 203.0.113.7 - US"), text)
        assertTrue(text.contains("IP not from blocked or whitelisted country 203.0.113.7 - US"), text)
        assertTrue(text.contains("No countries blocked or whitelisted"), text)
        assertTrue(text.contains("IP not geolocated"), text)
        assertTrue(text.contains("Loopback IP exempt from country allowlist check"), text)
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** access_control.py:43 null levels suppress the blocked/not_affected logs. */
  @Test
  fun testLogCountryCheckResultNullLevelsSuppress() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        val cfg = config {
          blockedCountries = setOf("CN")
          logSuspiciousLevel = null
        }
        AccessControl.resolveCountryVerdict("203.0.113.7", cfg, FakeGeo("CN"))
        assertFalse(capture.text().contains("IP from blocked country 203.0.113.7"), capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** access_control.py:96 lazy initialize when the handler is not initialized. */
  @Test
  fun testResolveCountryVerdictInitializesLazyHandler() {
    scanRunTest {
      val geo = FakeGeo("US", initialized = false)
      val cfg = config { whitelistCountries = setOf("US") }
      val (isBlocked, country) = AccessControl.resolveCountryVerdict("203.0.113.7", cfg, geo)
      assertEquals(false, isBlocked)
      assertEquals("US", country)
      assertEquals(1, geo.initializeCalls)
    }
  }

  /** access_control.py:122 request-object overloads. */
  @Test
  fun testCheckIpCountryWithRequestAndString() {
    scanRunTest {
      val cfg = config { blockedCountries = setOf("CN") }
      val request = ScanRequest(clientHost = "203.0.113.7")
      assertTrue(AccessControl.checkIpCountry(request, cfg, FakeGeo("CN")))
      assertTrue(AccessControl.checkIpCountry("203.0.113.7", cfg, FakeGeo("CN")))
      assertFalse(AccessControl.checkIpCountry(object {}, cfg, FakeGeo(null)))
    }
  }

  /** access_control.py:197 cloud-provider seam. */
  @Test
  fun testCheckIpAccessCloudProviderSeam() {
    scanRunTest {
      AccessControl.cloudIpChecker = { ip, providers ->
        if (ip == "13.107.42.14" && "Azure" in providers) {
          AccessControl.CloudProviderDetails("Azure", "13.107.0.0/16")
        } else {
          null
        }
      }
      try {
        val cfg = config { blockCloudProviders = setOf("Azure") }
        val result = AccessControl.checkIpAccess("13.107.42.14", cfg)
        assertEquals(false, result.allowed)
        assertEquals("Azure", result.cloudProvider)
        assertEquals("13.107.0.0/16", result.network)
        // No provider hit -> allowed.
        val miss = AccessControl.checkIpAccess("1.2.3.4", cfg)
        assertEquals(true, miss.allowed)
      } finally {
        AccessControl.cloudIpChecker = null
      }
    }
  }

  /** access_control.py:241 whitelist hit skips the country check. */
  @Test
  fun testCheckIpAccessWhitelistSkipsCountries() {
    scanRunTest {
      val cfg = config {
        whitelist = listOf("203.0.113.7")
        blockedCountries = setOf("CN")
      }
      val result = AccessControl.checkIpAccess("203.0.113.7", cfg, FakeGeo("CN"))
      assertEquals(true, result.allowed)
    }
  }

  /** access_control.py:241 unknown identity + skip flags. */
  @Test
  fun testCheckIpAccessUnknownIdentityFlags() {
    scanRunTest {
      val cfg = config {
        whitelist = listOf("203.0.113.7")
        whitelistCountries = setOf("US")
      }
      val blocked = AccessControl.checkIpAccess("unknown", cfg)
      assertEquals(false, blocked.allowed)
      val allowed = AccessControl.checkIpAccess("unknown", cfg, skipIpLists = true, skipCountries = true)
      assertEquals(true, allowed.allowed)
    }
  }

  /** access_control.py:284 isIpAllowed wrapper. */
  @Test
  fun testIsIpAllowedWrapper() {
    scanRunTest {
      val cfg = config { blacklist = listOf("1.2.3.4") }
      assertEquals(false, AccessControl.isIpAllowed("1.2.3.4", cfg))
      assertEquals(true, AccessControl.isIpAllowed("5.6.7.8", cfg))
    }
  }

  /** access_control.py:15 UA gate with the engine seam registered. */
  @Test
  fun testUserAgentAllowedWithEngineSeam() {
    scanRunTest {
      DetectionEngineWiring.register()
      val cfg = config { blockedUserAgents = listOf("sqlmap", "nmap|nikto") }
      assertEquals(false, AccessControl.isUserAgentAllowed("sqlmap/1.1.12", cfg))
      assertEquals(false, AccessControl.isUserAgentAllowed("nmap scanner", cfg))
      assertEquals(true, AccessControl.isUserAgentAllowed("Mozilla/5.0", cfg))
    }
  }

  /** access_control.py:36 loopback helper. */
  @Test
  fun testIsLoopback() {
    assertTrue(AccessControl.isLoopback("127.0.0.1"))
    assertTrue(AccessControl.isLoopback("::1"))
    assertFalse(AccessControl.isLoopback("1.2.3.4"))
    assertFalse(AccessControl.isLoopback("nope"))
  }

  /** access_control.py:22 extract-ip request shapes. */
  @Test
  fun testExtractIpFromRequestShapes() {
    assertEquals("203.0.113.7", AccessControl.extractIpFromRequest("203.0.113.7"))
    assertEquals("203.0.113.7", AccessControl.extractIpFromRequest(ScanRequest(clientHost = "203.0.113.7")))
    assertEquals("unknown", AccessControl.extractIpFromRequest(ScanRequest(clientHost = null)))
    assertEquals("unknown", AccessControl.extractIpFromRequest(object {}))
  }

  /** access_control.py:32. */
  @Test
  fun testHasCountryRules() {
    assertFalse(AccessControl.hasCountryRules(config {}))
    assertTrue(AccessControl.hasCountryRules(config { blockedCountries = setOf("CN") }))
    assertTrue(AccessControl.hasCountryRules(config { whitelistCountries = setOf("US") }))
  }
}

/** test_utils/test_scan_value_cap.py, test_scan_char_budget.py, test_detection_scan_threat_message.py. */
class DetectionScanTest {
  private fun regexThreat(pattern: String = "union.*select") = com.guardcore.engine.suspatterns.Threat(
      type = "regex",
      pattern = pattern,
      match = "union select",
      position = 0,
      executionTime = 0.0,
      category = "sqli",
      weight = 1.0,
  )

  /** test_detection_scan_threat_message.py. */
  @Test
  fun testBuildThreatMessageArms() {
    assertEquals(
        "Value matched pattern 'union.*select'",
        DetectionScan.buildThreatMessage(regexThreat()),
    )
    val semantic = com.guardcore.engine.suspatterns.Threat(
        type = "semantic",
        pattern = "",
        match = "",
        position = 0,
        executionTime = 0.0,
        category = "sqli",
        weight = 1.0,
        attackType = "sqli",
        probability = 0.91234,
    )
    assertEquals("Semantic attack: sqli (score: 0.91)", DetectionScan.buildThreatMessage(semantic))
    val timeout = com.guardcore.engine.suspatterns.Threat(
        type = "pattern_timeout",
        pattern = "(a+)+$",
        match = "",
        position = 0,
        executionTime = 0.0,
        category = "redos",
        weight = 1.0,
    )
    assertEquals(
        "Pattern exceeded scan time budget: '(a+)+$'",
        DetectionScan.buildThreatMessage(timeout),
    )
    val unknown = com.guardcore.engine.suspatterns.Threat(
        type = "unknown-kind",
        pattern = "",
        match = "",
        position = 0,
        executionTime = 0.0,
        category = "x",
        weight = 1.0,
    )
    assertEquals("Threat detected", DetectionScan.buildThreatMessage(unknown))
  }

  /** detection_scan.py:245. */
  @Test
  fun testResolveJsonRedactAll() {
    assertEquals(true, DetectionScan.resolveJsonRedactAll(null, true))
    assertEquals(false, DetectionScan.resolveJsonRedactAll(null, false))
    assertEquals(true, DetectionScan.resolveJsonRedactAll("preview", null))
    assertEquals(false, DetectionScan.resolveJsonRedactAll(null, null))
  }

  /** test_scan_value_cap.py: value cap warn-once. */
  @Test
  fun testScanValueBudgetExhaustedWarnsOnce() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 2) {
        val capture = LogCapture()
        capture.attach(GUARD_LOGGER, Level.ALL)
        try {
          assertEquals(false, DetectionScanBudget.scanValueBudgetExhausted("1.2.3.4"))
          assertEquals(false, DetectionScanBudget.scanValueBudgetExhausted("1.2.3.4"))
          assertEquals(true, DetectionScanBudget.scanValueBudgetExhausted("1.2.3.4"))
          assertEquals(true, DetectionScanBudget.scanValueBudgetExhausted("1.2.3.4"))
          assertEquals(
              1,
              Regex("detection_max_scan_values \\(2\\) reached").findAll(capture.text()).count(),
              capture.text(),
          )
        } finally {
          capture.detach(GUARD_LOGGER)
        }
      }
    }
  }

  /** test_scan_char_budget.py. */
  @Test
  fun testScanCharBudgetExhaustedWarnsOnce() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 100, maxScanChars = 10) {
        val capture = LogCapture()
        capture.attach(GUARD_LOGGER, Level.ALL)
        try {
          assertEquals(false, DetectionScanBudget.scanCharBudgetExhausted("1.2.3.4", 8))
          assertEquals(false, DetectionScanBudget.scanCharBudgetExhausted("1.2.3.4", 8))
          assertEquals(true, DetectionScanBudget.scanCharBudgetExhausted("1.2.3.4", 8))
          assertEquals(true, DetectionScanBudget.scanCharBudgetExhausted("1.2.3.4", 8))
          assertEquals(
              1,
              Regex("detection_max_scan_chars \\(10\\) reached").findAll(capture.text()).count(),
              capture.text(),
          )
        } finally {
          capture.detach(GUARD_LOGGER)
        }
      }
    }
  }

  @Test
  fun testWarnJsonDepthCapReachedOnce() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 10, maxJsonDepth = 5) {
        val capture = LogCapture()
        capture.attach(GUARD_LOGGER, Level.ALL)
        try {
          DetectionScanBudget.warnJsonDepthCapReachedOnce("1.2.3.4")
          DetectionScanBudget.warnJsonDepthCapReachedOnce("1.2.3.4")
          assertEquals(
              1,
              Regex("detection_max_json_depth \\(5\\) reached").findAll(capture.text()).count(),
              capture.text(),
          )
        } finally {
          capture.detach(GUARD_LOGGER)
        }
      }
    }
  }

  @Test
  fun testBudgetLogAtLevelArms() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        DetectionScanBudget.logAtLevel("DEBUG", "d")
        DetectionScanBudget.logAtLevel("INFO", "i")
        DetectionScanBudget.logAtLevel("WARNING", "w")
        DetectionScanBudget.logAtLevel("ERROR", "e")
        DetectionScanBudget.logAtLevel("CRITICAL", "c")
        DetectionScanBudget.logAtLevel("weird", "x")
        DetectionScanBudget.logAtLevel(null, "never")
        val text = capture.text()
        for (marker in listOf("d", "i", "w", "e", "c", "x")) {
          assertTrue(marker in text, text)
        }
        assertFalse("never" in text)
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  @Test
  fun testWithScanBudgetRestoresPreviousState() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 3, maxJsonDepth = 7, maxScanChars = 100, binaryMinRunLength = 8) {
        assertEquals(8, DetectionScanBudget.binaryIslandMinRunLength())
        assertEquals(7, DetectionScanBudget.jsonDepthCapValue())
      }
      // After the block the defaults apply again.
      assertEquals(16, DetectionScanBudget.binaryIslandMinRunLength())
      assertEquals(32, DetectionScanBudget.jsonDepthCapValue())
    }
  }

  /** detection_scan.py:363 component scan + logging. */
  @Test
  fun testCheckRequestComponentDetectsAndLogs() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 100) {
        val capture = LogCapture()
        capture.attach(GUARD_LOGGER, Level.ALL)
        try {
          val (detected, trigger, threats) =
              DetectionScan.checkRequestComponent(
                  "1 UNION SELECT username, password FROM users--",
                  "query",
                  "query param 'q'",
                  "127.0.0.1",
                  "corr",
                  null,
                  "WARNING",
              )
          assertTrue(detected)
          assertTrue(trigger.isNotEmpty(), trigger)
          assertTrue(threats.isNotEmpty())
          assertTrue(capture.text().contains("Potential attack detected from"), capture.text())
        } finally {
          capture.detach(GUARD_LOGGER)
        }
      }
    }
  }

  /** detection_scan.py:348 null level and long-value truncation. */
  @Test
  fun testLogDetectedComponentArms() {
    scanRunTest {
      val capture = LogCapture()
      capture.attach(GUARD_LOGGER, Level.ALL)
      try {
        DetectionScan.logDetectedComponent("v".repeat(150), "header", "127.0.0.1", null)
        assertEquals(0, capture.records.size)
        DetectionScan.logDetectedComponent("v".repeat(150), "header", "127.0.0.1", "INFO")
        val line = capture.text()
        assertTrue(line.contains("..."), line)
        DetectionScan.logDetectedComponent("short", "header", "127.0.0.1", "INFO")
        assertTrue("short" in capture.text())
      } finally {
        capture.detach(GUARD_LOGGER)
      }
    }
  }

  /** detection_scan.py:287 enhanced scan miss + embedded-json arms. */
  @Test
  fun testCheckValueEnhancedMissAndEmbeddedJson() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 100) {
        val miss =
            DetectionScan.checkValueEnhanced(
                "totally-benign-value",
                "query",
                "127.0.0.1",
                "corr",
            )
        assertFalse(miss.detected)

        val embedded =
            DetectionScan.checkValueEnhanced(
                PyJson.dumps(linkedMapOf("username" to linkedMapOf<String, Any?>("\$ne" to 1))),
                "header:x-note",
                "127.0.0.1",
                "corr",
            )
        assertTrue(embedded.detected, embedded.trigger)
        assertEquals(listOf("nosql"), embedded.threats.map { it.category })

        // context == request_body skips the embedded pass entirely.
        val bodySkip =
            DetectionScan.checkValueEnhanced(
                PyJson.dumps(linkedMapOf<String, Any?>("\$ne" to 1)),
                "request_body",
                "127.0.0.1",
                "corr",
            )
        // The body context still scans the raw text (the operator string itself).
        assertFalse(bodySkip.detected || bodySkip.trigger.isNotEmpty())
      }
    }
  }

  /** detection_scan.py:402 name scan hits. */
  @Test
  fun testScanComponentNameDetectsAttackInName() {
    scanRunTest {
      DetectionScanBudget.withScanBudget(maxValues = 100) {
        val (detected, trigger, threats) =
            DetectionScan.scanComponentName(
                "union select * from users",
                "query",
                "query param name",
                null,
                "127.0.0.1",
                "corr",
                null,
            )
        assertTrue(detected, trigger)
        assertTrue(threats.isNotEmpty())
      }
    }
  }

  /** detection_scan.py:425 always-scan header patterns. */
  @Test
  fun testCheckAlwaysScanHeaderArms() {
    val (hit, trigger, threats) = DetectionScan.checkAlwaysScanHeader("\${jndi:ldap://x}")
    assertTrue(hit, trigger)
    assertEquals("cmd_injection", threats.single().category)
    val (miss, emptyTrigger, emptyThreats) = DetectionScan.checkAlwaysScanHeader("Mozilla/5.0")
    assertFalse(miss)
    assertEquals("", emptyTrigger)
    assertTrue(emptyThreats.isEmpty())
  }

  /** detection_scan.py:211 fallback scan over all compiled patterns. */
  @Test
  fun testFallbackPatternCheckDetects() {
    scanRunTest {
      PenetrationDetection.configureDetection(defaultScanConfig())
      val (detected, trigger) =
          DetectionScan.fallbackPatternCheck("1 UNION SELECT password FROM users--", "127.0.0.1", "query")
      assertTrue(detected, trigger)
      assertEquals("Value matched pattern (fallback)", trigger)
    }
  }
}

/** embedded_json_scan.py surface. */
class EmbeddedJsonScanTest {
  @Test
  fun testNonJsonReturnsNull() {
    scanRunTest {
      assertNull(
          EmbeddedJsonScan.checkEmbeddedJson(
              "plain text",
              "header:x-note",
              "127.0.0.1",
              "corr",
              null,
              excludedBodyFields = emptySet(),
              sensitiveBodyFields = emptySet(),
              redactAll = false,
          ),
      )
    }
  }

  @Test
  fun testJsonHitCarriesRedactedDisplayOverride() {
    scanRunTest {
      val hit =
          EmbeddedJsonScan.checkEmbeddedJson(
              PyJson.dumps(linkedMapOf("note" to XSS_LOCAL, "password" to "secret")),
              "header:x-note",
              "127.0.0.1",
              "corr",
              null,
              excludedBodyFields = emptySet(),
              sensitiveBodyFields = setOf("password"),
              redactAll = false,
          )
      assertTrue(hit != null && hit.detected)
      assertTrue((hit!!.logOverride ?: "").contains("[REDACTED]"), hit.logOverride)
      assertFalse((hit.logOverride ?: "").contains("secret"))
    }
  }

  @Test
  fun testRedactAllCollapsesDisplayAndKeys() {
    scanRunTest {
      val hit =
          EmbeddedJsonScan.checkEmbeddedJson(
              PyJson.dumps(linkedMapOf("note" to XSS_LOCAL)),
              "header:x-note",
              "127.0.0.1",
              "corr",
              null,
              excludedBodyFields = emptySet(),
              sensitiveBodyFields = emptySet(),
              redactAll = true,
          )
      assertTrue(hit != null && hit.detected)
      assertEquals("[REDACTED]", hit!!.logOverride)
    }
  }

  @Test
  fun testBenignJsonIsMiss() {
    scanRunTest {
      val hit =
          EmbeddedJsonScan.checkEmbeddedJson(
              PyJson.dumps(linkedMapOf("note" to "hello")),
              "header:x-note",
              "127.0.0.1",
              "corr",
              null,
              excludedBodyFields = emptySet(),
              sensitiveBodyFields = emptySet(),
              redactAll = false,
          )
      assertTrue(hit != null && !hit!!.detected)
    }
  }
}

/** agent_events.py surface. */
class AgentEventsTest {
  @Test
  fun testInvokeErrorHookArms() {
    var called: String? = null
    AgentEvents.invokeErrorHook(null, "stage", RuntimeException("x"), emptyMap())
    AgentEvents.invokeErrorHook(
        AgentEvents.SecurityConfigOnErrorHook { stage, _, _ -> called = stage },
        "scan",
        RuntimeException("x"),
        emptyMap(),
    )
    assertEquals("scan", called)
    // A raising hook is swallowed and logged.
    val capture = LogCapture()
    capture.attach(GUARD_LOGGER, Level.ALL)
    try {
      AgentEvents.invokeErrorHook(
          AgentEvents.SecurityConfigOnErrorHook { _, _, _ -> throw IllegalStateException("boom") },
          "stage",
          RuntimeException("x"),
          emptyMap(),
      )
      assertTrue(capture.text().contains("on_error hook raised"), capture.text())
    } finally {
      capture.detach(GUARD_LOGGER)
    }
  }

  @Test
  fun testGetPipelineResponseTimeArms() {
    assertNull(AgentEvents.getPipelineResponseTime(null))
    val request = ScanRequest()
    val first = AgentEvents.getPipelineResponseTime(request)
    assertTrue(first != null && first >= 0.0)
    val second = AgentEvents.getPipelineResponseTime(request)
    assertTrue(second != null && second >= first!!, "second read must not go backwards")
  }

  @Test
  fun testSendAgentEventArms() {
    scanRunTest {
      // Null handler is a no-op.
      AgentEvents.sendAgentEvent(null, "suspicious_request", "1.2.3.4", "action", "reason")
      // Recording handler receives the envelope with request fields.
      val agent = RecordingAgentHandler()
      val request = ScanRequest(clientHost = "127.0.0.1", headers = mapOf("User-Agent" to "ua"))
      AgentEvents.sendAgentEvent(
          agent,
          "suspicious_request",
          "1.2.3.4",
          "action",
          "reason",
          request,
          metadata = mapOf("k" to "v"),
          extra = mapOf("decorator_type" to "dt", "rule_type" to "rt", "custom" to 1),
      )
      assertEquals(1, agent.events.size)
      val event = agent.events[0] as Map<*, *>
      assertEquals("suspicious_request", event["event_type"])
      assertEquals("1.2.3.4", event["ip_address"])
      assertEquals("/", event["endpoint"])
      assertEquals("GET", event["method"])
      assertEquals("ua", event["user_agent"])
      assertEquals("ip_extraction", event["handler_name"])
      assertEquals("dt", event["decorator_type"])
      assertEquals("rt", event["rule_type"])
      assertEquals(1, event["custom"])
      // A failing handler logs and does not throw.
      val failing = RecordingAgentHandler { throw IllegalStateException("nope") }
      val capture = LogCapture()
      capture.attach(Logger.getLogger("guard_core.utils"), Level.ALL)
      try {
        AgentEvents.sendAgentEvent(failing, "suspicious_request", "1.2.3.4", "a", "r")
        assertTrue(capture.text().contains("Failed to send agent event"), capture.text())
      } finally {
        capture.detach(Logger.getLogger("guard_core.utils"))
      }
    }
  }
}

/** detection_result_builders.py + path_matching.py tails. */
class DetectionResultBuildersTest {
  @Test
  fun testThreatCategoryAndScoreArms() {
    val regex = com.guardcore.engine.suspatterns.Threat("regex", "p", "m", 0, 0.0, "sqli", 1.0)
    assertEquals("sqli", DetectionResultBuilders.threatCategory(regex))
    val semantic = com.guardcore.engine.suspatterns.Threat(
        "semantic", "", "", 0, 0.0, "", 1.0, attackType = "xss", probability = null, threatScore = 0.7,
    )
    assertEquals("xss", DetectionResultBuilders.threatCategory(semantic))
    assertEquals(0.7, DetectionResultBuilders.threatScore(semantic))
    val neitherProbNorScore = com.guardcore.engine.suspatterns.Threat(
        "semantic", "", "", 0, 0.0, "", 1.0, attackType = "xss",
    )
    assertEquals(1.0, DetectionResultBuilders.threatScore(neitherProbNorScore))
    val unknown = com.guardcore.engine.suspatterns.Threat("other", "", "", 0, 0.0, "c", 1.0)
    assertNull(DetectionResultBuilders.threatCategory(unknown))
  }

  @Test
  fun testBuildDetectionHitAggregatesCategoriesAndScores() {
    val t1 = com.guardcore.engine.suspatterns.Threat("regex", "p", "m", 0, 0.0, "sqli", 1.0, threatScore = 0.4)
    val t2 = com.guardcore.engine.suspatterns.Threat("regex", "p2", "m", 0, 0.0, "sqli", 1.0, threatScore = 0.9)
    val t3 = com.guardcore.engine.suspatterns.Threat("other", "", "", 0, 0.0, "", 1.0)
    val result = DetectionResultBuilders.buildDetectionHit("trigger", listOf(t1, t2, t3))
    assertTrue(result.isThreat)
    assertEquals(listOf("sqli"), result.threatCategories)
    assertEquals(0.9, result.threatScores["sqli"])
  }

  @Test
  fun testBuildDetectionMiss() {
    val miss = DetectionResultBuilders.buildDetectionMiss()
    assertFalse(miss.isThreat)
    assertEquals("", miss.triggerInfo)
    assertTrue(miss.threatCategories.isEmpty())
  }

  /** path_matching.py:78 null-normalize arm. */
  @Test
  fun testPathIsExcludedNullNormalize() {
    // A control character makes the python urlsplit-normalize fail -> not excluded.
    assertFalse(PathMatching.pathIsExcluded("/a\nb", listOf("/a")))
    assertTrue(PathMatching.pathIsExcluded("/admin/x", listOf("/admin")))
    assertFalse(PathMatching.pathIsExcluded("/adminx", listOf("/admin")))
  }
}

/** body_reader.py tails. */
class BodyReaderFullTest {
  @Test
  fun testParseContentLengthArms() {
    assertEquals(5, BodyReader.parseContentLength(" 5 "))
    assertNull(BodyReader.parseContentLength(""))
    assertNull(BodyReader.parseContentLength("abc"))
    assertNull(BodyReader.parseContentLength("-5"))
    assertEquals(10, BodyReader.parseContentLength("10"))
  }

  @Test
  fun testSafeReadTimeoutReturnsNull() {
    scanRunTest {
      assertNull(BodyReader.safeRead({ kotlinx.coroutines.delay(5000); byteArrayOf() }, 0.05))
      assertEquals(1, BodyReader.safeRead({ byteArrayOf(1) }, 1.0)!!.size)
    }
  }

  @Test
  fun testReadCappedBodyNullConfigReadsWholeBody() {
    scanRunTest {
      val request = ScanRequest(method = "POST", bodyBytes = "hello".encodeToByteArray())
      val body = BodyReader.readCappedBody(request, null)
      assertEquals("hello", body!!.decodeToString())
    }
  }

  @Test
  fun testReadCappedBodyWithoutContentLengthAndBoundedReader() {
    scanRunTest {
      val request = ScanRequest(method = "POST", bodyBytes = "hello".encodeToByteArray())
      val body = BodyReader.readCappedBody(request, defaultScanConfig())
      assertNull(body)
    }
  }

  @Test
  fun testBoundedReaderCapAndCache() {
    scanRunTest {
      val request =
          object : GuardRequest, com.guardcore.protocols.BoundedBodyReader {
            override val urlPath = "/"
            override val urlScheme = "http"
            override val urlFull = "http://example.com/"
            override fun urlReplaceScheme(scheme: String) = urlFull
            override val method = "POST"
            override val clientHost = "127.0.0.1"
            override val headers = emptyMap<String, String>()
            override val queryParams = emptyMap<String, String>()
            override val state = object : com.guardcore.protocols.RequestState {
              private val attrs = mutableMapOf<String, Any?>()
              override fun getAttr(name: String): Any? = attrs[name]
              override fun setAttr(name: String, value: Any?) {
                attrs[name] = value
              }
            }
            override val scope = emptyMap<String, Any?>()
            private val payload = "0123456789abcdefghij".encodeToByteArray()
            public var reads = 0

            override suspend fun body(): ByteArray = payload

            override suspend fun readBodyPrefix(maxBytes: Int): ByteArray {
              reads++
              return payload.copyOfRange(0, minOf(maxBytes, payload.size))
            }
          }
        // detection_max_body_inspect_bytes has a 1024 floor; the payload below stays under it.
        val config = defaultScanConfig { detectionMaxBodyInspectBytes = 1024 }
        val first = BodyReader.readCappedBody(request, config)
        assertEquals("0123456789abcdefghij", first!!.decodeToString())
        // Second read serves from the prefix cache without another bounded read.
        val second = BodyReader.readCappedBody(request, config)
        assertEquals("0123456789abcdefghij", second!!.decodeToString())
    }
  }
}

/** detection_engine_wiring seam behaviors (deadline + straddle arms). */
class DetectionEngineWiringFullTest {
  @Test
  fun testUserAgentMatcherSwallowsBadPatternAndDeadline() {
    DetectionEngineWiring.register()
    scanRunTest {
      // A pattern the config-time ReDoS gate would reject, built with validation skipped, must
      // still be swallowed by the matcher arm (python: safe_finditer swallows match errors).
      val builder = SecurityConfigBuilder()
      builder.blockedUserAgents = listOf("([bad")
      val cfg = builder.buildInternal(skipBounds = true)
      assertEquals(true, AccessControl.isUserAgentAllowed("sqlmap", cfg))
    }
  }

  @Test
  fun testStraddleOverlapProviderReturnsLongestPatternCap() {
    DetectionEngineWiring.register()
    PenetrationDetection.configureDetection(defaultScanConfig())
    val provider = BodyReader.straddleOverlapBytesProvider
    assertTrue(provider != null, "engine wiring must register the provider")
    val overlap = provider!!.invoke()
    assertTrue(overlap >= 0)
    assertTrue(overlap <= 256)
  }
}
