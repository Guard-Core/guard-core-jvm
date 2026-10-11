package com.guardcore.core

import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.core.checks.implementations.UserAgentCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import java.util.logging.Level
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_block_vs_ban_escalation.py: a BLOCK (global ip, route ip, or user
 * agent) with a detected threat escalates through the shared helper - counts increment with the
 * REAL detected categories, thresholds ban, and ban failures never turn the block into a pass.
 *
 * Seam mapping: python patches `detect_penetration_patterns` with a fixed verdict; the JVM drives
 * the real engine with the payload on the request path (the counted categories are the engine's
 * own), the no-threat halves reach the identical "not_enabled" verdict through the disabled
 * config/route knobs, and the ban mock is the record-then-throw `banIpOverride` seam. The python
 * file calls the private `_check_global_ip_restrictions` / `_check_route_ip_restrictions` directly;
 * those steps are reached through `check()` with the route config absent (global step decides) or
 * carrying the block (route step decides), which drives the identical code path.
 */
public class BlockVsBanEscalationTest {
  /**
   * python rebuilds every mock per test; the ban fault-injection seam lives on the process
   * singleton, so it is dropped after each test or it intercepts real bans in later classes.
   */
  @org.junit.jupiter.api.AfterEach
  fun dropBanOverride() {
    com.guardcore.handlers.IpBanManager.getInstance().banIpOverride = null
  }

  private val xssPath = "/?q=<script>alert(1)</script>"
  private val sqliPath = "/?q=' OR '1'='1"

  private class RecordingLogger : java.util.logging.Logger("test.blockban", null) {
    var severeCount: Int = 0
    var severeMessages: MutableList<String> = mutableListOf()

    override fun log(level: Level, msg: String, thrown: Throwable) {
      if (level == Level.SEVERE) {
        severeCount += 1
        severeMessages.add(msg)
      }
    }
  }

  private class BanFailedFailingBus : com.guardcore.protocols.MiddlewareEventBusProtocol {
    override suspend fun sendMiddlewareEvent(
        eventType: String,
        request: com.guardcore.protocols.GuardRequest,
        actionTaken: String,
        reason: String,
        metadata: Map<String, Any?>,
    ) {
      if (eventType == "ip_ban_failed") {
        throw java.io.IOException("event bus down too")
      }
    }

    override suspend fun sendHttpsViolationEvent(
        request: com.guardcore.protocols.GuardRequest,
        routeConfig: Any?,
    ) {}

    override suspend fun sendCloudDetectionEvents(
        request: com.guardcore.protocols.GuardRequest,
        clientIp: String,
        cloudProvidersToCheck: List<String>,
        routeConfig: Any?,
        cloudHandler: Any?,
        passiveMode: Boolean,
    ) {}
  }

  /** python `_make_middleware`: the check config with the recording bus. */
  private fun middleware(
      config: com.guardcore.config.SecurityConfig,
      logger: java.util.logging.Logger? = null,
  ): TestMiddleware = TestMiddleware(config).also { if (logger != null) it.loggerOverride = logger }

  /** python `_make_request`: preset identity state, badbot UA, and the threat payload path. */
  private fun request(
      clientIp: String? = "1.2.3.4",
      urlPath: String = xssPath,
      routeConfig: RouteConfig? = null,
  ): TestRequest {
    val req =
        TestRequest(
            clientHost = clientIp ?: "192.0.2.1",
            urlPath = urlPath,
            headers = mapOf("User-Agent" to "badbot"),
        )
    req.state.setAttr("client_ip", clientIp)
    req.state.setAttr("route_config", routeConfig)
    req.state.setAttr("is_whitelisted", false)
    return req
  }

  private fun routeConfig(mutate: RouteConfig.() -> Unit = {}): RouteConfig =
      RouteConfig().apply(mutate)

  private fun recordingBan(
      banCalls: MutableList<Triple<String, Int, String>>,
      failWith: Throwable? = null,
  ) {
    IpBanManager.getInstance().banIpOverride = { ip, duration, reason ->
      banCalls.add(Triple(ip, duration, reason))
      failWith?.let { throw it }
      true
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:59-84

  @Test
  fun globalIpBlockWithThreatIncrementsCounter() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1000
        blacklist = listOf("20.0.0.1")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = "20.0.0.1"))

      assertNotNull(result)
      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["20.0.0.1"])
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:87-114

  @Test
  fun globalIpBlockWithThreatRepeatedTriggersBan() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 2
        autoBanDuration = 300
        blacklist = listOf("21.0.0.1")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      check.check(request(clientIp = "21.0.0.1"))
      assertEquals(0, banCalls.size)
      check.check(request(clientIp = "21.0.0.1"))

      assertEquals(listOf(Triple("21.0.0.1", 300, "penetration_attempt")), banCalls)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:117-143

  @Test
  fun globalIpBlockNoThreatNoCounterChange() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
        blacklist = listOf("22.0.0.1")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = "22.0.0.1"))

      assertNotNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:146-184

  @Test
  fun globalIpBlockPassiveModeNoEscalation() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = true
        enableIpBanning = true
        autoBanThreshold = 1
        blacklist = listOf("23.0.0.1")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = "23.0.0.1"))

      assertNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
      assertTrue(
          mw.bus.events.none { it["event_type"] == "penetration_attempt" },
          "passive mode must not escalate",
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:187-215

  @Test
  fun globallyWhitelistedIpBlockedByRouteWhitelistIsNotWhitelisted() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
        whitelist = listOf("24.0.0.1")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipWhitelist = listOf("9.9.9.9") }
      val request = request(clientIp = "24.0.0.1", urlPath = "/api", routeConfig = rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:218-253

  @Test
  fun globalWhitelistBlockedByStricterRouteWhitelistEscalates() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        whitelist = listOf("203.0.113.0/24")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipWhitelist = listOf("10.0.0.1") }
      val request = request(clientIp = "203.0.113.55", urlPath = sqliPath, routeConfig = rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
      assertEquals<Map<String, Int>?>(
          mapOf("sqli" to 1),
          mw.suspiciousRequestCounts["203.0.113.55"],
      )
      assertEquals(
          listOf(Triple("203.0.113.55", config.autoBanDuration, "penetration_attempt")),
          banCalls,
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:256-290

  @Test
  fun globalWhitelistBlockedByRouteBlacklistStillEscalates() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        whitelist = listOf("203.0.113.0/24")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipBlacklist = listOf("203.0.113.55") }
      val request = request(clientIp = "203.0.113.55", urlPath = sqliPath, routeConfig = rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals<Map<String, Int>?>(
          mapOf("sqli" to 1),
          mw.suspiciousRequestCounts["203.0.113.55"],
      )
      assertEquals(
          listOf(Triple("203.0.113.55", config.autoBanDuration, "penetration_attempt")),
          banCalls,
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:293-326

  @Test
  fun routeBlacklistWithoutGlobalWhitelistEscalatesAsControl() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipBlacklist = listOf("203.0.113.55") }
      val request = request(clientIp = "203.0.113.55", urlPath = sqliPath, routeConfig = rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals<Map<String, Int>?>(
          mapOf("sqli" to 1),
          mw.suspiciousRequestCounts["203.0.113.55"],
      )
      assertEquals(
          listOf(Triple("203.0.113.55", config.autoBanDuration, "penetration_attempt")),
          banCalls,
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:329-355

  @Test
  fun globalWhitelistAndRouteWhitelistBothContainingIpIsAllowed() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
        whitelist = listOf("203.0.113.0/24")
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipWhitelist = listOf("203.0.113.55") }
      val request = request(clientIp = "203.0.113.55", urlPath = "/api", routeConfig = rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:358-385
  // python patches check_route_ip_access to False; the JVM blocks at the route step through the
  // real route blacklist, which drives the identical route-step + escalation path.

  @Test
  fun routeIpBlockWithThreatIncrementsCounter() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1000
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipBlacklist = listOf("24.0.0.1") }
      val request = request(clientIp = "24.0.0.1", routeConfig = rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["24.0.0.1"])
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:388-416

  @Test
  fun routeIpBlockNoThreatNoCounterChange() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig {
        ipBlacklist = listOf("24.5.0.1")
        enableSuspiciousDetection = false
      }
      val request = request(clientIp = "24.5.0.1", routeConfig = rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:419-456

  @Test
  fun routeIpBlockPassiveModeNoEscalation() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = true
        enableIpBanning = true
        autoBanThreshold = 1
      }
      val mw = middleware(config)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)
      val rc = routeConfig { ipBlacklist = listOf("25.0.0.1") }
      val request = request(clientIp = "25.0.0.1", routeConfig = rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertTrue(
          mw.bus.events.none { it["event_type"] == "penetration_attempt" },
          "passive mode must not escalate",
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:459-479

  @Test
  fun userAgentBlockWithThreatIncrementsCounter() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1000
        blockedUserAgents = listOf("badbot")
      }
      val mw = middleware(config)
      val check = UserAgentCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = "26.0.0.1"))

      assertNotNull(result)
      assertEquals<Map<String, Int>?>(mapOf("xss" to 1), mw.suspiciousRequestCounts["26.0.0.1"])
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:482-502

  @Test
  fun userAgentBlockWithThreatRepeatedTriggersBan() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 2
        autoBanDuration = 300
        blockedUserAgents = listOf("badbot")
      }
      val mw = middleware(config)
      val check = UserAgentCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      check.check(request(clientIp = "27.0.0.1"))
      assertEquals(0, banCalls.size)
      check.check(request(clientIp = "27.0.0.1"))
      assertEquals(listOf(Triple("27.0.0.1", 300, "penetration_attempt")), banCalls)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:505-525

  @Test
  fun userAgentBlockNoThreatNoCounterChange() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        enablePenetrationDetection = false
        blockedUserAgents = listOf("badbot")
      }
      val mw = middleware(config)
      val check = UserAgentCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = "28.0.0.1"))

      assertNotNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertEquals(0, banCalls.size)
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:528-558

  @Test
  fun userAgentBlockPassiveModeNoEscalation() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = true
        enableIpBanning = true
        autoBanThreshold = 1
        blockedUserAgents = listOf("badbot")
      }
      val mw = middleware(config)
      val check = UserAgentCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = "29.0.0.1"))

      assertNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertTrue(
          mw.bus.events.none { it["event_type"] == "penetration_attempt" },
          "passive mode must not escalate",
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:561-591

  @Test
  fun userAgentBlockNoClientIpSkipsEscalation() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        blockedUserAgents = listOf("badbot")
      }
      val mw = middleware(config)
      val check = UserAgentCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls)

      val result = check.check(request(clientIp = null))

      assertNotNull(result)
      assertEquals(0, mw.suspiciousRequestCounts.size)
      assertTrue(
          mw.bus.events.none { it["event_type"] == "penetration_attempt" },
          "no client ip means no escalation",
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:594-622
  // python counts detect calls; the JVM pins the same single-scan property through the
  // detection-result cache the helper installs in the request state (one cache entry, one scan).

  @Test
  fun noDoubleCountBlockedProbeIncrementsOnce() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1000
        blockedUserAgents = listOf("badbot")
      }
      val mw = middleware(config)
      val check = UserAgentCheck(mw)
      val request = request(clientIp = "30.0.0.1")

      check.check(request)

      assertEquals(
          1,
          mw.suspiciousRequestCounts["30.0.0.1"]?.get("xss"),
          "a blocked probe increments exactly once",
      )
      assertNotNull(
          request.state.getAttr(
              com.guardcore.core.checks.ChecksHelpers.DETECTION_RESULT_STATE_ATTR,
          ),
          "the single scan is cached in the request state",
      )
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:625-658

  @Test
  fun globalIpBlockStillReturns403WhenBanIpRaises() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 7200
        blacklist = listOf("50.0.0.1")
      }
      val logger = RecordingLogger()
      val mw = middleware(config, logger = logger)
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = IllegalStateException("duration exceeds local cap"))

      val result = check.check(request(clientIp = "50.0.0.1"))

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(listOf(Triple("50.0.0.1", 7200, "penetration_attempt")), banCalls)
      assertEquals(1, logger.severeCount)
      assertTrue(logger.severeMessages[0].contains("50.0.0.1"))
      assertEquals("ip_ban_failed", mw.bus.events.last()["event_type"])
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:663-689

  @Test
  fun userAgentBlockStillReturns403WhenBanIpRaises() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        autoBanDuration = 7200
        blockedUserAgents = listOf("badbot")
      }
      val logger = RecordingLogger()
      val mw = middleware(config, logger = logger)
      val check = UserAgentCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = IllegalStateException("duration exceeds local cap"))

      val result = check.check(request(clientIp = "51.0.0.1"))

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(listOf(Triple("51.0.0.1", 7200, "penetration_attempt")), banCalls)
      assertEquals(1, logger.severeCount)
      assertTrue(logger.severeMessages[0].contains("51.0.0.1"))
      assertEquals("ip_ban_failed", mw.bus.events.last()["event_type"])
    }
  }

  // ------------------------------- test_block_vs_ban_escalation.py:692-729

  @Test
  fun globalIpBlockSurvivesBanAndEventBusBothFailing() {
    coreRunTest {
      resetCoreBanState()
      val config = coreTestConfig {
        passiveMode = false
        enableIpBanning = true
        autoBanThreshold = 1
        failSecure = true
        blacklist = listOf("52.0.0.1")
      }
      val logger = RecordingLogger()
      val mw = middleware(config, logger = logger)
      mw.eventBusOverride = BanFailedFailingBus()
      val check = IpSecurityCheck(mw)
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, failWith = IllegalStateException("redis down, ban not applied"))

      val result = check.check(request(clientIp = "52.0.0.1"))

      assertNotNull(result)
      assertEquals(403, result.statusCode)
      assertEquals(2, logger.severeCount)
    }
  }
}
