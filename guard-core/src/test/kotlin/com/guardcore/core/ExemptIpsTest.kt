package com.guardcore.core

import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.checks.implementations.CloudProviderCheck
import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.core.checks.implementations.RateLimitCheck
import com.guardcore.core.checks.implementations.SuspiciousActivityCheck
import com.guardcore.core.checks.implementations.UserAgentCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.protocols.RouteConfigResolverProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_exempt_ips.py: the exempt-ips contract - the flag is set from the
 * global exempt list, it does not whitelist anyone, and the rate-limit / user-agent /
 * cloud-provider checks skip exempt requests while penetration detection still scans them.
 */
class ExemptIpsTest {
  private val exemptIp = "198.51.100.7"
  private val otherIp = "203.0.113.9"

  private class StubResolver : RouteConfigResolverProtocol {
    override fun getRouteConfig(request: com.guardcore.protocols.GuardRequest): Any? = null

    override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean = false

    override fun getCloudProvidersToCheck(routeConfig: Any?): List<String> = listOf("AWS")
  }

  private fun middleware(config: com.guardcore.config.SecurityConfig): TestMiddleware =
      TestMiddleware(config, resolver = StubResolver())

  private fun request(
      ip: String,
      routeConfig: RouteConfig? = null,
      userAgent: String = "curl/8.0",
      state: Map<String, Any?> = emptyMap(),
  ): TestRequest {
    val request =
        TestRequest(clientHost = ip, urlPath = "/api", headers = mapOf("User-Agent" to userAgent))
    request.state.setAttr("client_ip", ip)
    routeConfig?.let { request.state.setAttr("route_config", it) }
    for ((k, v) in state) request.state.setAttr(k, v)
    return request
  }

  private suspend fun ipCheck(
      config: com.guardcore.config.SecurityConfig,
      request: TestRequest,
  ): com.guardcore.protocols.GuardResponse? = IpSecurityCheck(middleware(config)).check(request)

  /** test_exempt_match_sets_the_flag_without_blocking_anyone (parametrized over 4 ips). */
  @Test
  fun exemptMatchSetsTheFlagWithoutBlockingAnyone() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp, "198.51.100.16/28")
        enableIpBanning = true
      }
      val cases =
          mapOf(
              exemptIp to true,
              "198.51.100.20" to true, // inside 198.51.100.16/28
              otherIp to false,
              "unknown" to false,
          )
      for ((ip, expected) in cases) {
        val req = request(ip)
        assertNull(ipCheck(config, req), "ip=$ip must not be blocked")
        assertEquals(expected, req.state.getAttr("is_exempt"), "is_exempt for ip=$ip")
        assertEquals(false, req.state.getAttr("is_whitelisted"))
      }
    }
  }

  @Test
  fun blacklistedExemptIpIsStillBlocked() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        blacklist = listOf(exemptIp)
        enableIpBanning = true
      }
      val req = request(exemptIp)
      val result = ipCheck(config, req)
      assertTrue(result != null, "a blacklisted exempt ip must still be blocked")
      assertEquals(false, req.state.getAttr("is_exempt"))
    }
  }

  @Test
  fun bannedExemptIpIsStillBlocked() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        enableIpBanning = true
      }
      IpBanManager.getInstance().bannedIps[exemptIp] = System.currentTimeMillis() / 1000.0 + 3600
      val result = ipCheck(config, request(exemptIp))
      assertTrue(result != null, "a banned exempt ip must still be blocked")
    }
  }

  @Test
  fun exemptIpDoesNotPassARestrictiveWhitelist() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        whitelist = listOf(otherIp)
        enableIpBanning = true
      }
      val req = request(exemptIp)
      val result = ipCheck(config, req)
      assertTrue(result != null, "exempt status must not satisfy a restrictive whitelist")
      assertEquals(false, req.state.getAttr("is_exempt"))
    }
  }

  @Test
  fun routeBlockIpStillBlocksAnExemptIp() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        enableIpBanning = true
      }
      val routeConfig = RouteConfig()
      routeConfig.ipBlacklist = listOf(exemptIp)
      val result = ipCheck(config, request(exemptIp, routeConfig))
      assertTrue(result != null, "a route-level block must still hit an exempt ip")
    }
  }

  @Test
  fun routeRequireIpTakesOverAsItDoesForTheWhitelist() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        whitelist = listOf(exemptIp)
        enableIpBanning = true
      }
      val routeConfig = RouteConfig()
      routeConfig.ipWhitelist = listOf(exemptIp)
      val req = request(exemptIp, routeConfig)
      assertNull(ipCheck(config, req))
      assertEquals(false, req.state.getAttr("is_whitelisted"))
      assertEquals(false, req.state.getAttr("is_exempt"))
    }
  }

  /** test_global_cloud_block_still_applies_as_it_does_for_the_whitelist (whitelist/exempt_ips). */
  @Test
  fun globalCloudBlockStillAppliesAsItDoesForTheWhitelist() {
    coreRunTest {
      resetIpBanGlobalState()
      for (ipListField in listOf("whitelist", "exempt_ips")) {
        val config = coreTestConfig {
          blockCloudProviders = setOf("AWS")
          if (ipListField == "whitelist") {
            whitelist = listOf(exemptIp)
          } else {
            exemptIps = listOf(exemptIp)
          }
          enableIpBanning = true
        }
        val cloud = CloudManager.getInstance()
        cloud.isCloudIpOverride = { ip, providers ->
          ip == exemptIp && providers == setOf("AWS")
        }
        cloud.cloudProviderDetailsOverride = { ip, _ -> Pair("AWS", "3.0.0.0/8") }
        try {
          val result = ipCheck(config, request(exemptIp))
          assertTrue(
              result != null,
              "global cloud block must still apply through $ipListField",
          )
        } finally {
          cloud.isCloudIpOverride = null
          cloud.cloudProviderDetailsOverride = null
        }
      }
    }
  }

  /** The _run_twice helper: exempt and non-exempt state for the same ip. */
  private suspend fun runTwice(
      check: SecurityCheck,
      userAgent: String = "curl/8.0",
      routeConfig: RouteConfig? = null,
  ): Pair<com.guardcore.protocols.GuardResponse?, com.guardcore.protocols.GuardResponse?> {
    val exempt =
        check.check(
            request(
                exemptIp,
                routeConfig,
                userAgent,
                state = mapOf("is_whitelisted" to false, "is_exempt" to true),
            ),
        )
    val notExempt =
        check.check(
            request(
                exemptIp,
                routeConfig,
                userAgent,
                state = mapOf("is_whitelisted" to false, "is_exempt" to false),
            ),
        )
    return Pair(exempt, notExempt)
  }

  @Test
  fun rateLimitIsSkippedForAnExemptRequest() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        enableRateLimiting = true
        rateLimit = 1
      }
      val mw = middleware(config)
      val check = RateLimitCheck(mw)
      val manager = mw.rateLimitHandler as com.guardcore.handlers.RateLimitManager
      manager.reset()
      val routeConfig = RouteConfig()
      routeConfig.rateLimit = 1
      // Warm the counter past the limit (the python test mocks check_rate_limit to a constant
      // 429; against the live manager the non-exempt leg must be a request OVER the limit).
      repeat(2) {
        check.check(request(exemptIp, routeConfig, state = mapOf("is_exempt" to false)))
      }
      val (exempt, notExempt) = runTwice(check, routeConfig = routeConfig)
      assertNull(exempt, "rate limiting must be skipped for an exempt request")
      assertTrue(notExempt != null, "rate limiting must apply to a non-exempt request")
    }
  }

  @Test
  fun userAgentCheckIsSkippedForAnExemptRequest() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        blockedUserAgents = listOf("badbot")
      }
      val (exempt, notExempt) =
          runTwice(UserAgentCheck(middleware(config)), userAgent = "badbot/1.0")
      assertNull(exempt, "the user-agent check must be skipped for an exempt request")
      assertTrue(notExempt != null, "the user-agent check must apply to a non-exempt request")
    }
  }

  @Test
  fun cloudProviderCheckIsSkippedForAnExemptRequest() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
        blockCloudProviders = setOf("AWS")
      }
      val cloud = CloudManager.getInstance()
      cloud.isCloudIpOverride = { ip, _ -> ip == exemptIp }
      cloud.cloudProviderDetailsOverride = { _, _ -> Pair("AWS", "3.0.0.0/8") }
      try {
        val (exempt, notExempt) = runTwice(CloudProviderCheck(middleware(config)))
        assertNull(exempt, "the cloud-provider check must be skipped for an exempt request")
        assertTrue(notExempt != null, "the cloud-provider check must apply to a non-exempt request")
      } finally {
        cloud.isCloudIpOverride = null
        cloud.cloudProviderDetailsOverride = null
      }
    }
  }

  @Test
  fun penetrationDetectionStillScansAnExemptRequest() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        exemptIps = listOf(exemptIp)
      }
      val check = SuspiciousActivityCheck(middleware(config))
      val req =
          request(
              exemptIp,
              state = mapOf("is_whitelisted" to false, "is_exempt" to true),
          )
      // get_cached_detection_result patch: seed the state cache with a threat.
      val threat =
          com.guardcore.DetectionResult(
              isThreat = true,
              triggerInfo = "xss",
              threatCategories = listOf("xss"),
          )
      req.state.setAttr(
          ChecksHelpers.DETECTION_RESULT_STATE_ATTR,
          Triple<
              com.guardcore.protocols.GuardRequest,
              com.guardcore.decorators.RouteConfig?,
              com.guardcore.DetectionResult,
          >(
              req,
              null,
              threat,
          ),
      )
      val result = check.check(req)
      assertTrue(result != null, "penetration detection must still scan an exempt request")
    }
  }

  @Test
  fun exemptIpsDefaultsToEmpty() {
    assertEquals(emptyList(), coreTestConfig().exemptIps)
  }

  @Test
  fun aPrefixZeroExemptEntryWarns() {
    val records = mutableListOf<java.util.logging.LogRecord>()
    val handler =
        object : java.util.logging.Handler() {
          override fun publish(record: java.util.logging.LogRecord) {
            records.add(record)
          }

          override fun flush() {}

          override fun close() {}
        }
    val logger = com.guardcore.config.ConfigWarnings.logger
    logger.addHandler(handler)
    logger.level = java.util.logging.Level.WARNING
    try {
      coreTestConfig { exemptIps = listOf("0.0.0.0/0") }
    } finally {
      logger.removeHandler(handler)
    }
    assertTrue(
        records.any { it.message.contains("exempt_ips contains a /0 network") },
        "expected the /0 exemption warning, got: ${records.map { it.message }}",
    )
    assertFalse(records.isEmpty())
  }

  private fun nowSeconds(): Double = System.nanoTime() / 1_000_000_000.0
}
