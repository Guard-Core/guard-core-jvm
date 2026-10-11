package com.guardcore.core

import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.isIpBanned
import com.guardcore.handlers.resetIpBanGlobalState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * Port of tests/test_core/test_helpers.py (ip list membership, country access, route ip access,
 * credential extraction, referrer domain matching) and the suspicious-counts surface of
 * test_suspicious_counts_concurrency.py.
 */
public class ChecksHelpersTest {
  private val config = coreTestConfig()
  private val middleware = TestMiddleware(config)

  /** test_helpers.py:27-57: ip list membership. */
  @Test
  fun ipListMembership() {
    val addr = com.guardcore.util.py.parseAddress("192.0.2.1")
    assertTrue(ChecksHelpers.isIpInBlacklist("192.0.2.1", addr, listOf("192.0.2.1")))
    assertTrue(ChecksHelpers.isIpInBlacklist("192.0.2.1", addr, listOf("192.0.2.0/24")))
    assertFalse(ChecksHelpers.isIpInBlacklist("192.0.2.1", addr, listOf("10.0.0.1")))
    assertNull(ChecksHelpers.isIpInWhitelist("192.0.2.1", addr, emptyList()))
    assertEquals(true, ChecksHelpers.isIpInWhitelist("192.0.2.1", addr, listOf("192.0.2.1")))
    assertEquals(true, ChecksHelpers.isIpInWhitelist("192.0.2.1", addr, listOf("192.0.2.0/24")))
    assertEquals(false, ChecksHelpers.isIpInWhitelist("192.0.2.1", addr, listOf("10.0.0.1")))
  }

  private class StubGeo(private val table: Map<String, String>) :
      com.guardcore.protocols.GeoIPHandler {
    override val isInitialized: Boolean = true

    override fun getCountry(ip: String): String? = table[ip]

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override suspend fun refresh() {}

    override fun close() {}
  }

  /** test_helpers.py:59-111: check_country_access truth table. */
  @Test
  fun checkCountryAccess() {
    val geo = StubGeo(mapOf("192.0.2.1" to "CN"))
    val noHandler = RouteConfig()
    assertNull(ChecksHelpers.checkCountryAccess("192.0.2.1", noHandler, null))

    val blocked = RouteConfig()
    blocked.blockedCountries = listOf("CN")
    assertEquals(false, ChecksHelpers.checkCountryAccess("192.0.2.1", blocked, geo))
    assertNull(
        ChecksHelpers.checkCountryAccess("192.0.2.1", blocked, StubGeo(mapOf("192.0.2.1" to "US"))),
    )

    val whitelisted = RouteConfig()
    whitelisted.whitelistCountries = listOf("US")
    assertEquals(false, ChecksHelpers.checkCountryAccess("192.0.2.1", whitelisted, geo))
    assertEquals(
        true,
        ChecksHelpers.checkCountryAccess(
            "192.0.2.1",
            whitelisted,
            StubGeo(mapOf("192.0.2.1" to "US")),
        ),
    )
    assertEquals(
        false,
        ChecksHelpers.checkCountryAccess("192.0.2.1", whitelisted, StubGeo(emptyMap())),
    )
  }

  /** test_helpers.py:130-185: check_route_ip_access. */
  @Test
  fun checkRouteIpAccess() {
    coreRunTest {
      val geo = StubGeo(emptyMap())
      val route = RouteConfig()
      route.ipBlacklist = listOf("192.0.2.1")
      assertEquals(false, ChecksHelpers.checkRouteIpAccess("192.0.2.1", route, middleware))

      val allowRoute = RouteConfig()
      allowRoute.ipWhitelist = listOf("192.0.2.1")
      assertEquals(true, ChecksHelpers.checkRouteIpAccess("192.0.2.1", allowRoute, middleware))

      val badRoute = RouteConfig()
      badRoute.ipWhitelist = listOf("192.0.2.5")
      assertEquals(false, ChecksHelpers.checkRouteIpAccess("not-an-ip", badRoute, middleware))

      val plainRoute = RouteConfig()
      assertNull(ChecksHelpers.checkRouteIpAccess("192.0.2.1", plainRoute, middleware))
      assertEquals(
          null,
          ChecksHelpers.checkRouteIpAccess(
              com.guardcore.util.IpExtraction.UNKNOWN_CLIENT_IDENTITY,
              plainRoute,
              middleware,
          ),
      )
      assertEquals(
          false,
          ChecksHelpers.checkRouteIpAccess(
              com.guardcore.util.IpExtraction.UNKNOWN_CLIENT_IDENTITY,
              allowRoute,
              middleware,
          ),
      )
    }
  }

  /** test_helpers.py: extract_credential truth table (helpers.py:259-270). */
  @Test
  fun extractCredential() {
    assertEquals("tok" to "", ChecksHelpers.extractCredential("Bearer tok", "bearer"))
    assertEquals(
        null to "Missing or invalid Bearer token",
        ChecksHelpers.extractCredential("Basic tok", "bearer"),
    )
    assertEquals("user:pw" to "", ChecksHelpers.extractCredential("Basic user:pw", "basic"))
    assertEquals(
        null to "Missing or invalid Basic authentication",
        ChecksHelpers.extractCredential("Bearer tok", "basic"),
    )
    assertEquals("raw" to "", ChecksHelpers.extractCredential("raw", "api_key"))
    assertEquals(
        null to "Missing api_key authentication",
        ChecksHelpers.extractCredential("", "api_key"),
    )
  }

  /** test_helpers.py: is_referrer_domain_allowed (helpers.py:281-292). */
  @Test
  fun referrerDomainMatching() {
    assertTrue(
        ChecksHelpers.isReferrerDomainAllowed(
            "https://app.example.com/page",
            listOf("example.com"),
        ),
    )
    assertTrue(
        ChecksHelpers.isReferrerDomainAllowed("https://sub.example.com", listOf("example.com")),
    )
    assertTrue(
        ChecksHelpers.isReferrerDomainAllowed(
            "https://app.example.com",
            listOf("https://app.example.com"),
        ),
    )
    assertFalse(ChecksHelpers.isReferrerDomainAllowed("https://evil.com", listOf("example.com")))
    assertFalse(
        ChecksHelpers.isReferrerDomainAllowed("https://evilexample.com", listOf("example.com")),
    )
  }

  /** test_suspicious_counts_concurrency.py surface: counters accumulate per category. */
  @Test
  fun suspiciousCountsIncrement() {
    coreRunTest {
      resetIpBanGlobalState()
      ChecksHelpers.incrementSuspiciousCounts(
          middleware,
          "192.0.2.10",
          listOf("sqli", "sqli", "xss"),
      )
      assertEquals(2, middleware.suspiciousRequestCounts["192.0.2.10"]?.get("sqli"))
      assertEquals(1, middleware.suspiciousRequestCounts["192.0.2.10"]?.get("xss"))
      ChecksHelpers.incrementSuspiciousCounts(middleware, "192.0.2.10", "rate_limit")
      assertEquals(1, middleware.suspiciousRequestCounts["192.0.2.10"]?.get("rate_limit"))
    }
  }

  /** helpers.py:375-411 via the G-9 fold: threshold resolution against live counters. */
  @Test
  fun thresholdBanResolution() {
    runBlocking {
      resetIpBanGlobalState()
      val banningConfig = coreTestConfig {
        enableIpBanning = true
        autoBanThreshold = 2
        autoBanDuration = 1234
      }
      val ipBanManager = IpBanManager.getInstance()
      // total 1 < 2 -> no ban
      assertNull(
          ChecksHelpers.resolveAndApplyThresholdBan(
              mapOf("sqli" to 1),
              banningConfig,
              ipBanManager,
              "203.0.113.5",
              listOf("sqli"),
              "penetration_attempt",
          ),
      )
      // total 3 >= 2 -> flat fallback ban with the configured duration
      val result =
          ChecksHelpers.resolveAndApplyThresholdBan(
              mapOf("sqli" to 1, "xss" to 1, "lfi" to 1),
              banningConfig,
              ipBanManager,
              "203.0.113.5",
              listOf("sqli"),
              "penetration_attempt",
          )
      assertEquals(Triple(1234, "penetration_attempt", null), result)
      assertTrue(ipBanManager.isIpBanned("203.0.113.5"))
    }
  }
}
