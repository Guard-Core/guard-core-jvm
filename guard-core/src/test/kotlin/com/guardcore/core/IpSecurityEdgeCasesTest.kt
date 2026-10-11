package com.guardcore.core

import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.resetIpBanGlobalState
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RouteConfigResolverProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_ip_security_edge_cases.py: the banned-ip bypass and passive halves,
 * the missing/unknown client-identity halves, and the whitelist/country-whitelist escalation
 * blocks. The python file patches internal helpers; the JVM drives the real paths (the escalation
 * helper is exception-safe and the ban manager is empty).
 */
class IpSecurityEdgeCasesTest {
  private class BypassAllResolver : RouteConfigResolverProtocol {
    override fun getRouteConfig(request: GuardRequest): Any? = null

    override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean = true

    override fun getCloudProvidersToCheck(routeConfig: Any?): List<String> = emptyList()
  }

  private class BypassIpOnlyResolver : RouteConfigResolverProtocol {
    override fun getRouteConfig(request: GuardRequest): Any? = null

    override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean =
        checkName == "ip"

    override fun getCloudProvidersToCheck(routeConfig: Any?): List<String> = emptyList()
  }

  private class StubGeoHandler : GeoIPHandler {
    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override fun getCountry(ip: String): String? = null

    override suspend fun refresh() {}

    override fun close() {}
  }

  private fun request(
      clientIp: String?,
      routeConfig: RouteConfig? = null,
  ): TestRequest {
    val req = TestRequest(clientHost = clientIp)
    req.state.setAttr("client_ip", clientIp)
    req.state.setAttr("route_config", routeConfig)
    return req
  }

  @Test
  fun checkBannedIpBypass() {
    coreRunTest {
      resetIpBanGlobalState()
      val mw = TestMiddleware(coreTestConfig(), resolver = BypassAllResolver())
      val check = IpSecurityCheck(mw)
      val req = request("1.2.3.4", RouteConfig())
      assertNull(check.check(req), "a route-level ip_ban bypass must skip the ban check")
    }
  }

  @Test
  fun checkBannedIpPassiveMode() {
    coreRunTest {
      resetIpBanGlobalState()
      val mw = TestMiddleware(coreTestConfig { passiveMode = true })
      val check = IpSecurityCheck(mw)
      IpBanManager.getInstance().bannedIps["1.2.3.4"] = System.currentTimeMillis() / 1000.0 + 3600
      val req = request("1.2.3.4")
      assertNull(check.check(req), "passive mode must not block a banned ip")
      assertTrue(mw.bus.events.isNotEmpty())
      assertEquals("logged_only", mw.bus.events.last()["action_taken"])
    }
  }

  @Test
  fun checkRouteIpRestrictionsPassiveMode() {
    coreRunTest {
      resetIpBanGlobalState()
      val mw = TestMiddleware(coreTestConfig { passiveMode = true })
      val check = IpSecurityCheck(mw)
      val routeConfig = RouteConfig()
      routeConfig.ipBlacklist = listOf("1.2.3.4")
      val req = request("1.2.3.4", routeConfig)
      assertNull(check.check(req), "passive mode must not enforce a route ip restriction")
    }
  }

  @Test
  fun checkWithNoClientIp() {
    coreRunTest {
      resetIpBanGlobalState()
      val check = IpSecurityCheck(TestMiddleware(coreTestConfig()))
      val req = request(null)
      assertNull(check.check(req), "a request without a client ip must be skipped")
    }
  }

  @Test
  fun checkGlobalIpRestrictionsPassiveMode() {
    coreRunTest {
      resetIpBanGlobalState()
      val mw = TestMiddleware(coreTestConfig { passiveMode = true })
      val check = IpSecurityCheck(mw)
      val req = request("1.2.3.4")
      assertNull(
          check.check(req),
          "passive mode must not block on the global restriction (empty lists allow)",
      )
    }
  }

  @Test
  fun checkWithBypassIpCheck() {
    coreRunTest {
      resetIpBanGlobalState()
      val mw = TestMiddleware(coreTestConfig(), resolver = BypassIpOnlyResolver())
      val check = IpSecurityCheck(mw)
      val req = request("1.2.3.4")
      assertNull(check.check(req), "the ip bypass flag must skip the whole check")
    }
  }

  @Test
  fun fullFlowWithRouteConfig() {
    coreRunTest {
      resetIpBanGlobalState()
      val check = IpSecurityCheck(TestMiddleware(coreTestConfig()))
      val req = request("1.2.3.4", RouteConfig())
      assertNull(check.check(req), "an empty route config must not block a clean ip")
    }
  }

  @Test
  fun unknownClientIdentityNotBlockedWithDefaultConfig() {
    coreRunTest {
      resetIpBanGlobalState()
      val check = IpSecurityCheck(TestMiddleware(coreTestConfig()))
      val req = request("unknown")
      assertNull(check.check(req), "an unknown identity must pass with the default config")
    }
  }

  @Test
  fun unknownClientIdentityBlockedWhenWhitelistConfigured() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig { whitelist = listOf("10.0.0.1") }
      val check = IpSecurityCheck(TestMiddleware(config))
      val result = check.check(request("unknown"))
      assertTrue(result != null, "an unknown identity must be blocked with a whitelist")
      assertEquals(403, result!!.statusCode)
    }
  }

  @Test
  fun unknownClientIdentityBlockedWhenWhitelistCountriesConfigured() {
    coreRunTest {
      resetIpBanGlobalState()
      val config = coreTestConfig {
        whitelistCountries = setOf("US")
        geoIpHandler = StubGeoHandler()
      }
      val check = IpSecurityCheck(TestMiddleware(config, geoIpHandler = StubGeoHandler()))
      val result = check.check(request("unknown"))
      assertTrue(result != null, "an unknown identity must be blocked with country whitelisting")
      assertEquals(403, result!!.statusCode)
    }
  }

  @Test
  fun unknownClientIdentityWithEmptyRouteConfigNotBlocked() {
    coreRunTest {
      resetIpBanGlobalState()
      val check = IpSecurityCheck(TestMiddleware(coreTestConfig()))
      val req = request("unknown", RouteConfig())
      assertNull(check.check(req), "an empty route config must not block an unknown identity")
    }
  }

  @Test
  fun unknownClientIdentityWithRouteWhitelistBlocked() {
    coreRunTest {
      resetIpBanGlobalState()
      val routeConfig = RouteConfig()
      routeConfig.ipWhitelist = listOf("10.0.0.1")
      val check = IpSecurityCheck(TestMiddleware(coreTestConfig()))
      val result = check.check(request("unknown", routeConfig))
      assertTrue(result != null, "a route whitelist must block an unknown identity")
      assertEquals(403, result!!.statusCode)
    }
  }

  @Test
  fun unknownClientIdentityWithRouteWhitelistCountriesBlocked() {
    coreRunTest {
      resetIpBanGlobalState()
      val routeConfig = RouteConfig()
      routeConfig.whitelistCountries = listOf("US")
      // The config-level country rule validator needs a handler when country rules exist.
      val check =
          IpSecurityCheck(
              TestMiddleware(
                  coreTestConfig { geoIpHandler = StubGeoHandler() },
                  geoIpHandler = StubGeoHandler(),
              ),
          )
      val result = check.check(request("unknown", routeConfig))
      assertTrue(
          result != null,
          "a route country whitelist must block an unknown identity",
      )
      assertEquals(403, result!!.statusCode)
    }
  }

  @Test
  fun unknownClientIdentityWithRouteBlacklistNotBlocked() {
    coreRunTest {
      resetIpBanGlobalState()
      val routeConfig = RouteConfig()
      routeConfig.ipBlacklist = listOf("10.0.0.1")
      val check = IpSecurityCheck(TestMiddleware(coreTestConfig()))
      val req = request("unknown", routeConfig)
      assertNull(check.check(req), "a route blacklist must not block an unknown identity")
    }
  }
}
