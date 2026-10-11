package com.guardcore.core

import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.CloudManager
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.util.py.IpNetwork
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of tests/test_core/test_ip_security_global_route_merge.py: the global-vs-route IP control
 * merge semantics of IpSecurityCheck (decorated routes keep the global blacklist, route whitelists
 * override, country rules compose, cloud-provider and country blocks name their filter).
 *
 * Seam mapping: the python autouse fixture patches `ip_ban_manager.is_ip_banned` to False and
 * `escalate_identity_violation` to a no-op. On the JVM the ban manager drives the real singleton
 * emptied by [resetIpBanGlobalState], and the escalation is muted the way the reference exposes to
 * users: penetration detection off in the config and on the route config, so the escalation helper
 * returns before emitting (helpers.py:316-329 not_enabled branch) - the asserted events stay
 * exactly the ip_blocked / decorator_violation pair the python file pins.
 */
public class IpSecurityGlobalRouteMergeTest {
  private class StubGeoHandler(private val country: String?) : GeoIPHandler {
    override val isInitialized: Boolean = false

    override suspend fun initialize() {}

    override suspend fun initializeRedis(
        redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
    ) {}

    override suspend fun initializeAgent(
        agentHandler: com.guardcore.protocols.AgentHandlerProtocol,
    ) {}

    override fun getCountry(ip: String): String? = country

    override suspend fun refresh() {}

    override fun close() {}
  }

  /** The python fixture config: defaults with passive_mode=False (+ the escalation mute). */
  private fun mergeConfig(
      mutate: com.guardcore.config.SecurityConfigBuilder.() -> Unit = {},
  ) = coreTestConfig {
    passiveMode = false
    enablePenetrationDetection = false
    mutate()
  }

  /** Route configs in this file carry no detection override: silence the escalation helper. */
  private fun routeConfig(mutate: RouteConfig.() -> Unit = {}): RouteConfig =
      RouteConfig().apply {
        enableSuspiciousDetection = false
        mutate()
      }

  private fun requestFor(
      routeConfig: RouteConfig?,
      clientIp: String = "1.2.3.4",
  ): TestRequest {
    val request = TestRequest(clientHost = clientIp)
    request.state.setAttr("client_ip", clientIp)
    request.state.setAttr("route_config", routeConfig)
    return request
  }

  /** python `event_call = ...send_middleware_event.await_args`: the LAST emitted event. */
  private fun lastEvent(middleware: TestMiddleware): Map<String, Any?> {
    assertTrue(middleware.bus.events.isNotEmpty(), "expected an emitted event")
    return middleware.bus.events.last()
  }

  // ------------------------------- test_ip_security_global_route_merge.py:65-78

  @Test
  fun decoratedRouteStillEnforcesGlobalBlacklist() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { blacklist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { rateLimit = 5 }

      val result = check.check(requestFor(rc))

      assertNotNull(result)
      assertEquals("ip_blocked", lastEvent(middleware)["event_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:81-92

  @Test
  fun routeIpWhitelistOverridesGlobalBlacklist() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { blacklist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("1.2.3.4") }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:95-113

  @Test
  fun routeCountryRulesKeepGlobalIpBlacklistActive() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { blacklist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config, geoIpHandler = StubGeoHandler("US"))
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { blockedCountries = listOf("RU") }

      val result = check.check(requestFor(rc))

      assertNotNull(result)
      val event = lastEvent(middleware)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("global", event["filter_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:116-127

  @Test
  fun routeWithoutIpFieldsLeavesGlobalWhitelistSemantics() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { whitelist = listOf("9.9.9.9") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { rateLimit = 5 }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:130-141

  @Test
  fun globalWhitelistMatchSetsIsWhitelistedWithRouteConfig() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { whitelist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { rateLimit = 5 }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(true, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:144-158

  @Test
  fun routeWhitelistWithUnparseableIpBlocksAtRouteStep() {
    coreRunTest {
      resetCoreBanState()
      val middleware = TestMiddleware(mergeConfig())
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("1.2.3.4") }
      val request = requestFor(rc, clientIp = "not-an-ip")

      val result = check.check(request)

      assertNotNull(result)
      assertEquals("decorator_violation", lastEvent(middleware)["event_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:161-173

  @Test
  fun globallyWhitelistedConfigWithUnparseableClientIpNotWhitelisted() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { whitelist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("9.9.9.9") }
      val request = requestFor(rc, clientIp = "not-an-ip")

      val result = check.check(request)

      assertNotNull(result)
      // python: getattr(request.state, "is_whitelisted", False) is False - unset or false.
      assertTrue(request.state.getAttr("is_whitelisted") != true)
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:176-189
  // python calls `_check_global_ip_restrictions(request, "not-an-ip", route_config)` directly;
  // the private step is unreachable through check() with a route whitelist (the route step
  // blocks the unparseable identity first), so the port pins the public-surface observable of
  // the same scenario: the request is blocked and is_whitelisted never becomes true.

  @Test
  fun globalCheckUnparseableIpWithRouteWhitelistNotWhitelisted() {
    coreRunTest {
      resetCoreBanState()
      val middleware = TestMiddleware(mergeConfig())
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("1.2.3.4") }
      val request = requestFor(rc, clientIp = "not-an-ip")

      val result = check.check(request)

      assertTrue(request.state.getAttr("is_whitelisted") != true)
      assertNotNull(result)
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:192-206

  @Test
  fun routeBlacklistOnlyStillEnforcesGlobalWhitelist() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { whitelist = listOf("1.1.1.1") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipBlacklist = listOf("6.6.6.6") }

      val result = check.check(requestFor(rc))

      assertNotNull(result)
      val event = lastEvent(middleware)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("global", event["filter_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:209-220

  @Test
  fun routeBlacklistOnlyAllowsGloballyWhitelistedClient() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { whitelist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipBlacklist = listOf("6.6.6.6") }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(true, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:223-244

  @Test
  fun routeBlockedCountriesOnlyStillEnforcesGlobalBlockedCountries() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig {
        geoIpHandler = StubGeoHandler("CN")
        blockedCountries = setOf("CN")
      }
      val middleware = TestMiddleware(config, geoIpHandler = StubGeoHandler("CN"))
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { blockedCountries = listOf("RU") }

      val result = check.check(requestFor(rc))

      assertNotNull(result)
      val event = lastEvent(middleware)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("global", event["filter_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:247-258

  @Test
  fun routeWhitelistMatchOverridesGlobalWhitelistDefaultDeny() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { whitelist = listOf("1.1.1.1") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("1.2.3.4") }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:261-274

  @Test
  fun routeWhitelistSetButClientExcludedBlocksAtRouteStep() {
    coreRunTest {
      resetCoreBanState()
      val middleware = TestMiddleware(mergeConfig())
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("9.9.9.9") }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals("decorator_violation", lastEvent(middleware)["event_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:277-295

  @Test
  fun routeIpWhitelistMatchStillDeniedByRouteCountryMismatch() {
    coreRunTest {
      resetCoreBanState()
      val middleware = TestMiddleware(mergeConfig(), geoIpHandler = StubGeoHandler("CN"))
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig {
        ipWhitelist = listOf("1.2.3.4")
        whitelistCountries = listOf("US")
      }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNotNull(result)
      assertEquals("decorator_violation", lastEvent(middleware)["event_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:298-318

  @Test
  fun routeIpWhitelistMatchDoesNotBypassGlobalBlockedCountries() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig {
        geoIpHandler = StubGeoHandler("CN")
        blockedCountries = setOf("CN")
      }
      val middleware = TestMiddleware(config, geoIpHandler = StubGeoHandler("CN"))
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { ipWhitelist = listOf("1.2.3.4") }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNotNull(result)
      val event = lastEvent(middleware)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("global", event["filter_type"])
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:321-337

  @Test
  fun routeWhitelistCountriesMatchSkipsGlobalBlockedCountries() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig {
        geoIpHandler = StubGeoHandler("US")
        blockedCountries = setOf("US")
      }
      val middleware = TestMiddleware(config, geoIpHandler = StubGeoHandler("US"))
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig { whitelistCountries = listOf("US") }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:340-351

  @Test
  fun routeIpWhitelistOverridesRouteIpBlacklistSameIp() {
    coreRunTest {
      resetCoreBanState()
      val middleware = TestMiddleware(mergeConfig())
      val check = IpSecurityCheck(middleware)
      val rc = routeConfig {
        ipWhitelist = listOf("1.2.3.4")
        ipBlacklist = listOf("1.2.3.4")
      }
      val request = requestFor(rc)

      val result = check.check(request)

      assertNull(result)
      assertEquals(false, request.state.getAttr("is_whitelisted"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:354-380
  // python patches cloud_handler.is_cloud_ip / get_cloud_provider_details; the JVM drives the
  // real CloudManager through the registered AccessControl.cloudIpChecker seam (the established
  // real path, also used by the W4a pipeline revision tests).

  @Test
  fun globalCloudProviderBlockNamesProviderNotAllowlist() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { blockCloudProviders = setOf("AWS") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)

      val cloud = CloudManager.getInstance()
      val savedRanges = cloud.ipRanges.toMap()
      cloud.ipRanges["AWS"] = (savedRanges["AWS"] ?: emptySet()) + IpNetwork.parse("1.2.3.0/24")
      try {
        val result = check.check(requestFor(null))

        assertNotNull(result)
        val event = lastEvent(middleware)
        assertEquals("ip_blocked", event["event_type"])
        assertEquals("global", event["filter_type"])
        val reason = event["reason"] as String
        assertTrue(reason.contains("AWS"), "reason must name the provider: $reason")
        assertTrue(!reason.contains("allowlist/blocklist"))
        assertEquals("AWS", event["cloud_provider"])
        assertEquals("1.2.3.0/24", event["network"])
      } finally {
        cloud.ipRanges.clear()
        cloud.ipRanges.putAll(savedRanges)
      }
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:383-404

  @Test
  fun globalCountryBlockNamesTheCountry() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig {
        geoIpHandler = StubGeoHandler("RU")
        blockedCountries = setOf("RU")
      }
      val middleware = TestMiddleware(config, geoIpHandler = StubGeoHandler("RU"))
      val check = IpSecurityCheck(middleware)

      val result = check.check(requestFor(null))

      assertNotNull(result)
      val event = lastEvent(middleware)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("global", event["filter_type"])
      val reason = event["reason"] as String
      assertTrue(reason.contains("RU"), "reason must name the country: $reason")
      assertTrue(!reason.contains("allowlist/blocklist"))
      assertTrue(!event.containsKey("cloud_provider"))
      assertTrue(!event.containsKey("network"))
    }
  }

  // ------------------------------- test_ip_security_global_route_merge.py:407-421

  @Test
  fun globalBlacklistBlockKeepsExistingReason() {
    coreRunTest {
      resetCoreBanState()
      val config = mergeConfig { blacklist = listOf("1.2.3.4") }
      val middleware = TestMiddleware(config)
      val check = IpSecurityCheck(middleware)

      val result = check.check(requestFor(null))

      assertNotNull(result)
      val event = lastEvent(middleware)
      assertEquals("ip_blocked", event["event_type"])
      assertEquals("global", event["filter_type"])
      assertEquals("IP 1.2.3.4 not in global allowlist/blocklist", event["reason"])
      assertTrue(!event.containsKey("cloud_provider"))
    }
  }
}
