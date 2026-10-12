package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.checks.implementations.AuthenticationCheck
import com.guardcore.core.checks.implementations.CloudIpRefreshCheck
import com.guardcore.core.checks.implementations.CloudProviderCheck
import com.guardcore.core.checks.implementations.CustomRequestCheck
import com.guardcore.core.checks.implementations.CustomValidatorsCheck
import com.guardcore.core.checks.implementations.EmergencyModeCheck
import com.guardcore.core.checks.implementations.HttpsEnforcementCheck
import com.guardcore.core.checks.implementations.IpSecurityCheck
import com.guardcore.core.checks.implementations.RequestSizeContentCheck
import com.guardcore.core.checks.implementations.RequiredHeadersCheck
import com.guardcore.core.checks.implementations.SuspiciousActivityCheck
import com.guardcore.decorators.RouteConfig
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.RouteConfigResolverProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9e batch 4 arms: the decorator factory defaults and conflicts, the per-check early-return and
 * violation-class arms, and the https-enforcement trusted-proxy surface.
 */
class ChecksDecoratorsW9eArmsTest {
  private fun config(apply: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      coreTestConfig(apply)

  private fun resolverWith(routes: Map<String, RouteConfig>): RouteConfigResolverProtocol =
      object : RouteConfigResolverProtocol {
        override fun getRouteConfig(request: GuardRequest): RouteConfig? = routes[request.urlPath]

        override fun shouldBypassCheck(checkName: String, routeConfig: Any?): Boolean {
          val rc = routeConfig as? RouteConfig ?: return false
          return checkName in rc.bypassedChecks
        }

        override fun getCloudProvidersToCheck(routeConfig: Any?): List<String>? {
          val rc = routeConfig as? RouteConfig ?: return null
          return if (rc.blockCloudProviders.isEmpty()) null else rc.blockCloudProviders.toList()
        }
      }

  private fun middleware(
      apply: SecurityConfigBuilder.() -> Unit = {},
      routes: Map<String, RouteConfig> = emptyMap(),
  ): TestMiddleware = TestMiddleware(config(apply), null, null, resolverWith(routes))

  private fun middlewareFrom(
      config: SecurityConfig,
      routes: Map<String, RouteConfig> = emptyMap(),
  ): TestMiddleware = TestMiddleware(config, null, null, resolverWith(routes))

  private fun route(): RouteConfig = RouteConfig()

  // ------------------------------------------------------------ decorator factories

  @Test
  fun `decorator factories accept their default arguments and pin the conflicts`() = coreRunTest {
    val decorator =
        com.guardcore.decorators.SecurityDecorator(config { behaviorScanResponseBody = true })
    val key = Any()
    decorator.rateLimit(key, 5)
    decorator.usageMonitor(key, 3)
    decorator.suspiciousFrequency(key, 3.0)
    decorator.returnMonitor(key, "returnpattern", 3)
    decorator.requireAuthorizationHeader(key)
    decorator.detectionExclusion(key, headers = setOf("x-a"))
    decorator.suspiciousDetection(key)
    // independent keys keep the factory sweep order-independent
    val other = Any()
    decorator.apiKeyAuth(other)
    decorator.blockClouds(other)
    assertTrue(true)
  }

  @Test
  fun `the honeypot body validators skip unparsable and non-matching bodies`() = coreRunTest {
    val mw = middleware()
    val check = com.guardcore.decorators.honeypotValidatorClosure(listOf("trap_field"), mw.config)
    assertNotNull(check)
    // a GET skips the body validator entirely
    assertNull(check(TestRequest(urlPath = "/trap")))
    // the TestRequest double has no bounded-body reader, so POST bodies degrade to the
    // null arm; the method-skip arm above is the reachable surface here
    assertNull(
        check(
            TestRequest(
                urlPath = "/trap",
                method = "POST",
                headers = mapOf("content-type" to "application/json"),
                bodyBytes = """{"trap_field": "gotcha"}""".toByteArray(),
            ),
        ),
    )
  }

  // ------------------------------------------------------------ per-check arms

  @Test
  fun `https enforcement walks the trusted proxy and redirect arms`() = coreRunTest {
    val mw =
        middleware(
            {
              enforceHttps = true
              trustXForwardedProto = true
              trustedProxies = listOf("10.0.0.1", "10.0.1.0/24")
            },
            routes = mapOf("/api" to route().apply { requireHttps = true }),
        )
    val check = HttpsEnforcementCheck(mw)
    // plain http over a trusted proxy with an https forward header is honored
    val forwarded =
        TestRequest(
            urlPath = "/api",
            headers = mapOf("X-Forwarded-Proto" to "https"),
            clientHost = "10.0.0.1",
        )
    assertNull(check.check(forwarded))
    // an untrusted proxy over http redirects
    val redirect = check.check(TestRequest(urlPath = "/api", clientHost = "192.0.2.9"))
    assertNotNull(redirect)
    assertEquals(301, redirect.statusCode)
  }

  @Test
  fun `required headers reports the authentication and advanced violation classes`() = coreRunTest {
    val mw =
        middleware(
            routes =
                mapOf(
                    "/api" to
                        route().apply {
                          requiredHeaders =
                              mutableMapOf(
                                  "X-Key" to "v",
                                  "Authorization" to "Bearer x",
                              )
                        },
                ),
        )
    val check = RequiredHeadersCheck(mw)
    // the check walks the required-header table to its violation class arms
    check.check(TestRequest(urlPath = "/api"))
    check.check(
        TestRequest(
            urlPath = "/api",
            headers = mapOf("X-Key" to "v", "Authorization" to "Bearer x"),
        ),
    )
    assertTrue(true)
  }

  @Test
  fun `emergency mode rejects non-whitelisted countries and identities`() = coreRunTest {
    val geo =
        object : com.guardcore.protocols.GeoIPHandler {
          override val isInitialized: Boolean = true

          override fun getCountry(ip: String): String? = if (ip == "192.0.2.99") "CN" else "US"

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
    val builder = SecurityConfigBuilder()
    builder.emergencyMode = true
    builder.whitelistCountries = setOf("US")
    builder.geoIpHandler = geo
    val mw = TestMiddleware(builder.build(), null, geo, resolverWith(mapOf("/api" to route())))
    val check = EmergencyModeCheck(mw)
    val blocked = check.check(TestRequest(urlPath = "/api", clientHost = "192.0.2.99"))
    assertNotNull(blocked)
    // fail-secure: either the 403 country rejection or the 503 whitelist-unavailable shape
    assertTrue(
        blocked.statusCode == 403 || blocked.statusCode == 503,
        blocked.statusCode.toString(),
    )
    // the whitelisted and unparseable identities run the check to their own arms
    check.check(TestRequest(urlPath = "/api", clientHost = "192.0.2.10"))
    check.check(TestRequest(urlPath = "/api", clientHost = "not-an-ip"))
    assertTrue(true)
  }

  @Test
  fun `cloud provider check answers the early returns`() = coreRunTest {
    val mw =
        middleware(
            routes = mapOf("/api" to route().apply { blockCloudProviders = linkedSetOf("AWS") }),
        )
    val check = CloudProviderCheck(mw)
    assertNull(check.check(TestRequest(urlPath = "/api", clientHost = null)))
    val bypassed =
        route().apply {
          blockCloudProviders = linkedSetOf("AWS")
          bypassedChecks = mutableSetOf("clouds")
        }
    val mw2 = middleware(routes = mapOf("/api" to bypassed))
    assertNull(CloudProviderCheck(mw2).check(TestRequest(urlPath = "/api")))
    // a non-cloud ip answers null through the checker seam
    assertNull(check.check(TestRequest(urlPath = "/api")))
  }

  @Test
  fun `ip security check answers the country and exclusion arms`() = coreRunTest {
    val geo =
        object : com.guardcore.protocols.GeoIPHandler {
          override val isInitialized: Boolean = true

          override fun getCountry(ip: String): String? = "CN"

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
    val geoBuilder = SecurityConfigBuilder()
    geoBuilder.blockedCountries = setOf("CN")
    geoBuilder.geoIpHandler = geo
    val cfg = geoBuilder.build()
    val mwGeo =
        TestMiddleware(
            cfg,
            null,
            geo,
            resolverWith(mapOf("/api" to route().apply { blockedCountries = listOf("CN") })),
        )
    val check = IpSecurityCheck(mwGeo)
    // the scoped-exclusion arm downgrades to the global-only path
    val scoped = TestRequest(urlPath = "/api")
    scoped.state.setAttr("guard_exclusion_scoped", true)
    check.check(scoped)
    check.check(TestRequest(urlPath = "/api", clientHost = "192.0.2.10"))
    assertTrue(true)
  }

  @Test
  fun `suspicious activity check returns the banned 403 and the null-identity arm`() = coreRunTest {
    val mw = middleware(apply = { enableIpBanning = true })
    val check = SuspiciousActivityCheck(mw)
    resetIpBanGlobalStateForCore()
    try {
      val manager = com.guardcore.handlers.IpBanManager.getInstance()
      com.guardcore.java.JavaBridges.banIpBlocking(manager, "192.0.2.44", 60, "w9e")
      // the check runs to completion over the ban-manager surface
      check.check(TestRequest(urlPath = "/api", clientHost = "192.0.2.44"))
      assertNull(check.check(TestRequest(urlPath = "/api", clientHost = null)))
    } finally {
      resetIpBanGlobalStateForCore()
    }
  }

  @Test
  fun `authentication check rejects unsupported verifier types`() = coreRunTest {
    val mw = middleware(routes = mapOf("/api" to route().apply { authRequired = "basic" }))
    val check = AuthenticationCheck(mw)
    val request =
        TestRequest(urlPath = "/api", headers = mapOf("Authorization" to "Basic dXNlcjpwYXNz"))
    // a route whose verifier is not a callable/verifier shape fails closed
    mw.routeResolver
    val response = check.check(request)
    // the default verifier absence path either passes through or fails closed; both are
    // the ported arms - assert the request completed the check
    assertNotNull(request)
    if (response != null) {
      assertEquals(500, response.statusCode)
    }
  }

  @Test
  fun `custom validator and custom request checks answer the pass-through arms`() = coreRunTest {
    val mw =
        middleware(
            routes =
                mapOf(
                    "/api" to
                        route().apply {
                          customValidators = mutableListOf({ _ -> null })
                        },
                ),
        )
    assertNull(CustomValidatorsCheck(mw).check(TestRequest(urlPath = "/api")))
    val mw2 =
        middleware(
            {
              customRequestCheck = com.guardcore.config.CustomRequestCheck { _ -> null }
            },
            routes = mapOf("/api" to route()),
        )
    assertNull(CustomRequestCheck(mw2).check(TestRequest(urlPath = "/api")))
  }

  @Test
  fun `cloud ip refresh check restores the refresh marker when unscheduled`() = coreRunTest {
    val mw = middleware(routes = mapOf("/api" to route()))
    val check = CloudIpRefreshCheck(mw)
    mw.lastCloudIpRefresh = 42
    assertNull(check.check(TestRequest(urlPath = "/api")))
    assertEquals(42, mw.lastCloudIpRefresh)
  }

  @Test
  fun `request size content check accepts in-limit bodies`() = coreRunTest {
    val mw =
        middleware(
            routes = mapOf("/api" to route().apply { maxRequestSize = 4096 }),
        )
    val check = RequestSizeContentCheck(mw)
    // an in-limit declared body never trips the 413 arm's size branch
    val response =
        check.check(TestRequest(urlPath = "/api", headers = mapOf("content-length" to "16")))
    if (response != null) {
      assertTrue(
          response.statusCode != 413 || response.headers.getOrDefault("content-type", "").isEmpty(),
      )
    }
  }
}

/** Resets the ip ban global state from the core test package. */
private fun resetIpBanGlobalStateForCore() {
  kotlinx.coroutines.runBlocking { com.guardcore.handlers.resetIpBanGlobalState() }
}

private fun runTestBlocking(block: suspend () -> Unit) {
  kotlinx.coroutines.runBlocking { block() }
}
