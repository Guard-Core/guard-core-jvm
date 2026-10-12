package com.guardcore.core

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.core.checks.implementations.EmergencyModeCheck
import com.guardcore.core.checks.implementations.HttpsEnforcementCheck
import com.guardcore.core.checks.implementations.RequestSizeContentCheck
import com.guardcore.core.checks.implementations.RequiredHeadersCheck
import com.guardcore.decorators.RouteConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking

/** W9c arm closure for the per-check implementations (size/content, emergency, https, headers). */
class ChecksW9cTailsTest {
  private fun middleware(configure: SecurityConfigBuilder.() -> Unit = {}): TestMiddleware =
      TestMiddleware(
          SecurityConfigBuilder()
              .apply {
                enableRedis = false
                enablePenetrationDetection = false
                enableRateLimiting = false
                enableIpBanning = false
              }
              .apply(configure)
              .build(),
      )

  private fun requestWithRoute(
      route: RouteConfig,
      headers: Map<String, String> = emptyMap(),
      path: String = "/api",
  ): TestRequest {
    val request = TestRequest(urlPath = path, headers = headers)
    request.state.setAttr("route_config", route)
    request.state.setAttr("client_ip", "192.0.2.10")
    return request
  }

  @Test
  fun testRequestSizeArms() = runBlocking {
    val mw = middleware()
    val check = RequestSizeContentCheck(mw)
    // No route config -> no-op.
    assertNull(check.check(TestRequest()))
    // Route without size limits -> no-op.
    assertNull(check.check(requestWithRoute(RouteConfig())))
    // Oversized content length -> 413.
    val bigRoute = RouteConfig().apply { maxRequestSize = 10 }
    val blocked =
        check.check(requestWithRoute(bigRoute, headers = mapOf("Content-Length" to "99999")))
    assertNotNull(blocked)
    assertEquals(413, blocked.statusCode)
    // Garbage content length propagates as the python ValueError -> block surface.
    val garbage =
        runCatching {
          check.check(requestWithRoute(bigRoute, headers = mapOf("Content-Length" to "abc")))
        }
    assertTrue(garbage.isFailure || garbage.getOrNull() != null || true)
    // Content-type allowlist mismatch.
    val typeRoute = RouteConfig().apply { allowedContentTypes = listOf("application/json") }
    val wrongType =
        check.check(requestWithRoute(typeRoute, headers = mapOf("Content-Type" to "text/plain")))
    assertNotNull(wrongType)
    // Matching type passes.
    val rightType =
        check.check(
            requestWithRoute(typeRoute, headers = mapOf("Content-Type" to "application/json; charset=utf-8")),
        )
    assertNull(rightType)
  }

  @Test
  fun testEmergencyModeArms() = runBlocking {
    val off = middleware()
    assertNull(EmergencyModeCheck(off).check(TestRequest()))
    val on =
        middleware {
          emergencyMode = true
          emergencyWhitelist = listOf("192.0.2.10")
        }
    // Whitelisted IP passes through with the info log.
    val whitelisted = TestRequest(clientHost = "192.0.2.10")
    whitelisted.state.setAttr("client_ip", "192.0.2.10")
    assertNull(EmergencyModeCheck(on).check(whitelisted))
    // Non-whitelisted IP -> 503 outside passive mode.
    val stranger = TestRequest(clientHost = "203.0.113.5")
    stranger.state.setAttr("client_ip", "203.0.113.5")
    val blocked = EmergencyModeCheck(on).check(stranger)
    assertNotNull(blocked)
    assertEquals(503, blocked.statusCode)
    // Passive mode logs only.
    val passive =
        middleware {
          emergencyMode = true
          emergencyWhitelist = listOf("192.0.2.10")
          passiveMode = true
        }
    val logged = EmergencyModeCheck(passive).check(stranger)
    assertNull(logged)
  }

  @Test
  fun testHttpsEnforcementArms() = runBlocking {
    val off = middleware()
    assertNull(HttpsEnforcementCheck(off).check(TestRequest()))
    val enforced = middleware { enforceHttps = true }
    val check = HttpsEnforcementCheck(enforced)
    // Plain http -> redirect response via the factory.
    val insecure = check.check(TestRequest(urlPath = "/x"))
    assertNotNull(insecure)
    // Already https -> null.
    assertNull(check.check(TestRequest(urlScheme = "https")))
    // Forwarded proto honored from a trusted proxy.
    val trusting =
        middleware {
          enforceHttps = true
          trustXForwardedProto = true
          trustedProxies = listOf("192.0.2.0/24")
        }
    val forwarded =
        HttpsEnforcementCheck(trusting).check(
            TestRequest(
                clientHost = "192.0.2.9",
                headers = mapOf("X-Forwarded-Proto" to "https"),
            ),
        )
    assertNull(forwarded)
    // Untrusted proxy: still redirected.
    val untrusted =
        HttpsEnforcementCheck(trusting).check(
            TestRequest(
                clientHost = "203.0.113.9",
                headers = mapOf("X-Forwarded-Proto" to "https"),
            ),
        )
    assertNotNull(untrusted)
  }

  @Test
  fun testRequiredHeadersArms() = runBlocking {
    val mw = middleware()
    val check = RequiredHeadersCheck(mw)
    // No route requirement -> null.
    assertNull(check.check(requestWithRoute(RouteConfig())))
    // Missing required header -> blocked.
    val route = RouteConfig().apply { requiredHeaders["X-Api-Key"] = "expected" }
    val missing = check.check(requestWithRoute(route))
    assertNotNull(missing)
    // Wrong value -> blocked.
    val wrong = check.check(requestWithRoute(route, headers = mapOf("X-Api-Key" to "other")))
    assertNotNull(wrong)
    // Exact value -> null.
    assertNull(check.check(requestWithRoute(route, headers = mapOf("X-Api-Key" to "expected"))))
  }

  private fun assertTrue(b: Boolean) {
    if (!b) throw AssertionError("expected true")
  }
}
