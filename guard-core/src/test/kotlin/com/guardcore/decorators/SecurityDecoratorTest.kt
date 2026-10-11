package com.guardcore.decorators

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.handlers.BehaviorRule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The W4b decorators idiom-closure tests. The route-id collision campaign ports
 * tests/test_decorators/test_route_id_per_function.py (the guard-core #141/#142 class:
 * factory-built endpoints sharing one derived route id) onto the JVM route-key model, plus the
 * mixin parameter-surface and validation behavior.
 */
public class SecurityDecoratorTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder().apply(mutate).build()

  /** The test's StampedRoute analog of the python factory-built endpoint function. */
  private class Endpoint(override val routeKey: String) : StampedRoute {
    override var stampedRouteId: String? = null
  }

  // ------------------------------------------------ route-id collision campaign (G-12)

  @Test
  fun endpointsBuiltByOneFactoryKeepTheirOwnRateLimit() {
    val guard = SecurityDecorator(config())
    val strict = Endpoint("tests.factory.endpoint")
    val loose = Endpoint("tests.factory.endpoint")

    guard.rateLimit(strict, requests = 2, window = 60)
    guard.rateLimit(loose, requests = 100, window = 60)

    // Same derived base key (the python qualname analog), distinct stamped ids.
    assertEquals(strict.routeKey, loose.routeKey)
    assertNotEquals(strict.stampedRouteId, loose.stampedRouteId)

    val strictConfig = guard.getRouteConfig(strict.stampedRouteId!!)
    val looseConfig = guard.getRouteConfig(loose.stampedRouteId!!)
    assertEquals(2, strictConfig!!.rateLimit)
    assertEquals(100, looseConfig!!.rateLimit)
  }

  @Test
  fun settingsOfOneFactoryBuiltEndpointDoNotReachAnother() {
    val guard = SecurityDecorator(config())
    val admin = Endpoint("tests.factory.admin")
    val health = Endpoint("tests.factory.admin")

    guard.requireIp(admin, whitelist = listOf("10.0.0.1"))
    guard.bypass(health, checks = listOf("all"))

    val adminConfig = guard.getRouteConfig(admin.stampedRouteId!!)!!
    val healthConfig = guard.getRouteConfig(health.stampedRouteId!!)!!
    assertFalse(adminConfig.bypassedChecks.isNotEmpty())
    assertNull(healthConfig.ipWhitelist)
  }

  @Test
  fun theFirstEndpointKeepsThePlainRouteKeyRouteId() {
    val guard = SecurityDecorator(config())
    val first = Endpoint("tests.factory.endpoint")
    val second = Endpoint("tests.factory.endpoint")

    guard.rateLimit(first, requests = 2, window = 60)
    guard.rateLimit(second, requests = 100, window = 60)

    assertEquals(first.routeKey, first.stampedRouteId)
    assertNotEquals(first.routeKey, second.stampedRouteId)
    assertTrue(
        guard.getRouteConfig(first.routeKey) === guard.getRouteConfig(first.stampedRouteId!!),
    )
  }

  @Test
  fun stackedDecoratorsOnOneEndpointShareOneRouteConfig() {
    val guard = SecurityDecorator(config())
    val endpoint = Endpoint("tests.factory.endpoint")

    guard.requireIp(endpoint, whitelist = listOf("10.0.0.1"))
    guard.rateLimit(endpoint, requests = 5, window = 60)

    assertEquals(listOf(endpoint.stampedRouteId), guard.routeConfigMap.keys.toList())
    val routeConfig = guard.getRouteConfig(endpoint.stampedRouteId!!)!!
    assertEquals(listOf("10.0.0.1"), routeConfig.ipWhitelist)
    assertEquals(5, routeConfig.rateLimit)
  }

  @Test
  fun aStampedRouteIdIsNotReusedAcrossDecoratorInstances() {
    val guardA = SecurityDecorator(config())
    val guardB = SecurityDecorator(config())
    val first = Endpoint("tests.factory.endpoint")
    val second = Endpoint("tests.factory.endpoint")

    guardA.rateLimit(first, requests = 2, window = 60)
    guardB.bypass(second, checks = listOf("all"))

    // Cross-instance reuse of a stamped id must not select the other function's config:
    // decorating `first` with guardB assigns first its own config in guardB instead of joining
    // second's.
    guardB.requireIp(first, whitelist = listOf("10.0.0.1"))

    val firstConfig = guardB.getRouteConfig(first.stampedRouteId!!)!!
    val secondConfig = guardB.getRouteConfig(second.stampedRouteId!!)!!
    assertEquals(listOf("10.0.0.1"), firstConfig.ipWhitelist)
    assertEquals(setOf("all"), secondConfig.bypassedChecks)
    assertFalse(firstConfig.bypassedChecks.isNotEmpty())
  }

  // ------------------------------------------------ mixin parameter surface + validation

  @Test
  fun accessControlMixinsNormalizeAndFilter() {
    val guard = SecurityDecorator(config())
    val endpoint = Endpoint("ep")
    guard.blockCountries(endpoint, listOf("cn", "Ru"))
    assertEquals(listOf("CN", "RU"), guard.getRouteConfig("ep")!!.blockedCountries)

    guard.allowCountries(endpoint, listOf("us"))
    assertEquals(listOf("US"), guard.getRouteConfig("ep")!!.whitelistCountries)

    guard.blockClouds(endpoint, listOf("AWS", "nonsense"))
    assertEquals(setOf("AWS"), guard.getRouteConfig("ep")!!.blockCloudProviders)

    val all = Endpoint("ep-all")
    guard.blockClouds(all, null)
    assertEquals(
        com.guardcore.config.CloudProviders.VALID_CLOUD_PROVIDERS,
        guard.getRouteConfig("ep-all")!!.blockCloudProviders,
    )

    val bypassed = Endpoint("ep-bypass")
    guard.bypass(bypassed, listOf("rate_limit", "not_a_check"))
    assertEquals(
        setOf("rate_limit"),
        guard.getRouteConfig("ep-bypass")!!.bypassedChecks,
    )
  }

  @Test
  fun authenticationMixinsEnforceMutualExclusion() {
    val guard = SecurityDecorator(config())
    val endpoint = Endpoint("ep")

    guard.requireAuth(endpoint, type = "bearer")
    assertEquals("bearer", guard.getRouteConfig("ep")!!.authRequired)

    val error =
        assertFailsWith<IllegalArgumentException> {
          guard.requireAuthorizationHeader(endpoint, scheme = "basic")
        }
    assertTrue(error.message!!.contains("mutually exclusive"))

    val other = Endpoint("ep2")
    guard.requireAuthorizationHeader(other, scheme = "basic")
    val conflict =
        assertFailsWith<IllegalArgumentException> { guard.requireAuth(other, type = "bearer") }
    assertTrue(conflict.message!!.contains("mutually exclusive"))

    val keyed = Endpoint("ep3")
    guard.apiKeyAuth(keyed, headerName = "X-Key")
    val keyConfig = guard.getRouteConfig("ep3")!!
    assertTrue(keyConfig.apiKeyRequired)
    assertEquals("required", keyConfig.requiredHeaders["X-Key"])
    assertEquals("X-Key", keyConfig.apiKeyHeader)

    val https = Endpoint("ep4")
    guard.requireHttps(https)
    assertTrue(guard.getRouteConfig("ep4")!!.requireHttps)
  }

  @Test
  fun contentFilteringValidatesRedosBeforeMutation() {
    val guard = SecurityDecorator(config())
    val endpoint = Endpoint("ep")

    // An unsafe pattern raises before any route config lands.
    val error =
        assertFailsWith<IllegalArgumentException> {
          guard.blockUserAgents(endpoint, listOf("(a+)+$"))
        }
    assertTrue(error.message!!.contains("rejected by ReDoS validator"))
    assertNull(guard.getRouteConfig("ep"))

    guard.blockUserAgents(endpoint, listOf("badbot", "evilbot"))
    assertEquals(listOf("badbot", "evilbot"), guard.getRouteConfig("ep")!!.blockedUserAgents)

    guard.maxRequestSize(endpoint, 1024)
    assertEquals(1024, guard.getRouteConfig("ep")!!.maxRequestSize)

    guard.contentTypeFilter(endpoint, listOf("application/json"))
    assertEquals(listOf("application/json"), guard.getRouteConfig("ep")!!.allowedContentTypes)

    guard.requireReferrer(endpoint, listOf("example.com"))
    assertEquals(listOf("example.com"), guard.getRouteConfig("ep")!!.requireReferrer)
  }

  @Test
  fun behavioralMixinsAppendRulesWithValidation() {
    val guard = SecurityDecorator(config { behaviorScanResponseBody = true })
    val endpoint = Endpoint("ep")

    guard.usageMonitor(endpoint, maxCalls = 5, window = 60, action = "log")
    guard.suspiciousFrequency(endpoint, maxFrequency = 0.5, window = 100, action = "ban")
    val rules = guard.getRouteConfig("ep")!!.behaviorRules
    assertEquals(2, rules.size)
    assertEquals("usage", rules[0].ruleType)
    assertEquals(5, rules[0].threshold)
    assertEquals("frequency", rules[1].ruleType)
    assertEquals(50, rules[1].threshold)

    // return_monitor without response-body scanning is rejected like the python factory.
    val strictGuard = SecurityDecorator(config())
    val scanner = Endpoint("ep2")
    val error =
        assertFailsWith<RuntimeException> {
          strictGuard.returnMonitor(scanner, pattern = "secret", maxOccurrences = 3)
        }
    assertTrue(error.message!!.contains("behavior_scan_response_body"))

    guard.returnMonitor(endpoint, pattern = "secret", maxOccurrences = 3)
    assertEquals("return_pattern", guard.getRouteConfig("ep")!!.behaviorRules[2].ruleType)

    guard.behaviorAnalysis(
        endpoint,
        listOf(
            BehaviorRule(ruleType = "usage", threshold = 9, window = 30, action = "alert"),
        ),
    )
    assertEquals(4, guard.getRouteConfig("ep")!!.behaviorRules.size)
  }

  @Test
  fun advancedMixinsSetTimeWindowAndHoneypot() = runBlocking {
    val guard = SecurityDecorator(config())
    val endpoint = Endpoint("ep")

    guard.timeWindow(endpoint, startTime = "09:00", endTime = "17:00", timezone = "UTC")
    assertEquals(
        mapOf("start" to "09:00", "end" to "17:00", "timezone" to "UTC"),
        guard.getRouteConfig("ep")!!.timeRestrictions,
    )

    guard.suspiciousDetection(endpoint, enabled = false)
    assertFalse(guard.getRouteConfig("ep")!!.enableSuspiciousDetection)

    // Honeypot: a filled trap field in a form body rejects with the 403 simple response.
    val honeypot = Endpoint("honeypot")
    guard.honeypotDetection(honeypot, trapFields = listOf("website_url"))
    val validator = guard.getRouteConfig("honeypot")!!.customValidators.single()

    val formRequest =
        com.guardcore.core.TestRequest(
            method = "POST",
            headers =
                mapOf(
                    "content-type" to "application/x-www-form-urlencoded",
                    "content-length" to "26",
                ),
            bodyBytes = "username=bob&website_url=spam".encodeToByteArray(),
        )
    val rejected = validator(formRequest)
    assertTrue(rejected is SimpleDecoratorResponse)
    assertEquals(403, rejected.statusCode)

    val cleanRequest =
        com.guardcore.core.TestRequest(
            method = "POST",
            headers =
                mapOf(
                    "content-type" to "application/x-www-form-urlencoded",
                    "content-length" to "12",
                ),
            bodyBytes = "username=bob".encodeToByteArray(),
        )
    assertNull(validator(cleanRequest))

    val jsonTrap =
        com.guardcore.core.TestRequest(
            method = "POST",
            headers =
                mapOf(
                    "content-type" to "application/json",
                    "content-length" to "30",
                ),
            bodyBytes = """{"username": "bob", "website_url": "x"}""".encodeToByteArray(),
        )
    assertTrue(validator(jsonTrap) is SimpleDecoratorResponse)

    val jsonClean =
        com.guardcore.core.TestRequest(
            method = "POST",
            headers =
                mapOf(
                    "content-type" to "application/json",
                    "content-length" to "19",
                ),
            bodyBytes = """{"username": "bob"}""".encodeToByteArray(),
        )
    assertNull(validator(jsonClean))
  }

  @Test
  fun getRouteDecoratorConfigReadsTheStampedRequestState() {
    val guard = SecurityDecorator(config())
    val endpoint = Endpoint("ep")
    guard.rateLimit(endpoint, requests = 3, window = 60)

    val request = com.guardcore.core.TestRequest()
    assertNull(getRouteDecoratorConfig(request, guard))

    request.state.setAttr("guard_route_id", endpoint.stampedRouteId)
    assertEquals(3, getRouteDecoratorConfig(request, guard)!!.rateLimit)
  }
}
