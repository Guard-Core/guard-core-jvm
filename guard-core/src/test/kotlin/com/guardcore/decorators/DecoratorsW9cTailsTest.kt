package com.guardcore.decorators

import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * W9c arm closure for the decorators package: the RouteConfig tracked containers (revision bumps on
 * every mutation), the StampedRoute tails, and the SecurityDecorator factory surfaces.
 */
class RouteConfigTrackedTest {
  @Test
  fun testRevisionBumpsOnContainerMutation() {
    val revision = RouteConfigRevision()
    val list = TrackedList<String>(listOf("a"), revision)
    list.add("b")
    assertEquals(1, revision.value)
    list.remove("b")
    assertEquals(2, revision.value)
    val map = TrackedMap<String, String>(linkedMapOf("k" to "v"), revision)
    map["k2"] = "v2"
    assertEquals(3, revision.value)
    map.remove("k2")
    assertEquals(4, revision.value)
    val set = TrackedSet<String>(setOf("x"), revision)
    set.add("y")
    assertEquals(5, revision.value)
    set.remove("y")
    assertEquals(6, revision.value)
    val clearedList = TrackedList<String>(listOf("z"), revision)
    clearedList.add("w")
    clearedList.clear()
    assertTrue(revision.value > 6)
  }

  @Test
  fun testRouteConfigFieldSurfaces() {
    val rc = RouteConfig()
    rc.rateLimit = 5
    rc.rateLimitWindow = 60
    rc.ipWhitelist = listOf("1.2.3.4")
    rc.ipBlacklist = listOf("5.6.7.8")
    rc.blockedCountries = listOf("GB")
    rc.whitelistCountries = listOf("US")
    rc.bypassedChecks.add("rate_limit")
    rc.requireHttps = true
    rc.authRequired = "basic"
    rc.blockedUserAgents.add("curl/*")
    rc.requiredHeaders["X-Key"] = "v"
    rc.blockCloudProviders.add("aws")
    rc.maxRequestSize = 1000
    rc.allowedContentTypes = listOf("application/json")
    rc.timeRestrictions = mapOf("start" to "09:00", "end" to "17:00")
    rc.enableSuspiciousDetection = false
    rc.requireReferrer = listOf("example.com")
    rc.apiKeyRequired = true
    rc.apiKeyHeader = "X-Api-Key"
    rc.authorizationHeaderRequired = "Bearer"
    rc.geoRateLimits = mapOf("US" to Pair(10, 60))
    rc.excludedDetectionHeaders = setOf("x-ok")
    rc.excludedDetectionParams = setOf("ok")
    assertEquals(5, rc.rateLimit)
    assertEquals("basic", rc.authRequired)
    assertEquals(listOf("curl/*"), rc.blockedUserAgents.toList())
    assertEquals("v", rc.requiredHeaders["X-Key"])
    assertEquals(setOf("aws"), rc.blockCloudProviders.toSet())
    assertEquals(1000, rc.maxRequestSize)
    assertEquals(mapOf("US" to Pair(10, 60)), rc.geoRateLimits)
    assertFalse(rc.enableSuspiciousDetection)
  }
}

class SecurityDecoratorW9cTest {
  private fun decorator(): SecurityDecorator =
      SecurityDecorator(
          SecurityConfigBuilder().apply { behaviorScanResponseBody = true }.build(),
      )

  @Test
  fun testEveryFactorySurface() {
    // Route ids derive from the caller chain (the W4b collision study), so each factory gets a
    // fresh decorator and the assertion reads the live map immediately after the call.
    fun fresh(): SecurityDecorator =
        SecurityDecorator(SecurityConfigBuilder().apply { behaviorScanResponseBody = true }.build())

    var d = fresh()
    d.blockCountries("w9c", listOf("gb"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.requireIp("w9c", whitelist = listOf("192.0.2.1"), blacklist = listOf("203.0.113.9"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.allowCountries("w9c", listOf("us"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.blockClouds("w9c", listOf("AWS"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.bypass("w9c", listOf("rate_limit"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.rateLimit("w9c", 10, 60)
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.geoRateLimit("w9c", mapOf("US" to Pair(10, 60)))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.usageMonitor("w9c", maxCalls = 3, window = 60)
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.returnMonitor("w9c", pattern = "secret.*", maxOccurrences = 2)
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.behaviorAnalysis(
        "w9c",
        listOf(com.guardcore.handlers.BehaviorRule(ruleType = "usage", threshold = 3)),
    )
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.suspiciousFrequency("w9c", maxFrequency = 0.5, window = 60)
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.requireHttps("w9c")
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.requireAuth("w9c")
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.apiKeyAuth("w9c", verifier = RouteAuthVerifier { _, credential -> credential })
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.requireAuthorizationHeader("w9c", "bearer")
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.requireHeaders("w9c", mapOf("X-Key" to "v"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.blockUserAgents("w9c", listOf("curl/*"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.contentTypeFilter("w9c", listOf("application/json"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.maxRequestSize("w9c", 1024)
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.requireReferrer("w9c", listOf("example.com"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.customValidation("w9c") { null }
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.detectionExclusion("w9c", headers = setOf("x-ok"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.timeWindow("w9c", "09:00", "17:00")
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.suspiciousDetection("w9c", enabled = false)
    assertTrue(d.getRouteConfigs().values.isNotEmpty())

    d = fresh()
    d.honeypotDetection("w9c", listOf("trap-field"))
    assertTrue(d.getRouteConfigs().values.isNotEmpty())
  }
}
