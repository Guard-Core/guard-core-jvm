package com.guardcore.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * W9e builder-surface sweep: every builder property is written and read back once, closing the
 * property-getter and provided-flag arms the corpus and prior waves never touch.
 */
class BuilderW9eSurfaceTest {
  @Test
  fun `builder properties round trip through the setters and getters`() {
    val builder = SecurityConfigBuilder()
    builder.trustedProxyDepth = 3
    assertEquals(3, builder.trustedProxyDepth)
    builder.trustXForwardedProto = true
    assertTrue(builder.trustXForwardedProto == true)
    builder.passiveMode = true
    assertTrue(builder.passiveMode == true)
    val geo = null
    builder.geoIpHandler = geo
    assertEquals(geo, builder.geoIpHandler)
    builder.enableRedis = false
    assertTrue(builder.enableRedis == false)
    builder.redisUrl = "redis://localhost:6379/0"
    assertEquals("redis://localhost:6379/0", builder.redisUrl)
    builder.redisSocketConnectTimeout = 1.5
    assertEquals(1.5, builder.redisSocketConnectTimeout)
    builder.redisSocketTimeout = 2.5
    assertEquals(2.5, builder.redisSocketTimeout)
    builder.redisMaxConnections = 4
    assertEquals(4, builder.redisMaxConnections)
    builder.ipinfoToken = "w9e"
    assertEquals("w9e", builder.ipinfoToken)
    builder.ipinfoDbPath = java.nio.file.Path.of("/tmp/w9e.mmdb")
    assertEquals(java.nio.file.Path.of("/tmp/w9e.mmdb"), builder.ipinfoDbPath)
    builder.geoIpDbMaxAge = 7200
    assertEquals(7200, builder.geoIpDbMaxAge)
    builder.logfireServiceName = "w9e-svc"
    assertEquals("w9e-svc", builder.logfireServiceName)
    builder.otelServiceName = "w9e-otel"
    assertEquals("w9e-otel", builder.otelServiceName)
    builder.otelExporterEndpoint = "http://localhost:4318"
    assertEquals("http://localhost:4318", builder.otelExporterEndpoint)
    builder.behaviorScanResponseBody = true
    assertTrue(builder.behaviorScanResponseBody == true)
    builder.detectionSemanticThreshold = 0.7
    assertEquals(0.7, builder.detectionSemanticThreshold)
    builder.detectionThreatScoreThreshold = 0.9
    assertEquals(0.9, builder.detectionThreatScoreThreshold)
    builder.emergencyMode = false
    assertFalse(builder.emergencyMode == true)
    builder.routeResolutionStrict = true
    assertTrue(builder.routeResolutionStrict == true)
    builder.enableEnrichment = false
    assertFalse(builder.enableEnrichment == true)
    val config = builder.build()
    assertFalse(config.enableRedis)
  }
}
