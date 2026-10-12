package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9e batch 4 final config sweep: every builder property round-trips through its setter and getter,
 * and the validator rejection matrix covers the remaining list/enum/bound/path arms.
 */
class ConfigW9eFinalSweepTest {
  private fun expectConfigError(block: () -> Unit) {
    var thrown = false
    try {
      block()
    } catch (expected: ConfigValidationError) {
      thrown = true
    }
    assertTrue(thrown)
  }

  @Test
  fun `every builder property round trips`() {
    val b = SecurityConfigBuilder()
    b.whitelist = listOf("192.0.2.1")
    assertEquals(listOf("192.0.2.1"), b.whitelist)
    b.customLogFile = "/tmp/w9e.log"
    assertEquals("/tmp/w9e.log", b.customLogFile)
    b.logSuspiciousLevel = LogLevel.WARNING
    assertEquals(LogLevel.WARNING, b.logSuspiciousLevel)
    b.logRequestLevel = LogLevel.INFO
    assertEquals(LogLevel.INFO, b.logRequestLevel)
    b.logCountryCheckLevel = LogLevel.ERROR
    assertEquals(LogLevel.ERROR, b.logCountryCheckLevel)
    b.securityHeaders = mapOf("X-Frame-Options" to "DENY")
    assertEquals(mapOf("X-Frame-Options" to "DENY"), b.securityHeaders)
    b.blockCloudProviders = setOf("AWS")
    assertEquals(setOf("AWS"), b.blockCloudProviders)
    val store = Any()
    b.cloudIpStore = store
    assertEquals(store, b.cloudIpStore)
    b.agentApiKey = "k"
    assertEquals("k", b.agentApiKey)
    b.agentProjectId = "p"
    assertEquals("p", b.agentProjectId)
    b.agentProjectEncryptionKey = "enc"
    assertEquals("enc", b.agentProjectEncryptionKey)
    b.agentGuardVersion = "4.3.2"
    assertEquals("4.3.2", b.agentGuardVersion)
    b.agentHighWatermarkRatio = 0.8
    assertEquals(0.8, b.agentHighWatermarkRatio)
    b.agentMaxConcurrentFlushes = 4
    assertEquals(4, b.agentMaxConcurrentFlushes)
    b.agentBufferOverflowPolicy = BufferOverflowPolicy.DROP
    assertEquals(BufferOverflowPolicy.DROP, b.agentBufferOverflowPolicy)
    b.agentBackoffFactor = 1.5
    assertEquals(1.5, b.agentBackoffFactor)
    b.threatBanConfig = emptyMap()
    assertEquals(emptyMap(), b.threatBanConfig)
    b.behaviorMaxResponseBodyInspectBytes = 4096
    assertEquals(4096, b.behaviorMaxResponseBodyInspectBytes)
    b.bodyReadTimeout = 2.0
    assertEquals(2.0, b.bodyReadTimeout)
    b.syncBodyReadMaxConcurrent = 3
    assertEquals(3, b.syncBodyReadMaxConcurrent)
    b.logFormat = LogFormat.JSON
    assertEquals(LogFormat.JSON, b.logFormat)
    b.customErrorResponses = mapOf(403 to "nope")
    assertEquals(mapOf(403 to "nope"), b.customErrorResponses)
    b.rateLimit = 10
    assertEquals(10, b.rateLimit)
    b.rateLimitWindow = 30
    assertEquals(30, b.rateLimitWindow)
    b.enforceHttps = true
    assertTrue(b.enforceHttps == true)
    b.customResponseModifier = { response -> response }
    assertNotNull(b.customResponseModifier)
    b.authVerifier = AuthVerifier { _, _ -> true }
    assertNotNull(b.authVerifier)
    b.enableCors = true
    assertTrue(b.enableCors == true)
    b.corsAllowOrigins = listOf("https://w9e.example")
    assertEquals(listOf("https://w9e.example"), b.corsAllowOrigins)
    b.corsAllowMethods = listOf("GET")
    assertEquals(listOf("GET"), b.corsAllowMethods)
    b.corsAllowHeaders = listOf("X-A")
    assertEquals(listOf("X-A"), b.corsAllowHeaders)
    b.corsAllowCredentials = true
    assertTrue(b.corsAllowCredentials == true)
    b.corsExposeHeaders = listOf("X-B")
    assertEquals(listOf("X-B"), b.corsExposeHeaders)
    b.corsMaxAge = 600
    assertEquals(600, b.corsMaxAge)
    b.cloudIpRefreshInterval = 600
    assertEquals(600, b.cloudIpRefreshInterval)
    b.lazyInit = true
    assertTrue(b.lazyInit == true)
    b.excludePaths = listOf("/health")
    assertEquals(listOf("/health"), b.excludePaths)
    b.enableIpBanning = false
    assertTrue(b.enableIpBanning == false)
    b.enableRateLimiting = false
    assertTrue(b.enableRateLimiting == false)
    b.enablePenetrationDetection = false
    assertTrue(b.enablePenetrationDetection == false)
    b.failSecure = false
    assertTrue(b.failSecure == false)
    b.redisFailOpen = true
    assertTrue(b.redisFailOpen == true)
    b.routeResolutionStrict = false
    assertTrue(b.routeResolutionStrict == false)
    b.ipinfoToken = "tok"
    assertEquals("tok", b.ipinfoToken)
    b.enableAgent = false
    assertTrue(b.enableAgent == false)
    b.agentStrict = true
    assertTrue(b.agentStrict == true)
    b.onError = OnErrorHook { _, _, _ -> }
    assertNotNull(b.onError)
    b.onBlock = BlockHook { _, _ -> }
    assertNotNull(b.onBlock)
    b.agentEndpoint = "http://localhost:9"
    assertEquals("http://localhost:9", b.agentEndpoint)
    b.agentBufferSize = 128
    assertEquals(128, b.agentBufferSize)
    b.agentFlushInterval = 2
    assertEquals(2, b.agentFlushInterval)
    b.agentEnableEvents = false
    assertTrue(b.agentEnableEvents == false)
    b.agentEnableMetrics = false
    assertTrue(b.agentEnableMetrics == false)
    b.agentTimeout = 3
    assertEquals(3, b.agentTimeout)
    b.agentRetryAttempts = 2
    assertEquals(2, b.agentRetryAttempts)
    b.agentSensitiveHeaders = listOf("authorization")
    assertEquals(listOf("authorization"), b.agentSensitiveHeaders)
    b.agentMaxPayloadSize = 1024
    assertEquals(1024, b.agentMaxPayloadSize)
    b.agentCompressionEnabled = false
    assertTrue(b.agentCompressionEnabled == false)
    b.agentCompressionThreshold = 512
    assertEquals(512, b.agentCompressionThreshold)
    b.agentInstallId = "w9e-install"
    assertEquals("w9e-install", b.agentInstallId)
    b.agentPayloadSigningSecret = "s3cret"
    assertEquals("s3cret", b.agentPayloadSigningSecret)
    b.enableDynamicRules = false
    assertTrue(b.enableDynamicRules == false)
    b.dynamicRuleInterval = 60
    assertEquals(60, b.dynamicRuleInterval)
    b.dynamicRulesCachePathRaw = "/tmp/w9e-cache.json"
    assertEquals("/tmp/w9e-cache.json", b.dynamicRulesCachePathRaw)
    b.agentStatusInterval = 60
    assertEquals(60, b.agentStatusInterval)
    b.endpointRateLimits = mapOf("/api" to (5 to 60))
    assertEquals(mapOf("/api" to (5 to 60)), b.endpointRateLimits)
    b.detectionPatternValidationCachePath = "/tmp/w9e-cache"
    assertEquals("/tmp/w9e-cache", b.detectionPatternValidationCachePath)
    b.detectionMaxScanValues = 1000
    assertEquals(1000, b.detectionMaxScanValues)
    b.detectionMaxScanChars = 20000
    assertEquals(20000, b.detectionMaxScanChars)
    b.detectionMaxJsonDepth = 10
    assertEquals(10, b.detectionMaxJsonDepth)
    b.detectionBinaryMinRunLength = 64
    assertEquals(64, b.detectionBinaryMinRunLength)
    b.mutedEventTypes = setOf("access_denied")
    assertEquals(setOf("access_denied"), b.mutedEventTypes)
    b.mutedMetricTypes = setOf("error_rate")
    assertEquals(setOf("error_rate"), b.mutedMetricTypes)
    b.mutedCheckLogs = setOf("rate_limit")
    assertEquals(setOf("rate_limit"), b.mutedCheckLogs)
    b.logSensitiveHeadersRaw = setOf("authorization")
    assertEquals(setOf("authorization"), b.logSensitiveHeadersRaw)
    b.logSensitiveParamsRaw = setOf("token")
    assertEquals(setOf("token"), b.logSensitiveParamsRaw)
    b.logSensitiveBodyFieldsRaw = setOf("password")
    assertEquals(setOf("password"), b.logSensitiveBodyFieldsRaw)
    b.enableOtel = false
    assertTrue(b.enableOtel == false)
    b.otelResourceAttributes = mapOf("a" to "b")
    assertEquals(mapOf("a" to "b"), b.otelResourceAttributes)
    b.enableLogfire = false
    assertTrue(b.enableLogfire == false)
    b.enableEnrichment = false
    assertTrue(b.enableEnrichment == false)
    b.excludedDetectionHeaders = setOf("x-internal")
    assertEquals(setOf("x-internal"), b.excludedDetectionHeaders)
    b.excludedDetectionParams = setOf("q")
    assertEquals(setOf("q"), b.excludedDetectionParams)
    b.excludedDetectionBodyFields = setOf("secret")
    assertEquals(setOf("secret"), b.excludedDetectionBodyFields)
    b.detectionScanBody = false
    assertTrue(b.detectionScanBody == false)
    b.enabledDetectionCategories = setOf("xss")
    assertEquals(setOf("xss"), b.enabledDetectionCategories)
    b.redisPrefix = "w9e:prefix:"
    assertEquals("w9e:prefix:", b.redisPrefix)
    val config = b.build()
    // the sweep build carries a redis url, so the cross-field wiring enables redis
    assertTrue(config.enableRedis)
  }

  @Test
  fun `validator rejection matrix covers the list, dict, enum, bound and path arms`() {
    // the list arm
    expectConfigError {
      ConfigValidators.validateGlobalBehaviorRulesFieldValue(42, "global_behavior_rules")
    }
    // behavior-rule dict arms: a non-map item, a missing threshold, a bad rule_type and a
    // bad action enum
    expectConfigError {
      ConfigValidators.validateGlobalBehaviorRulesFieldValue(
          listOf("not-a-map"),
          "global_behavior_rules",
      )
    }
    expectConfigError {
      ConfigValidators.validateGlobalBehaviorRulesFieldValue(
          listOf(mapOf("rule_type" to "usage")),
          "global_behavior_rules",
      )
    }
    expectConfigError {
      ConfigValidators.validateGlobalBehaviorRulesFieldValue(
          listOf(mapOf("rule_type" to "bogus", "threshold" to 1)),
          "global_behavior_rules",
      )
    }
    expectConfigError {
      ConfigValidators.validateGlobalBehaviorRulesFieldValue(
          listOf(mapOf("rule_type" to "usage", "threshold" to 1, "action" to "bogus")),
          "global_behavior_rules",
      )
    }
    // the stringSetOf coercion arms (via the sensitive-name set validator)
    assertEquals(setOf("a"), ConfigValidators.validateSensitiveNameSetValue(listOf("a"), "w9e"))
    assertEquals(setOf("a"), ConfigValidators.validateSensitiveNameSetValue(setOf("a"), "w9e"))
    // non-string items are rejected
    var rejected = false
    try {
      ConfigValidators.validateSensitiveNameSetValue(listOf(1), "w9e")
    } catch (expected: ConfigValidationError) {
      rejected = true
    }
    assertTrue(rejected)
    assertEquals(emptySet(), ConfigValidators.validateSensitiveNameSetValue(null, "w9e"))
    expectConfigError { ConfigValidators.validateSensitiveNameSetValue(42, "w9e") }
    // the pattern-source redaction: the hex/octal decoders and the sensitive-name arm
    assertNotNull(ConfigValidators.redactPatternSource("\\x74\\157\\153\\145\\x6e"))
    assertNotNull(ConfigValidators.redactPatternSource("\\164\\157\\153\\145"))
    assertEquals("[REDACTED_PATTERN]", ConfigValidators.redactPatternSource("(?i:password)"))
    // the numeric bound arms
    ConfigValidators.checkGe(2, 2, "w9e")
    assertFailsWith<ConfigValidationError> { ConfigValidators.checkGe(1, 2, "w9e") }
    ConfigValidators.checkLe(2, 2, "w9e")
    assertFailsWith<ConfigValidationError> { ConfigValidators.checkLe(3, 2, "w9e") }
    ConfigValidators.checkGe(2.0, 2.0, "w9e")
    assertFailsWith<ConfigValidationError> { ConfigValidators.checkGe(1.0, 2.0, "w9e") }
    ConfigValidators.checkLe(2.0, 2.0, "w9e")
    assertFailsWith<ConfigValidationError> { ConfigValidators.checkLe(3.0, 2.0, "w9e") }
    assertFailsWith<ConfigValidationError> { ConfigValidators.checkGt(2.0, 2.0, "w9e") }
    ConfigValidators.checkGt(3.0, 2.0, "w9e")
    // the path arm: a non-string/path value and an unparsable path
    expectConfigError { ConfigValidators.validateDynamicRulesCachePathValue(42) }
    assertNull(ConfigValidators.validateDynamicRulesCachePathValue(null))
    assertEquals(
        Path.of("/tmp/w9e"),
        ConfigValidators.validateDynamicRulesCachePathValue("/tmp/w9e"),
    )
    assertEquals(
        Path.of("/tmp/w9e"),
        ConfigValidators.validateDynamicRulesCachePathValue(Path.of("/tmp/w9e")),
    )
  }
}
