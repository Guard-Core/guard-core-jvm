package com.guardcore.config

import com.guardcore.errors.ConfigValidationError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * W9d config tail coverage: the builder setter sweep for both booking arms, the fromMap coercion
 * rejection matrix, the hook/verifier appliers, and the SecurityConfig copyWith/valueByName tails.
 */
private fun goodBase(): MutableMap<String, Any?> =
    linkedMapOf(
        "enable_redis" to false,
        "ipinfo_token" to "tok",
    )

public class ConfigW9dTailsTest {
  @Test
  fun testSetterSweepBooksAndClears() {
    val builder = SecurityConfigBuilder()
    builder.customLogFile = "/tmp/g.log"
    builder.customLogFile = null
    builder.logSuspiciousLevel = LogLevel.WARNING
    builder.logSuspiciousLevel = null
    builder.logRequestLevel = LogLevel.INFO
    builder.logRequestLevel = null
    builder.logCountryCheckLevel = LogLevel.ERROR
    builder.logCountryCheckLevel = null
    builder.securityHeaders = mapOf("X-Foo" to "bar")
    builder.securityHeaders = null
    builder.blockCloudProviders = setOf("AWS")
    builder.blockCloudProviders = null
    builder.ipinfoDbPath = java.nio.file.Path.of("/tmp/mmdb")
    builder.ipinfoDbPath = null
    builder.agentApiKey = "k"
    builder.agentApiKey = null
    builder.agentProjectId = "p"
    builder.agentProjectId = null
    builder.agentProjectEncryptionKey = "e"
    builder.agentProjectEncryptionKey = null
    builder.agentGuardVersion = "v"
    builder.agentGuardVersion = null
    builder.agentHighWatermarkRatio = 0.9
    builder.agentHighWatermarkRatio = null
    builder.agentMaxConcurrentFlushes = 2
    builder.agentMaxConcurrentFlushes = null
    builder.agentBufferOverflowPolicy = BufferOverflowPolicy.DROP
    builder.agentBufferOverflowPolicy = null
    builder.agentBackoffFactor = 1.5
    builder.agentBackoffFactor = null
    builder.agentSensitiveHeaders = listOf("authorization")
    builder.agentSensitiveHeaders = null
    builder.agentMaxPayloadSize = 1024
    builder.agentMaxPayloadSize = null
    builder.agentCompressionEnabled = true
    builder.agentCompressionEnabled = null
    builder.agentCompressionThreshold = 512
    builder.agentCompressionThreshold = null
    builder.agentInstallId = "id"
    builder.agentInstallId = null
    builder.agentPayloadSigningSecret = "s"
    builder.agentPayloadSigningSecret = null
    builder.dynamicRulesCachePath = java.nio.file.Path.of("/tmp/rules.json")
    builder.dynamicRulesCachePath = null
    builder.detectionPatternValidationCachePath = "/tmp/cache.json"
    builder.detectionPatternValidationCachePath = null
    builder.otelExporterEndpoint = "http://localhost:4318"
    builder.otelExporterEndpoint = null
    builder.enableRedis = false
    val config = builder.build()
    assertNull(config.customLogFile)
    assertNull(config.agentApiKey)
  }

  @Test
  fun testHookAndVerifierAppliers() {
    val config =
        SecurityConfigBuilder.fromMap(
            goodBase() +
                mapOf(
                    "on_error" to OnErrorHook { stage, exc, context -> },
                    "on_block" to BlockHook { request, payload -> null },
                    "custom_request_check" to CustomRequestCheck { null },
                    "auth_verifier" to AuthVerifier { _, _ -> null },
                    "custom_response_modifier" to CustomResponseModifier { it },
                    "cloud_ip_store" to "any-store-token",
                    "agent_strict" to true,
                ),
            warnUnknown = false,
        )
    assertTrue(config.agentStrict)
    assertTrue(config.onError is OnErrorHook)
    assertTrue(config.onBlock is BlockHook)
    assertTrue(config.customRequestCheck is CustomRequestCheck)
    assertTrue(config.authVerifier is AuthVerifier)
    assertTrue(config.customResponseModifier is CustomResponseModifier)
    assertEquals("any-store-token", config.cloudIpStore)
  }

  @Test
  fun testFromMapCoercionRejections() {
    val cases: List<Map<String, Any?>> =
        listOf(
            mapOf("rate_limit" to true),
            mapOf("rate_limit" to 1.5),
            mapOf("redis_socket_connect_timeout" to true),
            mapOf("redis_socket_connect_timeout" to "x"),
            mapOf("passive_mode" to "x"),
            mapOf("redis_prefix" to 42),
            mapOf("whitelist" to 42),
            mapOf("blocked_user_agents" to 42),
            mapOf("security_headers" to 42),
            mapOf("custom_error_responses" to 42),
            mapOf("custom_error_responses" to mapOf("k" to "v")),
            mapOf("otel_resource_attributes" to 42),
            mapOf("custom_log_file" to 42),
            mapOf("log_suspicious_level" to "BOGUS"),
            mapOf("log_suspicious_level" to 42),
            mapOf("log_format" to "bogus"),
            mapOf("log_format" to 42),
            mapOf("agent_buffer_overflow_policy" to "bogus"),
            mapOf("endpoint_rate_limits" to 42),
            mapOf("endpoint_rate_limits" to mapOf("/x" to "bad")),
            mapOf("global_behavior_rules" to listOf(42)),
            mapOf(
                "global_behavior_rules" to listOf(mapOf("rule_type" to "bogus", "threshold" to 1)),
            ),
            mapOf(
                "global_behavior_rules" to
                    listOf(mapOf("rule_type" to "usage", "threshold" to 1, "action" to "bogus")),
            ),
            mapOf("global_behavior_rules" to listOf(mapOf("rule_type" to "usage"))),
            mapOf("threat_ban_config" to 42),
            mapOf("threat_ban_config" to mapOf("sqli" to "bad")),
            mapOf("threat_ban_config" to mapOf("sqli" to mapOf("threshold" to 1))),
        )
    for (case in cases) {
      assertFailsWith<ConfigValidationError> {
        SecurityConfigBuilder.fromMap(goodBase() + case, warnUnknown = false)
      }
    }
    // valid coercions through the same helpers
    val config =
        SecurityConfigBuilder.fromMap(
            goodBase() +
                mapOf(
                    "custom_error_responses" to mapOf(404 to "not found"),
                    "otel_resource_attributes" to mapOf("k" to "v"),
                    "threat_ban_config" to
                        mapOf("sqli" to mapOf("threshold" to 3, "duration" to 60)),
                    "global_behavior_rules" to
                        listOf(
                            mapOf(
                                "rule_type" to "usage",
                                "threshold" to 2,
                                "action" to "throttle",
                                "window" to 60,
                            ),
                        ),
                    "endpoint_rate_limits" to mapOf("/x" to listOf(5, 60)),
                ),
            warnUnknown = false,
        )
    assertEquals(mapOf(404 to "not found"), config.customErrorResponses)
    assertEquals(mapOf("k" to "v"), config.otelResourceAttributes)
    assertEquals(3, config.threatBanConfig["sqli"]?.threshold)
    assertEquals(2, config.globalBehaviorRules.first().threshold)
    assertEquals(mapOf("/x" to Pair(5, 60)), config.endpointRateLimits)
  }

  @Test
  fun testValueByNameAndUnknownField() {
    val config = SecurityConfigBuilder.fromMap(goodBase(), warnUnknown = false)
    assertEquals(listOf<String>(), config.valueByName("whitelist") ?: emptyList<String>())
    config.valueByName("rate_limit")
    config.valueByName("blocked_user_agents")
    assertFailsWith<ConfigValidationError> { config.valueByName("no_such_field") }
  }

  @Test
  fun testCopyWithGlobalBehaviorRulesRevalidation() {
    val config = SecurityConfigBuilder.fromMap(goodBase(), warnUnknown = false)
    val copied =
        config.copyWith(
            mapOf(
                "global_behavior_rules" to
                    listOf(
                        mapOf(
                            "rule_type" to "return_pattern",
                            "threshold" to 3,
                            "pattern" to "status:404",
                        ),
                    ),
            ),
        )
    assertEquals(1, copied.globalBehaviorRules.size)
  }

  @Test
  fun testGeoIpHandlerRequiredWithoutTokenFactory() {
    // no token and no factory: building must name the missing geo requirement
    val err =
        assertFailsWith<ConfigValidationError> {
          SecurityConfigBuilder()
              .apply {
                enableRedis = false
                blockedCountries = setOf("GB")
              }
              .build()
        }
    assertTrue(err.message!!.contains("geo"))
  }

  @Test
  fun testRawHookSetters() {
    val builder = SecurityConfigBuilder()
    builder.enableRedis = false
    builder.onError = OnErrorHook { stage, exc, context -> }
    val config = builder.build()
    assertTrue(config.onError is OnErrorHook)
  }
}
